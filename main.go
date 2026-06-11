package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

type DeviceProfile struct {
	ID         int64  `json:"id"`
	Alias      string `json:"alias"`
	Hostname   string `json:"hostname"`
	DeviceType string `json:"device_type"`
	CurrentIP  string `json:"current_ip"`
	CurrentMAC string `json:"current_mac"`
	IsBlocked  bool   `json:"is_blocked"`
	RateLimit  int    `json:"rate_limit"`
	LastSeen   int64  `json:"last_seen"`
	Online     string `json:"online"` // green/yellow/gray
	SpeedOut   uint64 `json:"speed_out"`
	NumMACs    int    `json:"num_macs"` // historical MAC count
}

type Config struct{ WANIF, LANIF, DBPath, DHCPHookPath string }

var (
	db     *sql.DB
	config Config
	mu     sync.RWMutex
)

func main() {
	log.SetFlags(log.LstdFlags)
	config = Config{
		WANIF:        getEnv("WAN_IF", "eth0"),
		LANIF:        getEnv("LAN_IF", "br-lan"),
		DBPath:       getEnv("DB_PATH", "/etc/devman/devman.db"),
		DHCPHookPath: getEnv("DHCP_HOOK", "/usr/lib/devman/dhcp-hook.sh"),
	}
	os.MkdirAll("/etc/devman", 0755)
	fmt.Println("devman v2 starting...")

	var err error
	db, err = sql.Open("sqlite", config.DBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	initDB()
	// installDHCPHook() // skip for now, test router doesn't have dnsmasq.conf writable

	// Startup: broadcast ping to fill ARP table
	broadcastPing()

	// Recover rules
	recoverRules()

	var wg sync.WaitGroup
	wg.Add(1)
	go deviceWatcher(&wg)
	wg.Add(1)
	go speedCollector(&wg)
	wg.Add(1)
	go ruleLoop(&wg)

	http.HandleFunc("/api/devices", apiDevices)
	http.HandleFunc("/api/block", apiBlock)
	http.HandleFunc("/api/limit", apiLimit)
	http.HandleFunc("/api/dhcp-event", apiDHCPEvent)
	http.HandleFunc("/api/merge", apiMerge)
	http.HandleFunc("/api/device/", apiDelete)
	go http.ListenAndServe(":9999", nil)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func initDB() {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mac TEXT DEFAULT '', hostname TEXT DEFAULT '',
			vendor_class TEXT DEFAULT '', opt55_hash TEXT DEFAULT '',
			device_type TEXT DEFAULT 'Unknown',
			alias TEXT DEFAULT '', ipv4 TEXT DEFAULT '',
			is_blocked INTEGER DEFAULT 0, rate_limit INTEGER DEFAULT 0,
			first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0,
			online_status TEXT DEFAULT 'gray'
		)`,
		`ALTER TABLE devices ADD COLUMN online_status TEXT DEFAULT 'gray'`,

		`CREATE TABLE IF NOT EXISTS device_macs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL, mac TEXT NOT NULL,
			first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS traffic (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL, speed_out INTEGER DEFAULT 0,
			recorded_at INTEGER DEFAULT 0
		)`,
	} {
		db.Exec(q)
	}
}

func broadcastPing() {
	// Get LAN subnet from interface
	out, _ := exec.Command("sh", "-c", fmt.Sprintf("ip -4 addr show %s | grep 'inet ' | awk '{print $2}'", config.LANIF)).Output()
	cidr := strings.TrimSpace(string(out))
	if cidr == "" {
		return
	}
	// ping broadcast address
	bcast := cidrToBroadcast(cidr)
	if bcast != "" {
		exec.Command("ping", "-b", "-c", "1", "-W", "1", bcast).Run()
	}
}

func cidrToBroadcast(cidr string) string {
	var ip [4]int
	var mask int
	fmt.Sscanf(cidr, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &mask)
	if mask == 0 {
		return ""
	}
	for i := mask; i < 32; i++ {
		ip[i/8] |= 1 << (7 - uint(i%8))
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func installDHCPHook() {
	hookDir := "/usr/lib/devman"
	os.MkdirAll(hookDir, 0755)
	script := `#!/bin/sh
# dnsmasq dhcp-script hook for devman
[ "$1" = "add" ] || [ "$1" = "old" ] || exit 0
MAC=$2 IP=$3
curl -s -X POST http://127.0.0.1:9999/api/dhcp-event -H "Content-Type: application/json" \
  -d "{\"mac\":\"$MAC\",\"ip\":\"$IP\",\"hostname\":\"${DNSMASQ_SUPPLIED_HOSTNAME:-}\",\"vendor_class\":\"${DNSMASQ_VENDOR_CLASS:-}\",\"opt55\":\"${DNSMASQ_REQUESTED_OPTIONS:-}\"}" &
`
	os.WriteFile(config.DHCPHookPath, []byte(script), 0755)

	// Add to dnsmasq config if not present
	data, _ := os.ReadFile("/etc/dnsmasq.conf")
	if !strings.Contains(string(data), "dhcp-script="+config.DHCPHookPath) {
		f, _ := os.OpenFile("/etc/dnsmasq.conf", os.O_APPEND|os.O_WRONLY, 0644)
		if f != nil {
			f.WriteString("\ndhcp-script=" + config.DHCPHookPath + "\ndhcp-authoritative\n")
			f.Close()
			exec.Command("/etc/init.d/dnsmasq", "restart").Run()
		}
	}
}

// ======== device discovery ========

func deviceWatcher(wg *sync.WaitGroup) {
	defer wg.Done()
	scanARP()
	go conntrackWatcher()
	go leaseWatcher()
}

func scanARP() {
	// ip neigh show (format: IP dev IF lladdr MAC STATE)
	out, _ := exec.Command("sh", "-c", "ip neigh show | grep REACHABLE").Output()
	fmt.Println("ARP scan: found", len(strings.Split(string(out), "\n"))-1, "REACHABLE entries")
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 {
			upsertDevice(f[0], f[4], "", "", "", "")
			fmt.Println("ARP added:", f[0], f[4])
		}
	}
	// /proc/net/arp
	out2, _ := exec.Command("cat", "/proc/net/arp").Output()
	for _, line := range strings.Split(string(out2), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && isLAN(f[0]) && f[0] != "127.0.0.1" && f[2] == "0x2" {
			upsertDevice(f[0], f[3], "", "", "", "")
		}
	}
}

func conntrackWatcher() {
	cmd := exec.Command("conntrack", "-E")
	stdout, _ := cmd.StdoutPipe()
	cmd.Start()
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	var ip, dst string
	buf := make([]byte, 8192)
	for {
		n, err := stdout.Read(buf)
		if n == 0 && err != nil {
			time.Sleep(time.Second)
			continue
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if strings.Contains(line, "src=") {
				ip = fieldVal(line, "src=")
			}
			if strings.Contains(line, "dst=") && strings.Contains(line, "bytes=") {
				dst = fieldVal(line, "dst=")
				if ip != "" && dst != "" && isLAN(ip) && !isLAN(dst) {
					upsertDevice(ip, "", "", "", "", "")
				}
				ip = ""
				dst = ""
			}
		}
	}
}

func leaseWatcher() {
	for {
		time.Sleep(10 * time.Second)
		mu.Lock()
		out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan 2>/dev/null | grep -v '^#'").Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && isLAN(f[0]) && f[1] != "" {
				db.Exec("UPDATE devices SET hostname=CASE WHEN hostname='' THEN ? ELSE hostname END WHERE ipv4=? OR mac IN (SELECT mac FROM device_macs)", f[1], f[0])
			}
		}
		mu.Unlock()
	}
}

// ======== 3-tier matching ========

func upsertDevice(ip, mac, hostname, vendorClass, opt55, devType string) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().Unix()

	// Get MAC from ARP if not provided (works for IPv4 and IPv6 via ip neigh)
	if mac == "" {
		mac = getMACviaIPNeigh(ip)
	}
	// Get hostname from DHCP if not provided
	if hostname == "" {
		hostname = getHostname(ip)
	}

	// Tier 1: MAC match
	if mac != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE mac=?", mac).Scan(&id) == nil {
			updateDevice(id, ip, mac, hostname, now)
			db.Exec("INSERT OR IGNORE INTO device_macs (device_id, mac, first_seen, last_seen) VALUES (?,?,?,?)", id, mac, now, now)
			return
		}
		// Check device_macs for historical MAC
		if db.QueryRow("SELECT device_id FROM device_macs WHERE mac=? LIMIT 1", mac).Scan(&id) == nil {
			updateDevice(id, ip, mac, hostname, now)
			db.Exec("UPDATE device_macs SET last_seen=? WHERE mac=?", now, mac)
			return
		}
	}

	// Tier 2: Hostname match
	if hostname != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE hostname=? LIMIT 1", hostname).Scan(&id) == nil {
			updateDevice(id, ip, mac, hostname, now)
			if mac != "" {
				db.Exec("INSERT OR IGNORE INTO device_macs (device_id, mac, first_seen, last_seen) VALUES (?,?,?,?)", id, mac, now, now)
			}
			return
		}
	}

	// Tier 3: DHCP fingerprint match
	if vendorClass != "" && opt55 != "" {
		fpHash := hashOpt55(opt55)
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE vendor_class=? AND opt55_hash=?", vendorClass, fpHash).Scan(&id) == nil {
			updateDevice(id, ip, mac, hostname, now)
			if mac != "" {
				db.Exec("INSERT OR IGNORE INTO device_macs (device_id, mac, first_seen, last_seen) VALUES (?,?,?,?)", id, mac, now, now)
			}
			return
		}
	}

	// Update by IPv4
	if !strings.Contains(ip, ":") && ip != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE ipv4=?", ip).Scan(&id) == nil {
			updateDevice(id, ip, mac, hostname, now)
			return
		}
	}

	// New device
	if devType == "" {
		devType = detectDeviceType(hostname, vendorClass)
	}
	fpHash := hashOpt55(opt55)
	db.Exec("INSERT INTO devices (mac, hostname, vendor_class, opt55_hash, device_type, ipv4, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)",
		mac, hostname, vendorClass, fpHash, devType, ipOr(ip), now, now)
	if mac != "" {
		result, _ := db.Exec("INSERT OR IGNORE INTO device_macs (device_id, mac, first_seen, last_seen) VALUES ((SELECT id FROM devices WHERE mac=? LIMIT 1),?,?,?)", mac, mac, now, now)
		_ = result
	}
}

func updateDevice(id int64, ip, mac, hostname string, now int64) {
	q := "UPDATE devices SET last_seen=?, online_status='green'"
	args := []interface{}{now}
	if mac != "" {
		q += ", mac=?"
		args = append(args, mac)
	}
	if hostname != "" {
		q += ", hostname=CASE WHEN hostname='' THEN ? ELSE hostname END"
		args = append(args, hostname)
	}
	if ip != "" && !strings.Contains(ip, ":") {
		q += ", ipv4=CASE WHEN ipv4='' THEN ? ELSE ipv4 END"
		args = append(args, ip)
	}
	q += " WHERE id=?"
	args = append(args, id)
	db.Exec(q, args...)
}

func ipOr(ip string) string {
	if strings.Contains(ip, ":") {
		return ""
	}
	return ip
}

func getMACviaIPNeigh(ip string) string {
	// Try /proc/net/arp first (IPv4)
	if !strings.Contains(ip, ":") {
		out, _ := exec.Command("cat", "/proc/net/arp").Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[0] == ip {
				return f[3]
			}
		}
	}
	// Try ip neigh (grep full table)
	out, _ := exec.Command("sh", "-c", "ip neigh show | grep '"+ip+"' 2>/dev/null").Output()
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, "lladdr ")
		if idx > 0 {
			return strings.SplitN(line[idx+7:], " ", 2)[0]
		}
	}
	return ""
}

func getMAC(ip string) string {
	out, _ := exec.Command("cat", "/proc/net/arp").Output()
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == ip {
			return f[3]
		}
	}
	return ""
}

func getHostname(ip string) string {
	out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan 2>/dev/null | grep '^"+ip+"[\t ]' | head -1").Output()
	f := strings.Fields(string(out))
	if len(f) >= 2 {
		return f[1]
	}
	return ""
}

func hashOpt55(opt55 string) string {
	if opt55 == "" {
		return ""
	}
	h := sha256.Sum256([]byte(opt55))
	return hex.EncodeToString(h[:])[:8]
}

func detectDeviceType(hostname, vendorClass string) string {
	h := strings.ToLower(hostname)
	v := strings.ToLower(vendorClass)

	for _, kw := range []string{"iphone", "ipad", "apple", "macbook", "macmini"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "Apple"
		}
	}
	for _, kw := range []string{"android", "pixel", "samsung", "oneplus", "xiaomi"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "Android"
		}
	}
	for _, kw := range []string{"desktop-", "pc-", "windows", "win10", "win11"} {
		if strings.Contains(h, kw) {
			return "Windows"
		}
	}
	for _, kw := range []string{"ubuntu", "raspberry", "debian", "centos", "openwrt"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "Linux"
		}
	}
	for _, kw := range []string{"mi", "lumi", "esp", "sonoff", "tasmota", "esphome", "xiaomi"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "IoT"
		}
	}
	return "Unknown"
}

// ======== speed ========

var prevBytes = map[string]uint64{}
var firstSample = map[string]bool{}
var speedMu sync.Mutex

func speedCollector(wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for range t.C {
		updateSpeed()
		updateOnlineStatus()
	}
}

func updateSpeed() {
	now := time.Now().Unix()
	out, _ := exec.Command("conntrack", "-L").Output()
	cur := map[string]uint64{}
	var ip string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "src=") {
			ip = fieldVal(line, "src=")
		}
		if ip != "" && strings.Contains(line, "bytes=") {
			bs := fieldVal(line, "bytes=")
			n, _ := atoui(bs)
			if isLAN(ip) && ip != "127.0.0.1" {
				cur[ip] += n
			}
		}
	}

	speedMu.Lock()
	mu.Lock()
	for ip, total := range cur {
		prev, ok := prevBytes[ip]
		prevBytes[ip] = total
		if !firstSample[ip] {
			firstSample[ip] = true
			continue
		}
		if !ok {
			continue
		}
		delta := total - prev
		speed := uint64(float64(delta) / 3.0 * 8)
		if speed > 0 {
			db.Exec("INSERT INTO traffic (device_id, speed_out, recorded_at) SELECT id,?,? FROM devices WHERE ipv4=?", speed, now, ip)
		}
	}
	mu.Unlock()
	speedMu.Unlock()
}

func updateOnlineStatus() {
	now := time.Now().Unix()
	mu.Lock()
	defer mu.Unlock()

	// Update online status
	db.Exec(`UPDATE devices SET online_status=CASE 
		WHEN last_seen > ? THEN 'green' 
		WHEN last_seen > ? THEN 'yellow' 
		ELSE 'gray' END`, now-120, now-1800)

	// Merge devices with same hostname
	rows, _ := db.Query(`SELECT id, hostname, mac, ipv4, last_seen FROM devices WHERE hostname!='' ORDER BY hostname, last_seen DESC`)
	if rows == nil {
		return
	}
	defer rows.Close()

	type dev struct {
		id       int64
		hostname string
		mac      string
		ipv4     string
		lastSeen int64
	}
	seen := map[string]*dev{}
	for rows.Next() {
		var d dev
		rows.Scan(&d.id, &d.hostname, &d.mac, &d.ipv4)
		if keep, ok := seen[d.hostname]; ok {
			// Merge this device into the keep device
			if d.mac != "" && keep.mac == "" {
				db.Exec("UPDATE devices SET mac=? WHERE id=?", d.mac, keep.id)
			}
			if d.ipv4 != "" && keep.ipv4 == "" {
				db.Exec("UPDATE devices SET ipv4=? WHERE id=?", d.ipv4, keep.id)
			}
			db.Exec("UPDATE devices SET last_seen=MAX(last_seen,?) WHERE id=?", d.lastSeen, keep.id)
			db.Exec("DELETE FROM devices WHERE id=?", d.id)
		} else {
			seen[d.hostname] = &d
		}
	}
}

// ======== rules ========

func recoverRules() {
	rows, _ := db.Query("SELECT id, ipv4, is_blocked, rate_limit FROM devices WHERE is_blocked=1 OR rate_limit>0")
	if rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var ip string
		var b, r int
		rows.Scan(&id, &ip, &b, &r)
		if b == 1 && ip != "" {
			blockIP(ip)
		}
		if r > 0 && ip != "" {
			limitIP(ip, r)
		}
	}
}

func ruleLoop(wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		enforce()
	}
}

func enforce() {
	rows, _ := db.Query("SELECT id, ipv4, is_blocked, rate_limit FROM devices WHERE online_status='green' AND ipv4!=''")
	if rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var ip string
		var b, r int
		rows.Scan(&id, &ip, &b, &r)
		if b == 1 && ip != "" {
			blockIP(ip)
		}
		if r > 0 && ip != "" {
			limitIP(ip, r)
		}
	}
}

func blockIP(ip string) {
	exec.Command("sh", "-c",
		"nft add table ip devman 2>/dev/null; "+
			"nft add chain ip devman forward '{ type filter hook forward priority filter - 1; }' 2>/dev/null; "+
			"nft add rule ip devman forward ip saddr "+ip+" drop 2>/dev/null").Run()
}

func limitIP(ip string, kbps int) {
	major := fmtIPtoHex(ip)
	exec.Command("sh", "-c", fmt.Sprintf(
		"tc qdisc add dev %s root handle 1: htb 2>/dev/null; tc class add dev %s parent 1: classid 1:%s htb rate %dkbit 2>/dev/null",
		config.WANIF, config.WANIF, major, kbps,
	)).Run()
}

func fmtIPtoHex(ip string) string {
	var a, b, c, d int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	return fmt.Sprintf("%x%02x%02x%02x", a, b, c, d)[:6]
}

// ======== API ========

func apiDevices(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	rows, _ := db.Query(`SELECT d.id, d.alias, d.hostname, d.device_type, d.ipv4, d.mac, d.is_blocked, d.rate_limit, d.last_seen, d.online_status,
		(SELECT COUNT(*) FROM device_macs WHERE device_id=d.id)
		FROM devices d ORDER BY d.last_seen DESC`)
	w.Header().Set("Content-Type", "application/json")
	if rows == nil {
		w.Write([]byte("[]"))
		return
	}
	defer rows.Close()
	var devs []DeviceProfile
	for rows.Next() {
		var d DeviceProfile
		var b int
		rows.Scan(&d.ID, &d.Alias, &d.Hostname, &d.DeviceType, &d.CurrentIP, &d.CurrentMAC, &b, &d.RateLimit, &d.LastSeen, &d.Online, &d.NumMACs)
		d.IsBlocked = b == 1
		db.QueryRow("SELECT COALESCE(speed_out,0) FROM traffic WHERE device_id=? ORDER BY recorded_at DESC LIMIT 1", d.ID).Scan(&d.SpeedOut)
		devs = append(devs, d)
	}
	json.NewEncoder(w).Encode(devs)
}

func apiDHCPEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC         string `json:"mac"`
		IP          string `json:"ip"`
		Hostname    string `json:"hostname"`
		VendorClass string `json:"vendor_class"`
		Opt55       string `json:"opt55"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	upsertDevice(req.IP, req.MAC, req.Hostname, req.VendorClass, req.Opt55, "")
	w.Write([]byte(`{"ok":true}`))
}

func apiBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID int64 `json:"device_id"`
		Block    bool  `json:"block"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	v := 0
	if req.Block {
		v = 1
	}
	db.Exec("UPDATE devices SET is_blocked=? WHERE id=?", v, req.DeviceID)
	w.Write([]byte(`{"ok":true}`))
}

func apiLimit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID  int64  `json:"device_id"`
		RateLimit int    `json:"rate_limit"`
		Alias     string `json:"alias"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Alias != "" {
		db.Exec("UPDATE devices SET alias=? WHERE id=?", req.Alias, req.DeviceID)
	}
	if req.RateLimit >= 0 {
		db.Exec("UPDATE devices SET rate_limit=? WHERE id=?", req.RateLimit, req.DeviceID)
	}
	w.Write([]byte(`{"ok":true}`))
}

func apiMerge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeepID  int64 `json:"keep_id"`
		MergeID int64 `json:"merge_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	// Move MACs from merge to keep
	db.Exec("UPDATE device_macs SET device_id=? WHERE device_id=?", req.KeepID, req.MergeID)
	// Update keep with merge's best data
	db.Exec(`UPDATE devices SET 
		hostname=CASE WHEN (SELECT hostname FROM devices WHERE id=?)!='' THEN (SELECT hostname FROM devices WHERE id=?) ELSE hostname END,
		alias=CASE WHEN (SELECT alias FROM devices WHERE id=?)!='' THEN (SELECT alias FROM devices WHERE id=?) ELSE alias END,
		last_seen=MAX(last_seen, (SELECT last_seen FROM devices WHERE id=?))
		WHERE id=?`, req.MergeID, req.MergeID, req.MergeID, req.MergeID, req.MergeID, req.KeepID)
	// Delete merge device
	db.Exec("DELETE FROM devices WHERE id=?", req.MergeID)
	w.Write([]byte(`{"ok":true}`))
}

func apiDelete(w http.ResponseWriter, r *http.Request) {
	// Parse /api/device/123
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/device/"), "/")
	if len(parts) > 0 {
		db.Exec("DELETE FROM devices WHERE id=?", parts[0])
	}
	w.Write([]byte(`{"ok":true}`))
}

// ======== helpers ========

func fieldVal(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	return strings.SplitN(line[idx+len(key):], " ", 2)[0]
}

func isLAN(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "fd") ||
		strings.HasPrefix(ip, "fe80:") || strings.HasPrefix(ip, "2408:") ||
		strings.HasPrefix(ip, "240e:")
}

func atoui(s string) (uint64, error) {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}
