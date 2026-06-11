package main

import (
	"database/sql"
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
	CurrentIP  string `json:"current_ip"`
	CurrentMAC string `json:"current_mac"`
	IsBlocked  bool   `json:"is_blocked"`
	RateLimit  int    `json:"rate_limit"`
	LastSeen   int64  `json:"last_seen"`
	Online     bool   `json:"online"`
	SpeedOut   uint64 `json:"speed_out"`
}

type Config struct{ WANIF, LANIF, DBPath string }

var (
	db     *sql.DB
	config Config
	mu     sync.RWMutex
)

func main() {
	log.SetFlags(log.LstdFlags)
	config = Config{
		WANIF:  getEnv("WAN_IF", "eth0"),
		LANIF:  getEnv("LAN_IF", "br-lan"),
		DBPath: getEnv("DB_PATH", "/var/lib/devman.db"),
	}
	var err error
	db, err = sql.Open("sqlite", config.DBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	initDB()

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
			mac TEXT DEFAULT '', alias TEXT DEFAULT '',
			hostname TEXT DEFAULT '', ipv4 TEXT DEFAULT '',
			is_blocked INTEGER DEFAULT 0, rate_limit INTEGER DEFAULT 0,
			last_seen INTEGER DEFAULT 0, first_seen INTEGER DEFAULT 0,
			online INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS traffic (
			device_id INTEGER, speed_out INTEGER DEFAULT 0,
			recorded_at INTEGER
		)`,
	} {
		db.Exec(q)
	}
}

// ======== device discovery ========

func deviceWatcher(wg *sync.WaitGroup) {
	defer wg.Done()
	scanExisting()
	go leaseWatcher()
	go conntrackWatcher()
}

func scanExisting() {
	out, _ := exec.Command("conntrack", "-L").Output()
	seen := map[string]bool{}
	var ip string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "src=") {
			ip = fieldVal(line, "src=")
		}
		if strings.Contains(line, "dst=") && ip != "" {
			dst := fieldVal(line, "dst=")
			if isLAN(ip) && !isLAN(dst) && !seen[ip] {
				seen[ip] = true
				upsertDevice(ip)
			}
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
		if n == 0 {
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			break
		}
		lines := strings.Split(string(buf[:n]), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if strings.Contains(line, "src=") {
				ip = fieldVal(line, "src=")
			}
			if strings.Contains(line, "dst=") && strings.Contains(line, "bytes=") {
				dst = fieldVal(line, "dst=")
				// Process complete conntrack entry
				if ip != "" && dst != "" && isLAN(ip) && !isLAN(dst) {
					upsertDevice(ip)
				}
				ip = ""
				dst = ""
			}
		}
	}
}

func leaseWatcher() {
	for {
		time.Sleep(5 * time.Second)
		out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan 2>/dev/null | grep -v '^#'").Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && isLAN(f[0]) {
				upsertDevice(f[0])
			}
		}
	}
}

func upsertDevice(ip string) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().Unix()
	mac := getMAC(ip)
	name := getHostname(ip)

	if mac != "" {
		// Merge: update by MAC
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE mac=?", mac).Scan(&id) == nil {
			if strings.Contains(ip, ":") {
				db.Exec("UPDATE devices SET hostname=CASE WHEN hostname='' THEN ? ELSE hostname END, last_seen=?, online=1 WHERE id=?", name, now, id)
			} else {
				db.Exec("UPDATE devices SET ipv4=?, hostname=CASE WHEN hostname='' THEN ? ELSE hostname END, last_seen=?, online=1 WHERE id=?", ip, name, now, id)
			}
			return
		}
	}

	// Update by IPv4
	if !strings.Contains(ip, ":") {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE ipv4=?", ip).Scan(&id) == nil {
			db.Exec("UPDATE devices SET mac=CASE WHEN mac='' THEN ? ELSE mac END, hostname=CASE WHEN hostname='' THEN ? ELSE hostname END, last_seen=?, online=1 WHERE id=?", mac, name, now, id)
			return
		}
	}

	// Merge by hostname (for IPv6 devices with no MAC)
	if name != "" && mac == "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE hostname=? AND mac='' LIMIT 1", name).Scan(&id) == nil {
			db.Exec("UPDATE devices SET last_seen=?, online=1 WHERE id=?", now, id)
			return
		}
	}

	// New device
	db.Exec("INSERT INTO devices (mac, hostname, ipv4, first_seen, last_seen, online) VALUES (?,?,?,?,?,1)", mac, name, ipOr(ip), now, now)
}

func ipOr(ip string) string {
	if strings.Contains(ip, ":") {
		return ""
	}
	return ip
}

func getMAC(ip string) string {
	if strings.Contains(ip, ":") {
		return "" // ARP only for IPv4
	}
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
	out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan 2>/dev/null | grep '^"+ip+"[ \t]' | head -1").Output()
	f := strings.Fields(string(out))
	if len(f) >= 2 {
		return f[1]
	}
	return ""
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
		checkOffline()
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
			continue // skip first sample (delta = total)
		}
		if !ok {
			continue
		}
		delta := total - prev
		speed := uint64(float64(delta) / 3.0 * 8)
		if speed > 0 {
			// Find device by IP (IPv4) or any device with this IPv6
			if strings.Contains(ip, ":") {
				db.Exec("INSERT INTO traffic (device_id, speed_out, recorded_at) SELECT id,?,? FROM devices WHERE mac!='' AND last_seen>? ORDER BY last_seen DESC LIMIT 1", speed, now, now-120)
			} else {
				db.Exec("INSERT INTO traffic (device_id, speed_out, recorded_at) SELECT id,?,? FROM devices WHERE ipv4=?", speed, now, ip)
			}
		}
	}

	mu.Unlock()
	speedMu.Unlock()
}

func checkOffline() {
	db.Exec("UPDATE devices SET online=0 WHERE online=1 AND last_seen < ?", time.Now().Unix()-120)
}

// ======== rules ========

func ruleLoop(wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		enforce()
	}
}

func enforce() {
	rows, _ := db.Query("SELECT id, ipv4, mac, is_blocked, rate_limit FROM devices WHERE online=1 AND ipv4!=''")
	if rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var ip, mac string
		var blocked, rate int
		rows.Scan(&id, &ip, &mac, &blocked, &rate)
		if blocked == 1 && ip != "" {
			blockIP(ip)
		}
		if rate > 0 && ip != "" {
			limitIP(ip, rate)
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
	// tc class add for this IP
	cmd := fmt.Sprintf(
		"tc qdisc add dev %s root handle 1: htb 2>/dev/null; "+
			"tc class add dev %s parent 1: classid 1:%s htb rate %dkbit 2>/dev/null",
		config.WANIF, config.WANIF, major, kbps,
	)
	exec.Command("sh", "-c", cmd).Run()
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
	rows, _ := db.Query("SELECT id, alias, hostname, ipv4, mac, is_blocked, rate_limit, last_seen, online FROM devices ORDER BY last_seen DESC")
	w.Header().Set("Content-Type", "application/json")
	if rows == nil {
		w.Write([]byte("[]"))
		return
	}
	defer rows.Close()
	var devs []DeviceProfile
	for rows.Next() {
		var d DeviceProfile
		var b, on int
		rows.Scan(&d.ID, &d.Alias, &d.Hostname, &d.CurrentIP, &d.CurrentMAC, &b, &d.RateLimit, &d.LastSeen, &on)
		d.IsBlocked = b == 1
		d.Online = on == 1
		db.QueryRow("SELECT COALESCE(speed_out,0) FROM traffic WHERE device_id=? ORDER BY recorded_at DESC LIMIT 1", d.ID).Scan(&d.SpeedOut)
		devs = append(devs, d)
	}
	json.NewEncoder(w).Encode(devs)
}

func apiBlock(w http.ResponseWriter, r *http.Request) {
	var req struct{ DeviceID int64 `json:"device_id"`; Block bool `json:"block"` }
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
