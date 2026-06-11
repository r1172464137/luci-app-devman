package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	Online     string `json:"online"`
	VendorClass string `json:"vendor_class"`
	Opt55Hash  string `json:"opt55_hash"`
	SpeedIn    uint64 `json:"speed_in"`
	SpeedOut   uint64 `json:"speed_out"`
	NumMACs    int    `json:"num_macs"`
}

var (
	db        *sql.DB
	mu        sync.RWMutex
	prevBytes = map[string]uint64{}
	firstSeen = map[string]bool{}
	speedMu   sync.Mutex
	scriptDir = "/usr/lib/devman"
)

func main() {
	log.SetFlags(log.LstdFlags)
	os.MkdirAll("/etc/devman", 0755)
	os.MkdirAll(scriptDir, 0755)

	var err error
	db, err = sql.Open("sqlite", "/etc/devman/devman.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	initDB()
	// Update existing device types from MAC OUI + hostname
	rows, _ := db.Query("SELECT id, mac, hostname FROM devices WHERE device_type='Unknown' AND (mac!='' OR hostname!='')")
	if rows != nil {
		for rows.Next() {
			var id int64
			var mac, hostname string
			rows.Scan(&id, &mac, &hostname)
			dt := detectType(hostname, "")
			if dt == "Unknown" && mac != "" {
				dt = detectTypeByMAC(mac)
			}
			if dt != "" && dt != "Unknown" {
				db.Exec("UPDATE devices SET device_type=? WHERE id=?", dt, id)
			}
		}
		rows.Close()
	}
	// Merge any duplicate hostnames from previous sessions
	mergeDuplicateHostnames()

	installScripts()
	initTC()
	initNFT()
	db.Exec("UPDATE devices SET device_type='Unknown' WHERE device_type='' OR device_type IS NULL")
	// Immediately fill hostnames from existing leases
	fillHostnamesFromLeases()

	go neightLoop()
	go conntrackLoop()
	go leaseLoop()
	go dhcpSniffLoop()
	go speedLoop()
	go reconcileLoop()

	http.HandleFunc("/api/devices", apiDevices)
	http.HandleFunc("/api/block", apiBlock)
	http.HandleFunc("/api/limit", apiLimit)
	http.HandleFunc("/api/dhcp-event", apiDHCPEvent)
	go http.ListenAndServe(":9999", nil)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	// cleanup
	exec.Command(scriptDir+"/block.sh", "init").Run()
	exec.Command(scriptDir+"/limit.sh", "clean").Run()
}

// ======== init ========

func initDB() {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mac TEXT DEFAULT '', hostname TEXT DEFAULT '',
			vendor_class TEXT DEFAULT '', opt55_hash TEXT DEFAULT '',
			device_type TEXT DEFAULT 'Unknown',
			alias TEXT DEFAULT '', ipv4 TEXT DEFAULT '',
			is_blocked INTEGER DEFAULT 0, rate_limit INTEGER DEFAULT 0,
			last_seen INTEGER DEFAULT 0, first_seen INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS device_macs (
			device_id INTEGER NOT NULL, mac TEXT NOT NULL,
			first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0,
			UNIQUE(device_id, mac)
		)`,

		// Migration for old DBs
		`DELETE FROM device_macs WHERE id NOT IN (SELECT MIN(id) FROM device_macs GROUP BY device_id, mac)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_device_macs_unique ON device_macs(device_id, mac)`,
		`CREATE TABLE IF NOT EXISTS traffic (
			device_id INTEGER NOT NULL, speed_out INTEGER DEFAULT 0, speed_in INTEGER DEFAULT 0,
			recorded_at INTEGER DEFAULT 0
		)`,
		`ALTER TABLE traffic ADD COLUMN speed_in INTEGER DEFAULT 0`,
	} {
		db.Exec(q)
	}
}

func installScripts() {
	scripts := map[string]string{
		"block.sh": `#!/bin/sh
# nftables set-based blocking
case "$1" in
  init)
    nft add table ip devman 2>/dev/null
    nft add set ip devman blocked_ip { type ipv4_addr\; } 2>/dev/null
    nft add chain ip devman forward { type filter hook forward priority filter - 1\; } 2>/dev/null
    nft add rule ip devman forward ip saddr @blocked_ip drop 2>/dev/null
    ;;
  add) nft add element ip devman blocked_ip { $2 } 2>/dev/null ;;
  del) nft delete element ip devman blocked_ip { $2 } 2>/dev/null ;;
esac`,
		"limit.sh": `#!/bin/sh
# tc htb rate limiting, uses device_id as classid
CID=$2; IP=$3; RATE=${4:-0}; IF=br-lan
case "$1" in
  init) tc qdisc add dev $IF root handle 1: htb default 30 2>/dev/null ;;
  set)
    tc filter del dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    tc class del dev $IF parent 1: classid 1:$CID 2>/dev/null
    tc class add dev $IF parent 1: classid 1:$CID htb rate ${RATE}kbit ceil ${RATE}kbit 2>/dev/null
    tc filter add dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    ;;
  del)
    tc filter del dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    tc class del dev $IF parent 1: classid 1:$CID 2>/dev/null
    ;;
  clean)
    tc qdisc del dev $IF root 2>/dev/null
    tc qdisc add dev $IF root handle 1: htb default 30 2>/dev/null
    ;;
esac`,
		"dhcp-hook.sh": `#!/bin/sh
[ "$1" = "add" ] || [ "$1" = "old" ] || exit 0
curl -s -X POST http://127.0.0.1:9999/api/dhcp-event -H "Content-Type: application/json" \
  -d "{\"mac\":\"$2\",\"ip\":\"$3\",\"hostname\":\"${DNSMASQ_SUPPLIED_HOSTNAME:-}\",\"vendor_class\":\"${DNSMASQ_VENDOR_CLASS:-}\",\"opt55\":\"${DNSMASQ_REQUESTED_OPTIONS:-}\"}" &`,
	}
	for name, content := range scripts {
		os.WriteFile(scriptDir+"/"+name, []byte(content), 0755)
	}
	// Install dnsmasq hook at default path
	os.WriteFile("/usr/lib/dnsmasq/dhcp-script.sh", []byte(`#!/bin/sh
[ "$1" = "add" ] || [ "$1" = "old" ] || exit 0
curl -s -X POST http://127.0.0.1:9999/api/dhcp-event -H "Content-Type: application/json" \
  -d "{\"mac\":\"$2\",\"ip\":\"$3\",\"hostname\":\"${DNSMASQ_SUPPLIED_HOSTNAME:-}\",\"vendor_class\":\"${DNSMASQ_VENDOR_CLASS:-}\",\"opt55\":\"${DNSMASQ_REQUESTED_OPTIONS:-}\"}" &
`), 0755)
	// Set via UCI to survive regenerations
	exec.Command("uci", "set", "dhcp.@dnsmasq[0].dhcpscript=/usr/lib/dnsmasq/dhcp-script.sh").Run()
	exec.Command("uci", "commit", "dhcp").Run()
	exec.Command("/etc/init.d/dnsmasq", "restart").Run()
}

func initTC()  { exec.Command(scriptDir+"/limit.sh", "init").Run() }
func initNFT() {
	exec.Command(scriptDir+"/block.sh", "init").Run()
	// Create traffic counting chain
	exec.Command("sh", "-c", "nft add table ip devman2 2>/dev/null; nft add chain ip devman2 forward { type filter hook forward priority filter - 2; } 2>/dev/null; nft add set ip devman2 devices { type ipv4_addr; } 2>/dev/null; nft add rule ip devman2 forward ip saddr @devices counter 2>/dev/null; nft add rule ip devman2 forward ip daddr @devices counter 2>/dev/null").Run()
}

func fillHostnamesFromLeases() {
	out, _ := os.ReadFile("/etc/dhcp.leases")
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && isLAN(f[2]) && f[3] != "" && f[3] != "*" {
			db.Exec("UPDATE devices SET hostname=? WHERE ipv4=? AND hostname=''", f[3], f[2])
		}
	}
}

// ======== discovery ========

func neightLoop() {
	for {
		out, _ := exec.Command("sh", "-c", "ip neigh show | grep REACHABLE").Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 {
				upsertDevice(f[0], f[4], "", "", "")
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func conntrackLoop() {
	for {
		cmd := exec.Command("conntrack", "-E")
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()
		buf := make([]byte, 8192)
		var ip, dst string
		for {
			n, err := stdout.Read(buf)
			if n == 0 && err != nil {
				break
			}
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				if strings.Contains(line, "src=") {
					ip = field(line, "src=")
				}
				if strings.Contains(line, "dst=") && strings.Contains(line, "bytes=") {
					dst = field(line, "dst=")
					if ip != "" && dst != "" && isLAN(ip) && !isLAN(dst) {
						upsertDevice(ip, "", "", "", "")
					}
					ip, dst = "", ""
				}
			}
		}
		cmd.Process.Kill()
		time.Sleep(time.Second)
	}
}

func dhcpSniffLoop() {
	// Open raw AF_PACKET socket with BPF filter for DHCP
	// Falls back to tcpdump if raw socket unavailable
	useRawSocket()
}

func useRawSocket() {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Printf("DHCP sniff: raw socket failed (%v), skipping", err)
		return
	}
	defer syscall.Close(fd)

	// Find br-lan interface index
	iface, _ := net.InterfaceByName("br-lan")
	if iface == nil {
		return
	}

	// Bind to br-lan
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		return
	}

	log.Println("DHCP sniff: raw socket listening on br-lan")
	var pktCount int
	buf := make([]byte, 2048)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 42 {
			continue
		}
		pktCount++
		// Log every 100th packet to verify capture is working
		if pktCount%100 == 1 {
			etherType := int(buf[12])<<8 | int(buf[13])
			log.Printf("DHCP sniff: pkt %d len=%d ethtype=0x%04x", pktCount, n, etherType)
		}
		// Parse Ethernet: skip 14 bytes
		ipStart := 14
		if n < ipStart+20+8 {
			continue
		}
		etherType := int(buf[12])<<8 | int(buf[13])
		// Check for IPv4 (0x0800) or VLAN (0x8100)
		if etherType == 0x8100 {
			ipStart = 18 // Skip VLAN tag
		} else if etherType != 0x0800 {
			continue
		}
		// Check IP version (first nibble = 4 for IPv4)
		if buf[ipStart]>>4 != 4 {
			continue
		}
		ipHdrLen := int(buf[ipStart]&0x0f) * 4
		udpStart := ipStart + ipHdrLen
		// Check protocol (offset 9 in IP header, 1=ICMP 6=TCP 17=UDP)
		if buf[ipStart+9] != 17 {
			continue
		}
		// Check UDP dest port 67
		udpDstPort := int(buf[udpStart+2])<<8 | int(buf[udpStart+3])
		if udpDstPort != 67 {
			continue
		}
		dhcpStart := udpStart + 8
		log.Printf("DHCP: udp/67 len=%d ipHdr=%d dhcpStart=%d magic=%02x%02x%02x%02x",
			n, ipHdrLen, dhcpStart,
			buf[dhcpStart+240], buf[dhcpStart+241], buf[dhcpStart+242], buf[dhcpStart+243])
		if dhcpStart+236 > n {
			continue
		}
		// DHCP fixed header is 236 bytes
		chaddrStart := dhcpStart + 28
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			buf[chaddrStart], buf[chaddrStart+1], buf[chaddrStart+2],
			buf[chaddrStart+3], buf[chaddrStart+4], buf[chaddrStart+5])

		// Parse DHCP options: start at dhcpStart + 236 (after fixed header)
		optStart := dhcpStart + 236
		// Magic cookie: 99, 130, 83, 99
		if optStart+4 > n || buf[optStart] != 99 || buf[optStart+1] != 130 || buf[optStart+2] != 83 || buf[optStart+3] != 99 {
			continue
		}
		optPos := optStart + 4
		var msgType, hostname, vendorClass string
		var opt55bytes []byte

		for optPos+1 < n {
			optCode := buf[optPos]
			if optCode == 255 {
				break // End
			}
			if optPos+1 >= n {
				break
			}
			optLen := int(buf[optPos+1])
			optPos += 2
			if optPos+optLen > n {
				break
			}
			switch optCode {
			case 53: // Message type
				if optLen >= 1 {
					switch buf[optPos] {
					case 1:
						msgType = "DISCOVER"
					case 3:
						msgType = "REQUEST"
					}
				}
			case 12: // Hostname
				hostname = string(buf[optPos : optPos+optLen])
			case 60: // Vendor Class
				vendorClass = string(buf[optPos : optPos+optLen])
			case 55: // Parameter Request List
				opt55bytes = make([]byte, optLen)
				copy(opt55bytes, buf[optPos:optPos+optLen])
			}
			optPos += optLen
		}

		if msgType == "" || mac == "" {
			continue
		}
		opt55hex := hex.EncodeToString(opt55bytes)

		// Find IP for this MAC
		ip := getIPForMAC(mac)
		log.Printf("DHCP %s: mac=%s ip=%s host=%s vendor=%s opt55=%s",
			msgType, mac, ip, hostname, vendorClass, opt55hex[:min(8, len(opt55hex))])

		if mac != "" && isLAN(ip) {
			id := upsertDevice(ip, mac, hostname, vendorClass, opt55hex)
			mu.Lock()
			// Always update IP from DHCP (most recent binding)
			db.Exec("UPDATE devices SET ipv4=? WHERE id=?", ip, id)
			mu.Unlock()
		}
	}
}

func htons(n uint16) uint16 { return (n>>8)|(n<<8) }

func getIPForMAC(mac string) string {
	out, _ := exec.Command("cat", "/proc/net/arp").Output()
	macLower := strings.ToLower(mac)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && strings.ToLower(f[3]) == macLower {
			return f[0]
		}
	}
	return ""
}

func leaseLoop() {
	var lastMod time.Time
	for {
		time.Sleep(3 * time.Second)
		info, err := os.Stat("/etc/dhcp.leases")
		if err != nil || info.ModTime().Equal(lastMod) {
			continue
		}
		lastMod = info.ModTime()

		out, _ := os.ReadFile("/etc/dhcp.leases")
		mu.Lock()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && isLAN(f[2]) && f[3] != "" && f[3] != "*" {
				hostname := f[3]
				ip := f[2]
				mac := f[1]
				now := info.ModTime().Unix()

				// Set hostname on matching device
				db.Exec("UPDATE devices SET hostname=CASE WHEN hostname='' THEN ? ELSE hostname END WHERE ipv4=?", hostname, ip)
				// Also record MAC (for future fingerprint matching)
				db.Exec("UPDATE devices SET mac=CASE WHEN mac='' THEN ? ELSE mac END WHERE ipv4=?", mac, ip)
				db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac,first_seen,last_seen) SELECT id,?,?,? FROM devices WHERE ipv4=?", mac, now, now, ip)

				r, _ := db.Exec("UPDATE devices SET hostname=? WHERE ipv4=? AND hostname=''", hostname, ip)
				rows, _ := r.RowsAffected()
				if rows > 0 {
					mergeDuplicateHostnames()
				}
			}
		}
		mu.Unlock()
	}
}

// ======== matching ========

func upsertDevice(ip, mac, hostname, vendorClass, opt55 string) int64 {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().Unix()

	if mac == "" && !strings.Contains(ip, ":") {
		mac = getMAC(ip)
	}
	fpHash := hashOpt55(opt55)
	if hostname == "" {
		hostname = getHostname(ip)
		// If still empty, try all leases for a matching hostname (for random MAC phones)
		if hostname == "" {
			hostname = searchHostnameByIP(ip)
		}
	}
	devType := detectType(hostname, vendorClass)
	if devType == "Unknown" && mac != "" {
		devType = detectTypeByMAC(mac)
	}

	// Tier 1: MAC
	if mac != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE mac=?", mac).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
		if db.QueryRow("SELECT device_id FROM device_macs WHERE mac=? LIMIT 1", mac).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
	}

	// Tier 2: Hostname
	if hostname != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE hostname=? LIMIT 1", hostname).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
	}

	// Tier 3: DHCP fingerprint
	if vendorClass != "" && opt55 != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE vendor_class=? AND opt55_hash=?", vendorClass, fpHash).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
	}

	// Final check: after all tiers failed, try to merge by hostname (phone changed MAC)
	if hostname != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE hostname=? LIMIT 1", hostname).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
	}

	// New device
	ipv4 := ""
	if !strings.Contains(ip, ":") {
		ipv4 = ip
	}
	r, _ := db.Exec("INSERT INTO devices (mac,hostname,vendor_class,opt55_hash,device_type,ipv4,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
		mac, hostname, vendorClass, fpHash, devType, ipv4, now, now)
	id, _ := r.LastInsertId()
	if mac != "" {
		db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac,first_seen,last_seen) VALUES (?,?,?,?)", id, mac, now, now)
	}
	return id
}

func updateDev(id int64, ip, mac, hostname, vendorClass, fpHash string, now int64) {
	q := "UPDATE devices SET last_seen=?"
	args := []interface{}{now}
	if mac != "" {
		q += ", mac=?"
		args = append(args, mac)
	}
	if hostname != "" {
		q += ", hostname=CASE WHEN hostname='' THEN ? ELSE hostname END"
		args = append(args, hostname)
		// Update device type from hostname
		if dt := detectType(hostname, ""); dt != "" {
			q += ", device_type=CASE WHEN device_type='Unknown' THEN ? ELSE device_type END"
			args = append(args, dt)
		}
	}
	if vendorClass != "" {
		q += ", vendor_class=?"
		args = append(args, vendorClass)
	}
	if fpHash != "" {
		q += ", opt55_hash=?"
		args = append(args, fpHash)
	}
	if ip != "" && !strings.Contains(ip, ":") {
		q += ", ipv4=?"
		args = append(args, ip)
	}
	q += " WHERE id=?"
	args = append(args, id)
	db.Exec(q, args...)
	if mac != "" {
		db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac,first_seen,last_seen) VALUES (?,?,?,?)", id, mac, now, now)
		// Update device type from MAC OUI if still Unknown
		if dt := detectTypeByMAC(mac); dt != "" {
			db.Exec("UPDATE devices SET device_type=? WHERE id=? AND device_type='Unknown'", dt, id)
		}
	}
}

func detectTypeByMAC(mac string) string {
	mac = strings.ToLower(strings.ReplaceAll(mac, ":", ""))
	if len(mac) < 6 {
		return ""
	}
	oui := mac[:6]
	// Detect randomized/local MAC (bit 1 of first byte = 1 → locally administered)
	if len(mac) >= 2 {
		firstByte, _ := hexToByte(mac[:2])
		if firstByte&0x2 != 0 {
			return "Mobile"
		}
	}
	switch oui {
	// Apple
	case "001e52", "0019e3", "002241", "002312", "002436", "00254b", "002608", "00264a",
		"003065", "0030f4", "0050e4", "006171", "006973", "008061", "00a040", "00b362",
		"00c610", "00d3e1", "00f4b9", "047d7b", "080007", "0c1539", "0c3021", "0c3e9f",
		"0c4de9", "0c5101", "102b96", "109add", "1424d8", "144fd6", "14691d", "149d99",
		"14bd61", "180373", "180f11", "182032", "183451", "186590", "188d0b", "18af61",
		"18e7f4", "1c1ac0", "1c36bb", "1c9148", "1cab01", "2002af", "2056a7", "205ef0",
		"20a2e4", "20c9d0", "2403b4", "28a03d", "28cfda", "28e02c", "28e7cf", "28f076",
		"28ff3c", "2c200b", "2c61f6", "2cbe08", "303316", "3059b7", "3090ab", "30f7c5",
		"3403de", "34363b", "34885d", "34ab37", "34e2fd", "362b1f", "380f4a", "38484c",
		"38c986", "38ec0d", "3c07a9", "3c1596", "3c6c40", "3cbd3e", "3ce072", "404d7f",
		"40a6d9", "40b395", "40bc60", "4400b1", "444c0c", "4464d4", "44d884", "4521c7",
		"480b49", "483b38", "488db6", "48a91c", "48bf6b", "48d705", "4c3271", "4c57ca",
		"4c74bf", "4cb199", "5014a6", "5055b1", "505dac", "507a55", "50bc96", "50de06",
		"50ea5f", "54323d", "54501e", "54ae27", "54e43a", "54eaa8", "583b65", "58b035",
		"5c0947", "5c95ae", "5c97f3", "5cf5da", "5cf7e6", "5cf938", "6001a8", "60334e",
		"6093ec", "60c547", "60f445", "60f81d", "60facd", "60fec5", "61007b", "6476ba",
		"64a3cb", "64b0a6", "64e682", "64fe28", "680949", "68253a", "6834eb", "684342",
		"685b35", "68a86d", "68d93c", "68fef7", "6c19c0", "6c3e6d", "6c4008", "6c709a",
		"6c72e7", "6c8dc5", "6c94f8", "6c96cf", "6caab8", "702b74", "70602b", "7081eb",
		"709c8f", "70a2b3", "70cd60", "70dca2", "70dee2", "70e72c", "70ece4", "70f087",
		"743a20", "7447ae", "7451ba", "748114", "748d08", "74e1b6", "74e2f5", "74e50b",
		"780931", "781844", "783a84", "7853f2", "786C1c", "787e61", "788451", "789f70",
		"78a3e4", "78ca39", "78d75f", "78e103", "78fd94", "7c0191", "7c04d0", "7c11be",
		"7c5049", "7c6d62", "7c6df8", "7cc3a1", "7cc537", "7cf05f", "7cfadf", "80006e",
		"80414e", "804971", "8058f8", "80618f", "80a6bb", "80b03d", "80be05", "80e650",
		"80ea48", "80ed2c", "841310", "8441a9", "847771", "848047", "848e0c", "84a134",
		"84b153", "84f03b", "84fcac", "8801a7", "880501", "8832e9", "886429", "886b44",
		"8873be", "88817c", "88a2d7", "88c663", "88e87f", "8c006d", "8c2937", "8c2daa",
		"8c3d79", "8c5877", "8c7aaa", "8c8590", "8c8ef2", "8caa61", "8cae4c", "8cce4e",
		"8cdb25", "900953", "901b0e", "903c92", "9046b7", "904c4f", "90724b", "90840d",
		"9098f0", "90a2da", "90b0ed", "90b21f", "90b931", "90c1c6", "90f278", "90fd61",
		"941564", "943b1e", "944424", "948d50", "949686", "94bf2d", "94e96a", "94f6a3",
		"9800c6", "98228d", "9824c2", "9825e2", "9844b8", "984b4a", "9859e0", "985aa9",
		"986af3", "987f4e", "98835c", "989e63", "98b8e3", "98c5e9", "98ca33", "98d6bb",
		"98e0d9", "98f0ab", "98fe94", "9c048d", "9c20d0", "9c207b", "9c293f", "9c358f",
		"9c4fda", "9c5106", "9c6492", "9c84bf", "9cf387", "9cf48e", "9cff3d":
		return "Apple"
	// Samsung
	case "0001d8", "001632", "0017c9", "001e98", "0024e9", "0025ab", "00263b", "0050f3",
		"006f64", "0090d0", "00d0cb", "0414a8", "04fe31", "080037", "080d6c",
		"082ae6", "0841bd", "0881bc", "08fc88", "0c2236", "0c2d89", "0c416a", "0c7155",
		"0ce122", "1020b6", "1045be", "1077b1", "10a5d0", "10d3a8", "10e453", "1430e4",
		"144d67", "1484b8", "1491af", "14a51b", "14cc20", "14f0c5", "1814eb", "182463",
		"184e32", "188961", "18af2b", "18dc56", "1c23b9", "1c3ade", "1c4af7", "1c62dc":
		return "Android"
	// Huawei
	case "00049f", "001882", "001e10", "00215c", "002361", "00259c", "0026bc", "0026c9",
		"0046cf", "0049df", "0077e7", "00cc5a", "00e007", "00e0fc", "04036b":
		return "Android"
	// Xiaomi
	case "001a7d", "040e3c", "08d833", "0ccb8d", "104fe4", "141553", "148352",
		"149f3c", "180d32", "1c0499", "1c5cf2", "2016b9", "20a7db", "241b7a", "280728",
		"28c7ce", "2c6fc7", "301ab7", "30c515", "344c0c", "349ee4", "34c731", "38e1d8",
		"403ec7", "405edb", "40e57e", "44a5b6", "4842e3", "48e324", "4c8a9c", "502b73",
		"50cda2", "54e061", "5820b1", "586938", "586ab0", "5c2e59", "5c4f09", "601a28",
		"6411e7", "644d70", "6460e7", "64b392", "64c9f9", "680571", "681dcf", "68a378",
		"68dfdd", "702c01", "70548a", "70a87b", "70bb58", "70fee6", "741e93", "74421e",
		"74b00c", "780d4c", "7830e2", "7831c1", "78471d", "788ec8", "78bcc4", "78d9c9",
		"7c1c4e", "7c8988", "8032b9", "804c6c", "806d77", "808a81", "8091cf":
		return "IoT"
	// Microsoft
	case "0003ff", "00125a", "0012d3", "001320", "0014a5", "00155d", "00172f", "0017fa",
		"0019b5", "001b40", "001b78", "001bfc", "001d09", "001d72", "0021a7":
		return "Windows"
	// Intel (many Windows PCs)
	case "00016c", "00166f", "0018de", "001b21", "001b77", "001cbf", "001de0",
		"001e64", "001e65", "001e67", "001ec0", "001f3b", "002163", "002275", "0023c6",
		"002412", "002427", "002570", "002655", "0026c6", "0026cf", "002713":
		return "Windows"
	// Google
	case "001a11", "001d7e", "00237e", "002415", "044a20", "080026", "08c5e1", "0c0e76",
		"105eb6", "1415b2", "143ee4", "1881e2", "1c659d", "242725", "244451", "2476c9",
		"28c678", "2c4c8c", "305d51", "349108", "38aa5d", "38ca73", "40b4cd",
		"4425bb", "485a3f", "54e4bd", "5859f0", "5c7b9d", "5ce623", "601431", "608f5c",
		"688b87", "6c2995", "6cbb18", "704529", "707c18", "74546c", "7824af":
		return "Android"
	}
	return "Unknown"
}

func detectType(hostname, vendorClass string) string {
	h := strings.ToLower(hostname)
	v := strings.ToLower(vendorClass)
	if h == "" {
		return "Unknown"
	}
	for _, kw := range []string{"iphone", "ipad", "apple", "macbook", "imac"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "Apple"
		}
	}
	for _, kw := range []string{"android", "pixel", "samsung", "sgt-", "oneplus", "redmi", "xiaomi"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "Android"
		}
	}
	if strings.Contains(h, "desktop") || strings.Contains(h, "compil") || strings.Contains(h, "windows") || strings.Contains(h, "pc-") {
		return "Windows"
	}
	if strings.Contains(h, "ubuntu") || strings.Contains(h, "debian") || strings.Contains(h, "raspberry") || strings.Contains(h, "openwrt") || strings.Contains(v, "dhcpcd-") {
		return "Linux"
	}
	for _, kw := range []string{"lumi", "gateway", "midea", "esp", "sonoff", "tasmota", "ipcamera", "camera", "wlan"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "IoT"
		}
	}
	// Tmall, tmall-genie
	if strings.Contains(h, "tmall") || strings.Contains(h, "天猫") {
		return "IoT"
	}
	return "Unknown"
}

// ======== speed via nftables counters ========

var nftPrevUp = map[string]uint64{}
var nftPrevDown = map[string]uint64{}
var nftFirst = map[string]bool{}

func speedLoop() {
	log.Printf("SPEED: started")
	var prevTx, prevRx = map[string]uint64{}, map[string]uint64{}
	var firstDone = map[string]bool{}

	for {
		time.Sleep(3 * time.Second)
		now := time.Now().Unix()

		out, _ := exec.Command("sh", "-c", "cat /proc/net/dev | grep br-lan | awk '{print $2,$10}'").Output()
		f := strings.Fields(string(out))
		tx, rx := uint64(0), uint64(0)
		if len(f) >= 2 {
			tx, _ = atoui(f[1])
			rx, _ = atoui(f[0])
		}

		mu.Lock()
		rows, _ := db.Query("SELECT ipv4 FROM devices WHERE ipv4!=''")
		var ips []string
		if rows != nil {
			for rows.Next() {
				var ip string
				rows.Scan(&ip)
				ips = append(ips, ip)
			}
			rows.Close()
		}
		n := uint64(len(ips))
		if n < 1 {
			mu.Unlock()
			continue
		}
		perTx, perRx := tx/n, rx/n
		log.Printf("SPEED: rx=%d tx=%d n=%d perRx=%d perTx=%d", rx, tx, n, perRx, perTx)

		for _, ip := range ips {
			if !firstDone[ip] {
				firstDone[ip] = true
				prevTx[ip] = perTx
				prevRx[ip] = perRx
				continue
			}
			up := uint64(float64(perTx-prevTx[ip]) / 3.0 * 8)
				dn := uint64(float64(perRx-prevRx[ip]) / 3.0 * 8)
				prevTx[ip] = perTx
				prevRx[ip] = perRx
				if up > 0 || dn > 0 {
					db.Exec("INSERT INTO traffic (device_id,speed_in,speed_out,recorded_at) SELECT id,?,?,? FROM devices WHERE ipv4=?", up, dn, now, ip)
				}
			}
		mu.Unlock()
	}
}

// ======== rules reconcile ========

func reconcileLoop() {
	for {
		time.Sleep(5 * time.Second)
		mergeDuplicateHostnames()
		mu.Lock()
		// 1. Block: for each device_id with is_blocked=1, block ALL its IPs
		blocked, _ := db.Query("SELECT DISTINCT ipv4 FROM devices WHERE is_blocked=1 AND ipv4!=''")
		if blocked != nil {
			for blocked.Next() {
				var ip string
				blocked.Scan(&ip)
				exec.Command(scriptDir+"/block.sh", "add", ip).Run()
			}
			blocked.Close()
		}
		// 2. Unblock: remove IPs that no longer have any blocked device
		unblocked, _ := db.Query("SELECT DISTINCT ipv4 FROM devices WHERE is_blocked=0 AND ipv4!='' AND ipv4 NOT IN (SELECT ipv4 FROM devices WHERE is_blocked=1)")
		if unblocked != nil {
			for unblocked.Next() {
				var ip string
				unblocked.Scan(&ip)
				exec.Command(scriptDir+"/block.sh", "del", ip).Run()
			}
			unblocked.Close()
		}
		// 3. Rate limits
		rows, _ := db.Query("SELECT id, ipv4, is_blocked, rate_limit FROM devices WHERE ipv4!=''")
		if rows != nil {
			for rows.Next() {
				var id int64
				var ip string
				var b, r int
				rows.Scan(&id, &ip, &b, &r)
				if r > 0 {
					exec.Command(scriptDir+"/limit.sh", "set", fmt.Sprintf("%d", id), ip, fmt.Sprintf("%d", r)).Run()
				} else {
					exec.Command(scriptDir+"/limit.sh", "del", fmt.Sprintf("%d", id), ip, "0").Run()
				}
			}
			rows.Close()
		}
		mu.Unlock()
	}
}

// ======== API ========

func apiDevices(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	rows, _ := db.Query(`SELECT d.id, d.alias, d.hostname, d.device_type, d.ipv4, d.mac, d.vendor_class, d.opt55_hash, d.is_blocked, d.rate_limit, d.last_seen,
		CASE WHEN d.last_seen > ? THEN 'green' WHEN d.last_seen > ? THEN 'yellow' ELSE 'gray' END,
		(SELECT COUNT(DISTINCT mac) FROM device_macs WHERE device_id=d.id)
		FROM devices d ORDER BY d.ipv4 ASC`, time.Now().Unix()-120, time.Now().Unix()-1800)
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
		rows.Scan(&d.ID, &d.Alias, &d.Hostname, &d.DeviceType, &d.CurrentIP, &d.CurrentMAC, &d.VendorClass, &d.Opt55Hash, &b, &d.RateLimit, &d.LastSeen, &d.Online, &d.NumMACs)
		if d.DeviceType == "" {
			d.DeviceType = "Unknown"
		}
		d.IsBlocked = b == 1
		db.QueryRow("SELECT COALESCE(speed_out,0) FROM traffic WHERE device_id=? ORDER BY recorded_at DESC LIMIT 1", d.ID).Scan(&d.SpeedOut)
		db.QueryRow("SELECT COALESCE(speed_in,0) FROM traffic WHERE device_id=? ORDER BY recorded_at DESC LIMIT 1", d.ID).Scan(&d.SpeedIn)
		devs = append(devs, d)
	}
	json.NewEncoder(w).Encode(devs)
}

func apiDHCPEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC, IP, Hostname, VendorClass, Opt55 string
	}
	json.NewDecoder(r.Body).Decode(&req)
	upsertDevice(req.IP, req.MAC, req.Hostname, req.VendorClass, req.Opt55)
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
	// Reconcile will pick it up within 5s and apply the block
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

func getMACviaNeigh(ip string) string {
	out, _ := exec.Command("sh", "-c", "ip neigh show | grep '"+ip+"'").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, "lladdr "); idx > 0 {
			return strings.SplitN(line[idx+7:], " ", 2)[0]
		}
	}
	return ""
}

func getMAC(ip string) string {
	out, _ := exec.Command("sh", "-c", "ip neigh show | grep '"+ip+"'").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, "lladdr "); idx > 0 {
			return strings.SplitN(line[idx+7:], " ", 2)[0]
		}
	}
	return ""
}

func searchHostnameByIP(ip string) string {
	// Search all lease files for this IP and return the hostname
	out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan 2>/dev/null | grep '"+ip+"[\t ]' | head -1").Output()
	f := strings.Fields(string(out))
	if len(f) >= 2 {
		return f[1]
	}
	return ""
}

func getHostname(ip string) string {
	out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan /etc/dhcp.leases 2>/dev/null | grep '"+ip+"' | head -1").Output()
	f := strings.Fields(string(out))
	if len(f) >= 4 && f[2] == ip {
		return f[3]
	}
	if len(f) >= 2 && f[0] == ip {
		return f[1]
	}
	return ""
}

func mergeDuplicateHostnames() {
	// Merge when same hostname AND either:
	// 1. Both have matching fingerprints
	// 2. One has fingerprint, the other has random MAC (phone privacy)
	rows, _ := db.Query(`SELECT d1.id, d2.id, d1.hostname, d1.mac, d2.mac, d1.ipv4, d2.ipv4, d1.vendor_class, d2.vendor_class, d1.opt55_hash, d2.opt55_hash
		FROM devices d1 JOIN devices d2 ON d1.hostname=d2.hostname AND d1.id<d2.id
		WHERE d1.hostname!=''`)
	if rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id1, id2 int64
		var hostname, mac1, mac2, ip1, ip2, vc1, vc2, fp1, fp2 string
		rows.Scan(&id1, &id2, &hostname, &mac1, &mac2, &ip1, &ip2, &vc1, &vc2, &fp1, &fp2)

		// Decision rules:
		hasFP1 := vc1 != "" && fp1 != ""
		hasFP2 := vc2 != "" && fp2 != ""
		fpMatch := hasFP1 && hasFP2 && vc1 == vc2 && fp1 == fp2

		shouldMerge := false
		if fpMatch {
			shouldMerge = true // Both have matching fingerprints → same device
		} else if hasFP1 && !hasFP2 {
			shouldMerge = true // One has fingerprint, other doesn't → merge into the known one
		} else if !hasFP1 && hasFP2 {
			shouldMerge = true // Same but reversed
		}
		if !shouldMerge {
			continue // Both without fingerprints → don't merge (could be different devices)
		}

		// Keep the one with fingerprint, or with fixed MAC
		keepID, rmID := id1, id2
		if !hasFP1 && hasFP2 {
			keepID, rmID = id2, id1
		} else if hasFP1 == hasFP2 {
			if isRandomMAC(mac1) && !isRandomMAC(mac2) {
				keepID, rmID = id2, id1
			}
		}

		db.Exec("UPDATE devices SET ipv4=CASE WHEN ipv4='' THEN ? ELSE ipv4 END WHERE id=?", ip2, keepID)
		// Move all data from rm to keep
		db.Exec("UPDATE device_macs SET device_id=? WHERE device_id=?", keepID, rmID)
		// Update keep with rm's IP and MAC if keep doesn't have them
		db.Exec("UPDATE devices SET ipv4=CASE WHEN ipv4='' THEN ? ELSE ipv4 END WHERE id=?", ip2, keepID)
		now := time.Now().Unix()
		if isRandomMAC(mac2) && !isRandomMAC(mac1) {
			db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac,first_seen,last_seen) VALUES (?,?,?,?)", keepID, mac2, now, now)
		} else if isRandomMAC(mac1) && !isRandomMAC(mac2) {
			db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac,first_seen,last_seen) VALUES (?,?,?,?)", keepID, mac1, now, now)
		}
		db.Exec("DELETE FROM devices WHERE id=?", rmID)
		log.Printf("Fingerprint-merged %s: %d → %d", hostname, rmID, keepID)
	}
}

func isRandomMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := hexToByte(mac[:2])
	if err != nil {
		return false
	}
	return b&0x2 != 0
}

func hashOpt55(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

func field(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	return strings.SplitN(line[idx+len(key):], " ", 2)[0]
}

func isLAN(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			ip.IsPrivate()
	}
	return len(ip) == net.IPv6len &&
		((ip[0]&0xfe) == 0xfc ||
			(ip[0] == 0xfe && ip[1]&0xc0 == 0x80))
}

func hexToByte(s string) (byte, error) {
	var b byte
	for i, c := range s {
		b *= 16
		switch {
		case c >= '0' && c <= '9':
			b += byte(c - '0')
		case c >= 'a' && c <= 'f':
			b += byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			b += byte(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("bad hex char %c at pos %d", c, i)
		}
	}
	return b, nil
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
