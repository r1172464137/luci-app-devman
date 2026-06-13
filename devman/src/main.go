package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"time"
	"syscall"

	_ "modernc.org/sqlite"
)

// ====== entry ======

func main() {
	log.SetFlags(log.LstdFlags)
	os.MkdirAll("/etc/devman", 0755)

	var err error
	db, err = sql.Open("sqlite", "/etc/devman/devman.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	initDB()
	// Re-detect vendor from hostname for old "Android" devices
	db.Exec("UPDATE devices SET device_type='Xiaomi' WHERE device_type='Android' AND (hostname LIKE '%xiaomi%' OR hostname LIKE '%redmi%')")
	db.Exec("UPDATE devices SET device_type='Samsung' WHERE device_type='Android' AND (hostname LIKE '%samsung%' OR hostname LIKE '%sgt-%')")
	db.Exec("UPDATE devices SET device_type='OnePlus' WHERE device_type='Android' AND hostname LIKE '%oneplus%'")
	db.Exec("UPDATE devices SET device_type='Huawei' WHERE device_type='Android' AND (hostname LIKE '%huawei%' OR hostname LIKE '%honor%')")
	db.Exec("UPDATE devices SET device_type='Google' WHERE device_type='Android' AND hostname LIKE '%pixel%'")
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

	nftInit()
	restoreRateLimits()
	installDnsmasqHook()
	db.Exec("UPDATE devices SET device_type='Unknown' WHERE device_type='' OR device_type IS NULL")

	go neightLoop()
	go conntrackLoop()
	go resolveHostnamesLoop()
	go dhcpSniffLoop()
	go reconcileLoop()

	http.HandleFunc("/api/devices", apiDevices)
	http.HandleFunc("/api/block", apiBlock)
	http.HandleFunc("/api/limit", apiLimit)
	http.HandleFunc("/api/dhcp-event", apiDHCPEvent)
	go http.ListenAndServe(":9999", nil)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	nftCleanup()
}

// ====== init ========

type DeviceProfile struct {
	ID          int64  `json:"id"`
	Alias       string `json:"alias"`
	Hostname    string `json:"hostname"`
	DeviceType  string `json:"device_type"`
	CurrentIP   string `json:"current_ip"`
	CurrentMAC  string `json:"current_mac"`
	IsBlocked   bool   `json:"is_blocked"`
	RateLimit   int    `json:"rate_limit"`
	RateLimitDn int    `json:"rate_limit_down"`
	LastSeen    int64  `json:"last_seen"`
	Online      string `json:"online"`
	VendorClass string `json:"vendor_class"`
	Opt55Hash   string `json:"opt55_hash"`
	Vendor      string `json:"vendor"`
	SpeedIn     uint64 `json:"speed_in"`
	SpeedOut    uint64 `json:"speed_out"`
	NumMACs     int    `json:"num_macs"`
}

var (
	db       *sql.DB
	mu       sync.RWMutex
	limitMu  sync.Mutex
	lanIface = "br-lan"
)

func initDB() {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT, alias TEXT DEFAULT '', hostname TEXT DEFAULT '',
			device_type TEXT DEFAULT 'Unknown', mac TEXT DEFAULT '', ipv4 TEXT DEFAULT '',
			is_blocked INTEGER DEFAULT 0, rate_limit INTEGER DEFAULT 0, rate_limit_dn INTEGER DEFAULT 0,
			last_seen INTEGER DEFAULT 0, vendor_class TEXT DEFAULT '', opt55_hash TEXT DEFAULT '', vendor TEXT DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS fingerprints (
			id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_class TEXT, opt55_hash TEXT,
			device_type TEXT DEFAULT 'Unknown', mac TEXT, hostname TEXT)`,
		`CREATE TABLE IF NOT EXISTS device_macs (device_id INTEGER, mac TEXT, UNIQUE(device_id, mac))`,
		`CREATE TABLE IF NOT EXISTS traffic (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, speed_in INTEGER DEFAULT 0, speed_out INTEGER DEFAULT 0, recorded_at INTEGER DEFAULT 0)`,
		`ALTER TABLE traffic ADD COLUMN speed_in INTEGER DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN rate_limit_dn INTEGER DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN vendor TEXT DEFAULT ''`,
	} {
		db.Exec(q)
	}
}

func installDnsmasqHook() {
	os.WriteFile("/usr/lib/dnsmasq/dhcp-script.sh", []byte(`#!/bin/sh
[ "$1" = "add" ] || [ "$1" = "old" ] || exit 0
curl -s -X POST http://127.0.0.1:9999/api/dhcp-event -H "Content-Type: application/json" \
  -d "{\"mac\":\"$2\",\"ip\":\"$3\",\"hostname\":\"${DNSMASQ_SUPPLIED_HOSTNAME:-}\",\"vendor_class\":\"${DNSMASQ_VENDOR_CLASS:-}\",\"opt55\":\"${DNSMASQ_REQUESTED_OPTIONS:-}\"}" &
`), 0755)
	exec.Command("uci", "set", "dhcp.@dnsmasq[0].dhcpscript=/usr/lib/dnsmasq/dhcp-script.sh").Run()
	exec.Command("uci", "commit", "dhcp").Run()
	exec.Command("/etc/init.d/dnsmasq", "reload").Run()
}

func netbiosQuery(ip string) string {
	// NetBIOS Node Status query on UDP 137
	conn, err := net.DialTimeout("udp", ip+":137", 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	// NODE STATUS REQUEST
	req := make([]byte, 50)
	req[0], req[1] = 0xa2, 0x48 // transaction ID
	req[2], req[4], req[5] = 0x00, 0x00, 0x01 // flags, questions
	req[11] = 0x20 // name length = 32
	for i := 12; i < 44; i++ {
		req[i] = 0x43
	}
	req[43] = 0x00       // terminator
	req[44], req[45] = 0x00, 0x21 // type = NBSTAT
	req[46], req[47] = 0x00, 0x01 // class = IN
	conn.Write(req)
	resp := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(resp)
	if n < 57 {
		return ""
	}
	numNames := int(resp[56])
	for i := 0; i < numNames && 57+i*18+16 <= n; i++ {
		off := 57 + i*18
		name := strings.TrimRight(string(resp[off:off+15]), " \x00")
		if len(name) > 0 && int(resp[off+15]) == 0x00 { // Workstation service
			return name
		}
	}
	return ""
}

func llmnrQuery(ip string) string {
	// LLMNR reverse query: send to 224.0.0.252:5355
	parts := strings.Split(ip, ".")
	if len(parts) != 4 { return "" }
	qname := fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa", parts[3], parts[2], parts[1], parts[0])
	return mdnsQuery(qname, "12") // PTR record
}

func mdnsQuery(name string, qtype string) string {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("224.0.0.252"), Port: 5355})
	if err != nil { return "" }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	// Build DNS query
	q := make([]byte, 0, 128)
	q = append(q, 0x00, 0x00) // ID
	q = append(q, 0x00, 0x00) // flags
	q = append(q, 0x00, 0x01) // QDCOUNT=1
	q = append(q, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR
	for _, part := range strings.Split(name, ".") {
		q = append(q, byte(len(part)))
		q = append(q, []byte(part)...)
	}
	q = append(q, 0x00) // terminator
	q = append(q, 0x00, 0x0c) // type PTR
	q = append(q, 0x00, 0x01) // class IN
	conn.Write(q)
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n < 12 { return "" }
	ansCount := int(buf[6])<<8 | int(buf[7])
	if ansCount == 0 { return "" }
	off := 12
	for off < n && buf[off] != 0x00 { off += int(buf[off]) + 1 }
	off += 5 // terminator + QTYPE + QCLASS
	if off+12 > n { return "" }
	off += 2 // skip name pointer
	off += 6 // type + class
	off += 4 // TTL
	rdLen := int(buf[off])<<8 | int(buf[off+1])
	off += 2
	if off+rdLen > n { return "" }
	rd := buf[off:off+rdLen]
	nameEnd := 0
	for nameEnd < rdLen && rd[nameEnd] != 0x00 {
		seg := int(rd[nameEnd])
		if seg > 63 { return "" }
		nameEnd += seg + 1
	}
	return strings.TrimSuffix(strings.ReplaceAll(string(rd[:nameEnd]), "\x00", "."), ".")
}

func resolveHostnamesLoop() {
	for {
		rows, _ := db.Query("SELECT DISTINCT ipv4 FROM devices WHERE hostname='' AND ipv4!=''")
		if rows != nil {
			for rows.Next() {
				var ip string
				rows.Scan(&ip)
				// Method 1: DNS reverse (nslookup)
				out, err := exec.Command("nslookup", ip).Output()
				if err == nil {
					for _, line := range strings.Split(string(out), "\n") {
						if strings.Contains(line, "name =") {
							hn := strings.TrimSpace(strings.Split(line, "name =")[1])
							hn = strings.TrimSuffix(hn, ".")
							if len(hn) > 0 && hn != "localhost" {
								upsertDevice(ip, "", hn, "", "")
								db.Exec("UPDATE devices SET hostname=? WHERE ipv4=? AND hostname=''", hn, ip)
							}
						}
					}
				}
				// Method 2: LLMNR (Windows)
				if hn := llmnrQuery(ip); hn != "" {
					upsertDevice(ip, "", hn, "", "")
					db.Exec("UPDATE devices SET hostname=? WHERE ipv4=? AND hostname=''", hn, ip)
				}
				// Method 3: NetBIOS (Windows legacy)
				if nb := netbiosQuery(ip); nb != "" {
					upsertDevice(ip, "", nb, "", "")
					db.Exec("UPDATE devices SET hostname=? WHERE ipv4=? AND hostname=''", nb, ip)
				}
			}
			rows.Close()
		}
		time.Sleep(15 * time.Second)
	}
}

func hexToByte(s string) (byte, error) {
	var b byte
	for i := 0; i < 2; i++ {
		var v byte
		switch {
		case s[i] >= '0' && s[i] <= '9':
			v = s[i] - '0'
		case s[i] >= 'a' && s[i] <= 'f':
			v = s[i] - 'a' + 10
		case s[i] >= 'A' && s[i] <= 'F':
			v = s[i] - 'A' + 10
		default:
			return 0, fmt.Errorf("invalid hex")
		}
		b = b<<4 | v
	}
	return b, nil
}

func hexToStr(b byte) string   { return fmt.Sprintf("%02x", b) }
func min(a, b int) int         { if a < b { return a }; return b }
