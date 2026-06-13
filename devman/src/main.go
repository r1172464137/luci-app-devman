package main

import (
	"database/sql"
	"fmt"
	"log"
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
	// Immediately fill hostnames from existing leases
	fillHostnamesFromLeases()

	go neightLoop()
	go mdnsLoop()
	go conntrackLoop()
	go leaseLoop()
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

func getLeaseFile() string {
	out, err := exec.Command("uci", "get", "dhcp.@dnsmasq[0].leasefile").Output()
	if err == nil && len(out) > 1 {
		return strings.TrimSpace(string(out))
	}
	return "/etc/dhcp.leases"
}

func resolveHostnamesLoop() {
	for {
		rows, _ := db.Query("SELECT DISTINCT ipv4 FROM devices WHERE hostname='' AND ipv4!='' AND isIPv4")
		if rows != nil {
			for rows.Next() {
				var ip string
				rows.Scan(&ip)
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
			}
			rows.Close()
		}
		time.Sleep(30 * time.Second)
	}
}

func fillHostnamesFromLeases() {
	leaseFile := getLeaseFile()
	out, _ := os.ReadFile(leaseFile)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ip := fields[2]
			hostname := fields[3]
			if hostname != "" && hostname != "*" && isLAN(ip) {
				upsertDevice(ip, "", hostname, "", "")
				// Persist hostname in DB so it survives lease wipe
				db.Exec("UPDATE devices SET hostname=? WHERE ipv4=? AND hostname=''", hostname, ip)
			}
		}
	}
	// dnsmasq hosts table (/tmp/hosts)
	out, _ = os.ReadFile("/tmp/hosts")
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && isLAN(fields[0]) {
			hostname := fields[1]
			if hostname != "" && !strings.HasPrefix(hostname, "#") {
				upsertDevice(fields[0], "", hostname, "", "")
				db.Exec("UPDATE devices SET hostname=? WHERE ipv4=? AND hostname=''", hostname, fields[0])
			}
		}
	}
	// Restore persisted hostnames from DB for devices that lost them
	db.Exec("UPDATE devices SET hostname=(SELECT hostname FROM devices d2 WHERE d2.mac=devices.mac AND d2.hostname!='' ORDER BY d2.last_seen DESC LIMIT 1) WHERE hostname=''")
	// Active reverse DNS via dnsmasq
	rows, _ := db.Query("SELECT DISTINCT ipv4 FROM devices WHERE hostname='' AND ipv4!=''")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ip string
			rows.Scan(&ip)
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
		}
	}
}

func searchHostnameByIP(ip string) string {
	out, _ := os.ReadFile("/etc/dhcp.leases")
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[2] == ip {
			if hn := fields[3]; hn != "*" {
				return hn
			}
		}
	}
	return ""
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
