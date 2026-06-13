package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func htons(v uint16) uint16 { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return binary.BigEndian.Uint16(b) }

// ====== discovery ======

func mdnsLoop() {
	for {
		// Raw socket mDNS listener — bypass Go's net.ListenMulticastUDP (broken on musl)
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			time.Sleep(60 * time.Second)
			continue
		}
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		sa := &syscall.SockaddrInet4{Port: 5353}
		copy(sa.Addr[:], net.ParseIP("224.0.0.251").To4())
		if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 5353}); err != nil {
			syscall.Close(fd)
			time.Sleep(60 * time.Second)
			continue
		}
		// Join multicast group
		var mreq [8]byte
		copy(mreq[0:4], net.ParseIP("224.0.0.251").To4())
		syscall.SetsockoptString(fd, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, string(mreq[:]))
		// Set timeout
		tv := syscall.Timeval{Sec: 5}
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		buf := make([]byte, 2048)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				break
			}
			if n < 12 || buf[2]&0x80 != 0x80 {
				continue
			}
			// Quick scan for .local hostname in response
			data := string(buf[:n])
			if !strings.Contains(data, ".local") {
				continue
			}
			for i := 12; i < n-8; i++ {
				// Look for A record (type=1) with IPv4 in answer
				if buf[i] == 0xc0 && buf[i+1] == 0x0c && i+12 < n {
					// Compressed name pointer, check for A record type
					if buf[i+2] == 0x00 && buf[i+3] == 0x01 && buf[i+8] == 0x00 && buf[i+9] == 0x04 {
						ip := fmt.Sprintf("%d.%d.%d.%d", buf[i+10], buf[i+11], buf[i+12], buf[i+13])
						if strings.HasPrefix(ip, "192.168") {
							// Find hostname before this answer
							for j := 12; j < i; j++ {
								segLen := int(buf[j])
								if segLen > 0 && segLen < 64 && j+segLen+1 < n-1 && buf[j+segLen+1] == 0x00 {
									hostname := string(buf[j+1 : j+1+segLen])
									nextOff := j + segLen + 1
									if nextOff < n-1 && buf[nextOff] > 0 && nextOff+int(buf[nextOff]) < n {
										hostname += "." + string(buf[nextOff+1:nextOff+1+int(buf[nextOff])])
									}
									if len(hostname) > 0 && !strings.Contains(hostname, "\x00") {
										upsertDevice(ip, "", hostname, "", "")
									}
									break
								}
							}
						}
					}
				}
			}
		}
		syscall.Close(fd)
		time.Sleep(60 * time.Second)
	}
}

func neightLoop() {
	log.Printf("NEIGH: started")
	firstRun := true
	for {
		if firstRun {
			exec.Command("/bin/ping", "-b", "-c", "1", "-W", "1", "192.168.5.255").Run()
			firstRun = false
		}
		out, _ := exec.Command("sh", "-c", "ip neigh show | grep -v FAILED").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			ip, mac := fields[0], fields[4]
			if mac == "00:00:00:00:00:00" || mac == "incomplete" || strings.HasPrefix(ip, "169.254") || strings.HasPrefix(ip, "127.") {
				continue
			}
			upsertDevice(ip, mac, "", "", "")
		}
		time.Sleep(10 * time.Second)
	}
}

func conntrackLoop() {
	log.Printf("CONNTRACK: started")
	for {
		out, _ := exec.Command("/usr/sbin/conntrack", "-L", "-o", "id").Output()
		for _, line := range strings.Split(string(out), "\n") {
			srcIdx := strings.Index(line, "src=")
			if srcIdx < 0 {
				continue
			}
			src := strings.SplitN(line[srcIdx+4:], " ", 2)[0]
			dstIdx := strings.Index(line, "dst=")
			if dstIdx < 0 {
				continue
			}
			dst := strings.SplitN(line[dstIdx+4:], " ", 2)[0]
			if !strings.HasPrefix(src, "192.168") && strings.HasPrefix(dst, "192.168") {
				ip := dst
				if ip != "" && !strings.HasPrefix(ip, "127.") && strings.Contains(line, "ASSURED") {
					upsertDevice(ip, "", "", "", "")
				}
			}
		}
		time.Sleep(15 * time.Second)
	}
}

func leaseLoop() {
	log.Printf("LEASE: started")
	for {
		fillHostnamesFromLeases()
		time.Sleep(30 * time.Second)
	}
}

func dhcpSniffLoop() {
	log.Printf("DHCP_RAW: starting AF_PACKET raw socket...")
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Printf("DHCP_RAW: raw socket failed: %v", err)
		return
	}
	defer syscall.Close(fd)

	buf := make([]byte, 2048)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		// ETH header (14) + IP header (20) + UDP header (8) = 42 bytes offset
		if n < 42+244 {
			continue
		}
		offset := 42
		if buf[offset] != 2 {
			continue
		} // BOOTREPLY
		htype := buf[offset+1]
		hlen := buf[offset+2]
		if htype != 1 || hlen != 6 {
			continue
		}
		mac := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			hexToStr(buf[offset+28]), hexToStr(buf[offset+29]),
			hexToStr(buf[offset+30]), hexToStr(buf[offset+31]),
			hexToStr(buf[offset+32]), hexToStr(buf[offset+33]))
		ip := fmt.Sprintf("%d.%d.%d.%d", buf[offset+16], buf[offset+17], buf[offset+18], buf[offset+19])
		// Parse options
		var msgType, hostname, vendorClass string
		var opt55hex []byte
		optPos := offset + 240
		for optPos < n-1 {
			optCode := int(buf[optPos])
			if optCode == 255 {
				break
			}
			optLen := int(buf[optPos+1])
			if optPos+optLen >= n {
				break
			}
			switch optCode {
			case 53:
				if optLen >= 1 {
					msgType = fmt.Sprintf("%d", buf[optPos+2])
				}
			case 12:
				if optLen > 0 {
					hostname = string(buf[optPos+2 : optPos+2+optLen])
				}
			case 60:
				if optLen > 0 {
					vendorClass = string(buf[optPos+2 : optPos+2+optLen])
				}
			case 55:
				if optLen > 0 {
					opt55hex = make([]byte, optLen)
					for i := 0; i < optLen; i++ {
						opt55hex[i] = buf[optPos+2+i]
					}
				}
			}
			optPos += 2 + optLen
		}
		if msgType == "3" || msgType == "5" {
			opt55hash := fmt.Sprintf("%x", sha256.Sum256(opt55hex))[:8]
			upsertDevice(ip, mac, hostname, vendorClass, opt55hash)
		}
	}
}

func isLAN(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.16.")
}

func isIPv4(ip string) bool {
	for _, c := range ip {
		if (c < '0' || c > '9') && c != '.' { return false }
	}
	return strings.Count(ip, ".") == 3
}

// ====== DB ops ======

func upsertDevice(ip, mac, hostname, vendorClass, opt55 string) int64 {
	now := time.Now().Unix()
	// Ignore IPv6 addresses
	if ip != "" && strings.Contains(ip, ":") { ip = "" }
	// Must have at least one identifiable attribute
	if ip == "" && hostname == "" && mac == "" { return 0 }
	// Must have IP or MAC to create a device
	if ip == "" && mac == "" { return 0 }
	fpHash := ""
	if vendorClass != "" && opt55 != "" {
		fpHash = fmt.Sprintf("%x", sha256.Sum256([]byte(vendorClass+opt55)))[:8]
	}
	if ip == "" && hostname == "" && mac == "" {
		return 0
	}
	// Try to fill hostname from leases if we have an IP
	if hostname == "" && ip != "" {
		hostname = searchHostnameByIP(ip)
	}
	devType := detectType(hostname, vendorClass)
	if devType == "Unknown" && mac != "" {
		devType = detectTypeByMAC(mac)
	}
	// Tier 1: MAC
	if mac != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE mac=?", mac).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, devType, now)
			return id
		}
	}
	// Tier 2: hostname
	if hostname != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE hostname=?", hostname).Scan(&id) == nil {
			if mac != "" && db.QueryRow("SELECT id FROM device_macs WHERE mac=?", mac).Scan(new(int64)) != sql.ErrNoRows {
			}
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, devType, now)
			return id
		}
	}
	// Tier 3: DHCP fingerprint
	if vendorClass != "" && opt55 != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE vendor_class=? AND opt55_hash=?", vendorClass, fpHash).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, devType, now)
			return id
		}
	}
	// New device
	result, _ := db.Exec("INSERT INTO devices (alias,hostname,device_type,mac,ipv4,vendor_class,opt55_hash,last_seen) VALUES ('',?,?,?,?,?,?,?)",
		hostname, devType, mac, ip, vendorClass, fpHash, now)
	if result != nil {
		id, _ := result.LastInsertId()
		if mac != "" {
			db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac) VALUES (?,?)", id, mac)
		}
		return id
	}
	return 0
}

func updateDev(id int64, ip, mac, hostname, vendorClass, fpHash, devType string, now int64) {
	currentIP := ""
	db.QueryRow("SELECT ipv4 FROM devices WHERE id=?", id).Scan(&currentIP)
	db.Exec("UPDATE devices SET ipv4=?, last_seen=? WHERE id=?", ip, now, id)
	if hostname != "" {
		db.Exec("UPDATE devices SET hostname=? WHERE id=? AND hostname=''", hostname, id)
	}
	if devType != "" && devType != "Unknown" {
		db.Exec("UPDATE devices SET device_type=? WHERE id=? AND (device_type='Unknown' OR device_type='')", devType, id)
	}
	if vendorClass != "" && fpHash != "" {
		db.Exec("UPDATE devices SET vendor_class=?, opt55_hash=? WHERE id=?", vendorClass, fpHash, id)
	}
	if mac != "" {
		db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac) VALUES (?,?)", id, mac)
	}
	// If IP changed from one known IP to another and the old IP was recorded as a different device, merge
	if currentIP != "" && currentIP != "0.0.0.0" && currentIP != ip && ip != "" {
		var dupID int64
		if db.QueryRow("SELECT id FROM devices WHERE ipv4=? AND id!=?", ip, id).Scan(&dupID) == nil {
			db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac) SELECT ?, mac FROM device_macs WHERE device_id=?", id, dupID)
			db.Exec("DELETE FROM device_macs WHERE device_id=?", dupID)
			db.Exec("UPDATE devices SET hostname=(SELECT hostname FROM devices WHERE id=?) WHERE id=? AND hostname=''", dupID, id)
			db.Exec("DELETE FROM devices WHERE id=?", dupID)
		}
	}
}

func mergeDuplicateHostnames() {
	rows, err := db.Query("SELECT hostname, COUNT(*) cnt FROM devices WHERE hostname!='' GROUP BY hostname HAVING cnt>1")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var hostname string
		var cnt int
		rows.Scan(&hostname, &cnt)
		// Find all IDs with this hostname
		r2, _ := db.Query("SELECT id FROM devices WHERE hostname=? ORDER BY last_seen DESC", hostname)
		if r2 == nil {
			continue
		}
		var ids []int64
		for r2.Next() {
			var id int64
			r2.Scan(&id)
			ids = append(ids, id)
		}
		r2.Close()
		if len(ids) < 2 {
			continue
		}
		keeper := ids[0]
		for _, id := range ids[1:] {
			db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac) SELECT ?, mac FROM device_macs WHERE device_id=?", keeper, id)
			db.Exec("DELETE FROM device_macs WHERE device_id=?", id)
			db.Exec("DELETE FROM devices WHERE id=?", id)
		}
	}
}

// ====== rules reconcile ======

func reconcileLoop() {
	for {
		time.Sleep(5 * time.Second)
		mergeDuplicateHostnames()
		mu.Lock()
		// 1. Block
		blocked, _ := db.Query("SELECT DISTINCT ipv4 FROM devices WHERE is_blocked=1 AND ipv4!=''")
		if blocked != nil {
			for blocked.Next() {
				var ip string
				blocked.Scan(&ip)
				nftBlock(ip)
			}
			blocked.Close()
		}
		// 2. Unblock
		unblocked, _ := db.Query("SELECT DISTINCT ipv4 FROM devices WHERE is_blocked=0 AND ipv4!='' AND ipv4 NOT IN (SELECT ipv4 FROM devices WHERE is_blocked=1)")
		if unblocked != nil {
			for unblocked.Next() {
				var ip string
				unblocked.Scan(&ip)
				nftUnblock(ip)
			}
			unblocked.Close()
		}
		mu.Unlock()
	}
}

// ====== HTTP handlers ======

func apiDevices(w http.ResponseWriter, r *http.Request) {
	calcSpeed()
	mu.RLock()
	defer mu.RUnlock()
	rows, _ := db.Query(`SELECT d.id, d.alias, d.hostname, d.device_type, d.ipv4, d.mac, d.vendor_class, d.opt55_hash, d.is_blocked, d.rate_limit, COALESCE(d.rate_limit_dn,0), d.last_seen,
		CASE WHEN d.last_seen > ? THEN 'green' WHEN d.last_seen > ? THEN 'yellow' ELSE 'gray' END,
		(SELECT COUNT(DISTINCT mac) FROM device_macs WHERE device_id=d.id)
		FROM devices d WHERE d.ipv4!='' ORDER BY d.ipv4 ASC`, time.Now().Unix()-120, time.Now().Unix()-1800)
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
		rows.Scan(&d.ID, &d.Alias, &d.Hostname, &d.DeviceType, &d.CurrentIP, &d.CurrentMAC, &d.VendorClass, &d.Opt55Hash, &b, &d.RateLimit, &d.RateLimitDn, &d.LastSeen, &d.Online, &d.NumMACs)
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

func apiBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID int64 `json:"device_id"`
		Block    bool  `json:"block"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	b := 0
	if req.Block {
		b = 1
	}
	db.Exec("UPDATE devices SET is_blocked=? WHERE id=?", b, req.DeviceID)
	w.Write([]byte(`{"ok":true}`))
}

func apiLimit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID    int64  `json:"device_id"`
		RateLimit   int    `json:"rate_limit"`
		RateLimitDn int    `json:"rate_limit_down"`
		Alias       string `json:"alias"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	log.Printf("LIMIT: id=%d rate=%d ratedn=%d alias=%s", req.DeviceID, req.RateLimit, req.RateLimitDn, req.Alias)
	if req.Alias != "" {
		db.Exec("UPDATE devices SET alias=? WHERE id=?", req.Alias, req.DeviceID)
	}
	if req.RateLimit != -1 {
		db.Exec("UPDATE devices SET rate_limit=? WHERE id=?", req.RateLimit, req.DeviceID)
	}
	if req.RateLimitDn != -1 {
		db.Exec("UPDATE devices SET rate_limit_dn=? WHERE id=?", req.RateLimitDn, req.DeviceID)
	}
	var ip string
	db.QueryRow("SELECT ipv4 FROM devices WHERE id=?", req.DeviceID).Scan(&ip)
	if ip != "" {
		var ul, dl int
		db.QueryRow("SELECT COALESCE(rate_limit,0), COALESCE(rate_limit_dn,0) FROM devices WHERE id=?", req.DeviceID).Scan(&ul, &dl)
		go nftSetLimit(ip, ul, dl)
	}
	w.Write([]byte(`{"ok":true}`))
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
	if req.MAC != "" && req.IP != "" {
		upsertDevice(req.IP, req.MAC, req.Hostname, req.VendorClass, req.Opt55)
	}
	w.Write([]byte(`{"ok":true}`))
}
