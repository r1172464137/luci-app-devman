# devman - OpenWrt Device Manager

Real-time device monitoring and control for OpenWrt routers.

## Features

- **Auto-discover** all LAN devices (conntrack + DHCP lease scanning)
- **Device merge** — IPv4/IPv6 for same MAC merged into one
- **Per-device speed** — real-time traffic rate (bps)
- **Hostname detection** — reads from dnsmasq & odhcpd leases
- **Block** — instantly cut internet for any device (nftables drop)
- **Limit** — per-device bandwidth cap (tc htb)
- **Rename** — custom device aliases
- **Web UI** — LuCI integration with auto-refresh

## Architecture

```
devman (Go daemon, /usr/bin/devman)
  ├─ conntrack -E  → detect new devices
  ├─ DHCP lease scan → hostname + IP
  ├─ conntrack -L   → per-IP byte counters → real-time speed
  ├─ nftables       → block/allow
  ├─ tc htb          → rate limit
  └─ HTTP :9999     → JSON API

luci-app-devman
  └─ LuCI controller + view → Web UI
```

## Install

```bash
opkg install devman_*.ipk luci-app-devman_*.ipk
/etc/init.d/devman start
```

Open LuCI → Network → Device Manager

## Requirements

- OpenWrt 23.05+
- nftables (firewall4)
- conntrack

## Build

```bash
# Go backend (pure Go, no CGO)
CGO_ENABLED=0 go build -ldflags="-s -w" -o devman .

# LuCI frontend (via OpenWrt build system)
make package/luci-app-devman/compile
```

## License

MIT
