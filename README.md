<p align="center">
  <strong><a href="./README.zh-CN.md">简体中文</a></strong>
  &nbsp;·&nbsp;
  <strong>English</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/OpenWrt-LuCI-00B5E2?style=flat-square&logo=openwrt&logoColor=white" alt="OpenWrt"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/database-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite"/>
  <img src="https://img.shields.io/badge/CGO-0-blue?style=flat-square" alt="CGO"/>
</p>

<h1 align="center">devman</h1>
<h3 align="center">OpenWrt Device Manager</h3>

<p align="center">
  Real-time device monitoring, blocking, and rate limiting for OpenWrt routers.
  <br/>
  <em>Card-style LuCI frontend · Pure Go daemon · Zero shell scripts</em>
</p>

---

## ✨ Features

| | | |
|:--|------|------|
| 🔍 | **Auto-discovery** | `ip neigh` + conntrack + dnsmasq lease — zero active probing |
| 📡 | **DHCP Fingerprint** | BPF socket filter real-time capture of Option 60+55 |
| 🏷️ | **Identification** | MAC OUI vendor detection + random MAC detection |
| ⚡ | **Speed Monitor** | `/proc/net/nf_conntrack` byte diff + EMA smoothing, 5s window |
| 🟢 | **Online Status** | Pure traffic-based: traffic→🟢 / <60s→🟢 / 60-120s→🟡 / >120s→⚫ |
| 🚫 | **Block** | nftables raw PREROUTING + forward dual-hook drop |
| 🎛️ | **Limit** | nft mark + tc HTB + IFB bidirectional rate limiting |
| 🔄 | **Recovery** | Bidirectional restore (DB ↔ nft/tc), survives DB rebuild |
| 💾 | **Persistence** | gorm + SQLite at `/etc/devman/devman.db` |
| 🔒 | **Security** | Shell-injection safe Lua proxy, temp-file API transport |

## 📁 Structure

```
devman/
├── devman/src/               # Go daemon (pure Go, CGO_ENABLED=0)
│   ├── main.go               # Entry + gorm init
│   ├── model.go              # Device / DeviceMAC models
│   ├── core.go               # Discovery / upsert / API / reconcile
│   ├── bpf.go                # BPF socket filter DHCP sniffer
│   ├── speed.go              # Speed calc + EMA smoothing
│   ├── nft.go                # nftables block/limit + bidirectional recovery
│   ├── tc.go                 # TC HTB + IFB lazy init
│   ├── lan.go                # LAN subnet auto-detection
│   ├── http.go               # HTTP route registration
│   ├── vendor.go             # Device type detection by hostname keywords
│   ├── oui.go                # MAC OUI vendor map
│   └── util.go               # hexToByte / min
├── luci-app-devman/           # LuCI card-style frontend
│   ├── luasrc/controller/    # Lua API proxy (injection-safe)
│   ├── htdocs/.../view/      # Single-page card UI
│   └── po/                   # Chinese translations
└── Makefile
```

## 🔄 Data Flow

```
ip neigh (15s) ──→ IP + MAC ──┐
conntrack (15s) ─→ Active IP ─┤
dhcp.leases (30s) → Hostname ─┼──→ upsertDevice ──→ SQLite
BPF (real-time) ──→ Fingerprint┘    │
                                     ├─ MAC match
                                     ├─ Hostname match
                                     └─ IP match
                                     
/proc/net/nf_conntrack (5s) ──→ bps (EMA) ──→ In-memory map

  Online:  🟢 traffic | 🟢 <60s | 🟡 60-120s | ⚫ >120s
  Block:   DB is_blocked ←→ reconcile(5s) ←→ nft raw + forward
  Limit:   DB rate_limit ←→ nftSetLimit ←→ nft mark + tc HTB + IFB
```

## 🚀 Build

```bash
# Go daemon (Go 1.21+)
cd devman/src && CGO_ENABLED=0 go build -ldflags="-s -w" -o devman .

# OpenWrt packages
make package/new/devman/compile V=s
make package/new/luci-app-devman/compile V=s
```

## 📡 API

| Route | Method | Description |
|------|:--:|------|
| `/api/devices` | `GET` | Device list with speed & online status |
| `/api/block` | `POST` | Block/unblock `{device_id, block}` |
| `/api/limit` | `POST` | Limit/rename `{device_id, rate_limit, rate_limit_down, alias}` |

## 📦 Dependencies

| Type | Package | Purpose |
|------|------|------|
| kmod | `kmod-ifb` | IFB virtual NIC, upload limiting |
| kmod | `kmod-sched-core` | HTB qdisc + fw filter |
| kmod | `kmod-sched-act-mirred` | mirred redirect action |
| userspace | `tc-tiny` / `tc-full` | tc CLI |
| userspace | `nftables` (firewall4) | Block + mark |
| Go | `gorm.io/gorm` | ORM |
| Go | `github.com/glebarez/sqlite` | Pure-Go SQLite driver |
| Go | `golang.org/x/net/bpf` | BPF bytecode assembly |

---

<p align="center">
  <sub>MIT License · <a href="https://github.com/r1172464137/luci-app-devman">GitHub</a></sub>
</p>
