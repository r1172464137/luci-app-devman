<p align="center">
  <strong>简体中文</strong>
  &nbsp;·&nbsp;
  <strong><a href="./README.en.md">English</a></strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/OpenWrt-LuCI-00B5E2?style=flat-square&logo=openwrt&logoColor=white" alt="OpenWrt"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/database-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite"/>
  <img src="https://img.shields.io/badge/CGO-0-blue?style=flat-square" alt="CGO"/>
</p>

<h1 align="center">luci-app-devman</h1>
<h3 align="center">OpenWrt 设备管理器 · Device Manager</h3>

<p align="center">
  OpenWrt 路由器的实时设备监控、封禁与限速面板。
  <br/>
  <em>卡片式 LuCI 前端 · 纯 Go 守护进程 · 零 Shell 脚本</em>
</p>

---

## ✨ 功能特性

| | | |
|:--|------|------|
| 🔍 | **自动发现** | `ip neigh` + conntrack + dnsmasq lease，零主动探测 |
| 📡 | **DHCP 指纹** | BPF socket filter 实时捕获 DHCP Option 60+55 |
| 🏷️ | **设备识别** | MAC OUI 厂商识别 + 随机 MAC 检测 |
| ⚡ | **速度监控** | `/proc/net/nf_conntrack` 字节差分 + EMA 平滑，5 秒更新 |
| 🟢 | **在线判断** | 纯流量检测：有流量→🟢 / 60s内有流量→🟢 / 60-120s无流量→🟡 / >120s无流量→⚫ |
| 🚫 | **封禁** | nftables raw PREROUTING + forward，仅阻断 WAN，保留 LAN 通信 |
| 🎛️ | **限速** | nft mark + tc HTB + IFB 双方向精确限速 |
| 🔄 | **规则恢复** | 启动双向恢复（DB ↔ nft/tc），DB 重建不丢规则 |
| 💾 | **持久化** | gorm + SQLite `/etc/devman/devman.db` |
| 🔒 | **安全** | Lua 前后端防注入，API 临时文件传参 |

## 📁 项目结构

```
devman/
├── devman/src/               # Go 守护进程（纯 Go，CGO_ENABLED=0）
│   ├── main.go               # 入口 + gorm 初始化
│   ├── model.go              # Device / DeviceMAC 模型
│   ├── core.go               # 设备发现 / 去重 / API / reconcile
│   ├── bpf.go                # BPF socket filter DHCP 嗅探
│   ├── speed.go              # 速度计算 + EMA 平滑
│   ├── nft.go                # nftables 封禁/限速 + 双向恢复
│   ├── tc.go                 # TC HTB + IFB 初始化
│   ├── lan.go                # LAN 子网自动检测
│   ├── http.go               # HTTP 路由注册
│   ├── vendor.go             # hostname/MAC 关键词设备类型识别
│   ├── oui.go                # MAC OUI 厂商映射
│   └── util.go               # hexToByte / min
├── luci-app-devman/           # LuCI 卡片式前端
│   ├── luasrc/controller/    # Lua API 代理（防注入）
│   ├── htdocs/.../view/      # 卡片式单页 UI
│   └── po/                   # 中文翻译
└── Makefile
```

## 🔄 数据流

```
ip neigh (15s) ──→ IP + MAC ──┐
conntrack (15s) ─→ 活跃 IP ───┤
dhcp.leases (30s) → hostname ──┼──→ upsertDevice ──→ SQLite
BPF (实时) ──────→ 指纹 ──────┘    │
                                   ├─ MAC 匹配
                                   ├─ hostname 匹配
                                   └─ IP 匹配

/proc/net/nf_conntrack (5s) ──→ bps (EMA) ──→ 内存 map

  在线:  🟢 有流量 | 🟢 <60s | 🟡 60-120s | ⚫ >120s
  封禁:  DB is_blocked ←→ reconcile(5s) ←→ nft raw + forward
  限速:  DB rate_limit ←→ nftSetLimit ←→ nft mark + tc HTB + IFB
```

## 🚀 编译

```bash
# Go 守护进程（需 Go 1.21+）
cd devman/src && CGO_ENABLED=0 go build -ldflags="-s -w" -o devman .

# OpenWrt 软件包
make package/new/devman/compile V=s
make package/new/luci-app-devman/compile V=s
```

## 📡 API 接口

| 路由 | 方法 | 说明 |
|------|:--:|------|
| `/api/devices` | `GET` | 设备列表（含速度和在线状态） |
| `/api/block` | `POST` | 封禁/解封 `{device_id, block}` |
| `/api/limit` | `POST` | 限速/重命名 `{device_id, rate_limit, rate_limit_down, alias}` |

## 📦 依赖

| 类型 | 包名 | 用途 |
|------|------|------|
| 内核模块 | `kmod-ifb` | IFB 虚拟网卡，上传限速 |
| 内核模块 | `kmod-sched-core` | HTB 队列 + fw 过滤器 |
| 内核模块 | `kmod-sched-act-mirred` | mirred 流量重定向 |
| 用户空间 | `tc-tiny` / `tc-full` | tc 命令行 |
| 用户空间 | `nftables` (firewall4) | 封禁 + mark |
| Go 库 | `gorm.io/gorm` | ORM |
| Go 库 | `github.com/glebarez/sqlite` | 纯 Go SQLite 驱动 |
| Go 库 | `golang.org/x/net/bpf` | BPF 字节码编译 |

---

<p align="center">
  <sub>MIT License · <a href="https://github.com/r1172464137/luci-app-devman">GitHub</a></sub>
</p>
