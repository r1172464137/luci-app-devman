# devman 重构实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development

**目标：** 将 devman 手写代码替换为成熟 Go 库 + Vue 3 前端，按职责拆分大文件

**技术栈：** go-chi/chi, google/nftables, florianl/go-conntrack, Vue 3

---

### 任务 1：添加新依赖并测试编译

**文件：**
- 修改：`devman/src/go.mod`

- [ ] 在 go.mod 中添加 chi/nftables/conntrack 依赖

### 任务 2：nftables 改用 google/nftables 库

**文件：**
- 修改：`devman/src/nft.go`

- [ ] 用 google/nftables 替换所有 exec.Command("nft", ...) 调用
- [ ] 保留相同的 nftables 规则集 (blocked_ip, lan_subnet, ul_mark, dl_mark)

### 任务 3：conntrack 改用 florianl/go-conntrack

**文件：**
- 修改：`devman/src/speed.go`

- [ ] 用 go-conntrack netlink API 替换 /proc/net/nf_conntrack 文本解析
- [ ] 保留相同的 speed 计算逻辑（差分、bps 转换）

### 任务 4：OUI 从硬编码改为 JSON 文件

**文件：**
- 创建：`devman/files/oui.json`
- 修改：`devman/src/oui.go`
- 修改：`devman/Makefile`

- [ ] 导出当前 ouiVendorMap 为 JSON 文件
- [ ] oui.go 启动时读取 oui.json
- [ ] Makefile 安装 oui.json

### 任务 5：HTTP 改用 chi router + 拆分 handlers

**文件：**
- 修改：`devman/src/http.go`
- 创建：`devman/src/handler/api.go`
- 修改：`devman/src/core.go`（移除 HTTP handler 部分）
- 删除：`devman/src/http.go`

- [ ] 用 chi/v5 替换 http.ServeMux
- [ ] 从 core.go 抽出 apiDevices/apiBlock/apiLimit 到 handler/api.go

### 任务 6：拆分发现逻辑

**文件：**
- 创建：`devman/src/discover/arp.go`
- 创建：`devman/src/discover/conntrack.go`
- 创建：`devman/src/discover/lease.go`
- 创建：`devman/src/discover/dns.go`
- 修改：`devman/src/main.go`（更新 import 路径）

### 任务 7：分离合并逻辑

**文件：**
- 创建：`devman/src/merge.go`
- 修改：`devman/src/core.go`

- [ ] mergeDuplicateHostnames, mergeByOpt55Hash, absorbNoFingerprint → merge.go

### 任务 8：LuCI 前端改用 Vue 3

**文件：**
- 创建：`luci-app-devman/htdocs/luci-static/resources/view/devman/app.js`
- 创建：`luci-app-devman/htdocs/luci-static/resources/view/devman/style.css`
- 创建：`luci-app-devman/htdocs/luci-static/resources/view/devman/vue.global.prod.js`
- 修改：`root/usr/share/luci/view/devman/overview.htm`
- 修改：`luci-app-devman/Makefile`

### 任务 9：编译测试 + APK 打包

- [ ] go build 验证编译通过
- [ ] push 到 GitHub
