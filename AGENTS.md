# WebSSH — 项目上下文

## Goal
构建一个轻量级 JumpServer 风格的 Web SSH 终端，支持服务器列表、终端面板、可折叠 SFTP 文件浏览器（跟随终端 CWD）、用户认证、内联文件编辑及安全加固。

## Constraints & Preferences
- Go 后端，xterm.js 前端，单二进制内嵌所有静态资源
- 深色主题 UI（GitHub Dark 风格，Catppuccin Mocha 可切换）
- 多服务器连接通过 session ID 管理，切换不断开；支持同一服务器开多个终端
- 服务器列表持久化到 SQLite（非 localStorage）；密码/私钥 AES-GCM 加密存储
- CWD 跟踪必须无感（终端不可见转义输出）
- 认证后方可访问页面；用户 bcrypt 哈希存 SQLite
- 支持内网/离线部署（无 CDN 依赖）
- 访问路径和登录密码均自动随机生成；自动密码仅在首次运行（无用户时）生成
- 敏感字段（password/privateKey）API 传输时使用每会话 AES-256-GCM 加密
- CSRF 保护所有写 API（POST/PUT/DELETE）
- 静态资源运行时压缩（HTML + JS）

## Progress
### Done
- `main.go`: Wails 应用入口，flag 解析，wails.Run() 启动原生窗口；嵌入 `frontend/` 目录
- `app.go`: App struct 包含所有 Wails 绑定方法：
  - 服务器 CRUD（ListServers/CreateServer/UpdateServer/DeleteServer/BatchImport）
  - 终端管理（Connect/TerminalInput/TerminalResize/CloseSession/ListSessions）
  - SFTP 操作（SFTPList/SFTPDownload/SFTPUpload/SFTPRemove/SFTPRename/SFTPMkdir/SFTPRead/SFTPWrite）
  - 通过 runtime.EventsEmit 发送 terminal:output/terminal:closed 事件
  - 通过 Manager 创建会话以供 SFTP 复用；cleanupSession 自动清理
- `wails.json`: Wails 项目配置，无前端构建步骤
- `build/darwin/Info.plist`: macOS 应用配置（深色模式、无 Dock 图标）
- `frontend/index.html`: 单文件前端（从 static/index.html 适配）：
  - 去掉登录页面、退出按钮、修改密码功能
  - 去掉 `__BASE_PATH__`、encField、CSRF 等 HTTP 相关代码
  - `window.go.main.App.*()` 替代 `fetch()` API 调用
  - `window.runtime.EventsOn("terminal:output")` 替代 WebSocket
  - 文件上传/下载通过 Go 方法直接传递二进制数据
  - 去掉 keepalive 定时器（WS 不再需要）
- `frontend/lib/`: xterm.js + CodeMirror（从 static/ 复制）
- `frontend/wailsjs/`: Wails 自动生成的 JS 绑定
- `internal/sshterm/handler.go`: 重构 — 移除 WebSocket handler，导出 DialSSH
- `internal/sshterm/session.go`: Session 增加 Stdin/SSHSession 字段
- `internal/sshterm/sftp.go`: 精简 — 移除 HTTP handler，保留核心类型和辅助函数
- `internal/store/handler.go`: 删除（不再需要 HTTP handler）
- `internal/auth/auth.go`: 删除（不再需要 HTTP 认证）
- `Makefile`: 更新为 Wails 构建目标（build/run/package/vet/clean）
- `.gitignore`: 增加 WebSSH.app 和 build/bin/ 排除

### In Progress
- (无)

### Blocked
- (无)

## Key Decisions
- 使用 Wails v2 构建原生 macOS 桌面应用，无需 HTTP 服务器
- 前后端通过 Wails 绑定直接通信，无需 fetch/WebSocket/CSRF/传输加密
- SSH 终端输出通过 `runtime.EventsEmit("terminal:output")` 推送 base64 数据
- SSH 终端输入通过 `TerminalInput(sessionID, data)` 方法调用
- 文件上传下载通过 `[]byte` 参数直接传递（Wails JSON 序列化处理）
- 去掉登录页面 — 桌面应用信任当前用户
- 数据存储仍使用 SQLite + AES-GCM 加密（store 包保持不变）
- macOS 构建需额外 `CGO_LDFLAGS="-framework UniformTypeIdentifiers"` 解决 Wails v2.9.2 在 Go 1.26 的链接问题

## Build
- `make build`: 编译二进制
- `make run`: 编译并运行
- `make package`: 编译并打包为 WebSSH.app
- `make vet`: 代码检查
- `make clean`: 清理构建产物

### Blocked
- (无)

## Key Decisions
- 使用 `github.com/gorilla/websocket`、`github.com/gorilla/mux`、`github.com/pkg/sftp`
- 使用 `modernc.org/sqlite`（纯 Go，无 CGO）
- 使用 `github.com/tdewolff/minify` 运行时压缩
- 存储加密密钥独立于登录密码：随机 AES-256-GCM 密钥存 `config` 表，改登录密码不影响已存服务器密码
- CSRF token = session token 前 16 字符
- 自动生成密码仅首次创建用户时生成；后续启动检测到已有用户则直接使用
- Three-stage SFTP fallback: subsystem → exec sftp-server → 新 SSH 连接
- `hostKeyCallback` 使用 TOFU（内存 sync.Map）
- 标签以逗号分隔存 `tags` 字段；ALTER TABLE 迁移兼容旧库
- sessions 以 session UUID 为 key（非 serverId），每个 session 持有 serverId 引用，支持同服务器多终端
- 上传使用 `MaxBytesReader` 限制 body 大小，`io.Copy` 错误不再忽略，失败自动 `sc.Remove` 清理残缺文件
- 前端通过 `/api/key` 获取 `maxBodyMB`，上传前拦截超限文件

## Next Steps
- **feat/wails-gui 分支**: 使用 Wails 构建原生 GUI 工具
  - 复用现有前端（xterm.js、CodeMirror、SFTP 文件浏览器等）和后端（SSH、SFTP、加密等）代码
  - 去掉登录页面（原生应用无需 HTTP 认证）
  - 利用 Wails 的 Go + 前端绑定能力，将现有 web 架构适配为桌面应用

## Relevant Files
- `main.go`: 入口、路由、压缩、CSRF
- `internal/sshterm/handler.go`: WebSocket ↔ SSH、dialSSH
- `internal/sshterm/session.go`: SessionManager、SFTP 重连、preambleReader、TOFU
- `internal/sshterm/sftp.go`: SFTP handlers、sanitizePath、上传限流
- `internal/auth/auth.go`: 认证、加密、CSRF、速率限制、KeyHandler（含 maxBodyMB）
- `internal/store/store.go`: SQLite 操作、加解密、服务器 CRUD、标签
- `internal/store/handler.go`: 服务器 CRUD HTTP handlers
- `static/index.html`: 完整前端（多会话标签栏、服务器列表新建终端、标签搜索/过滤、标签输入/展示、内嵌 SVG 图标、彩色方块文件类型、选中复制、上传前大小检查）
- `static/lib/`: 前端依赖（xterm.js + codemirror）

## Key Bug Fixes
- `connectToServer` 中缺少 `const empty = document.getElementById('empty-state')` 导致 ReferenceError
- `HandleFSUpload` 中 `io.Copy` 错误被忽略，导致上传失败时返回 `{Success: true}`
- 上传无 body 大小限制，`-maxbody` 仅作用于内联编辑器
- 前端上传队列在多批上传时 `totalBytes`/`sentBytes` 不重置导致进度计算错乱
