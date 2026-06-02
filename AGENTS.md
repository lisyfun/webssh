# WebSSH — 项目上下文

## Goal
构建一个轻量级 JumpServer 风格的 Web SSH 终端，支持服务器列表、终端面板、可折叠 SFTP 文件浏览器（跟随终端 CWD）、用户认证、内联文件编辑及安全加固。

## Constraints & Preferences
- Go 后端，xterm.js 前端，单二进制内嵌所有静态资源
- 深色主题 UI
- 多服务器连接通过 session ID 管理，切换不断开
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
- `main.go`: HTTP 入口，路由注册（WS、静态资源、SFTP API、登录/登出、密码修改、内联编辑器 `/read`/`/write`）；flags: `-addr`, `-user`, `-pass`, `-cert`/`-key`, `-url`, `-maxbody`, `-db`；store 初始化、用户确保、运行时压缩、CSRF 中间件
- `internal/sshterm/handler.go`: WebSocket SSH 中继（双向二进制、resize JSON）；PROMPT_COMMAND OSC 7 注入；接受 `DecryptFunc` 解密连接参数；`dialSSH` 同时支持密码和私钥认证
- `internal/sshterm/session.go`: `SessionManager`，`DialSFTP()` 三级回退，`preambleReader`，`hostKeyCallback` TOFU
- `internal/sshterm/sftp.go`: SFTP REST handlers（list/download/upload/remove/rename/mkdir/read/write）；**`sanitizePath()` 拒绝所有 `..` 遍历**
- `internal/auth/auth.go`: 用户认证、bcrypt 密码校验、每会话 AES-256-GCM 密钥、`KeyHandler` 返回 `{key, csrf}`、`CSRFValidate` 中间件、`DecryptField`/`DecryptWithKey`、速率限制（5 次/15 分钟封禁）、token 过期（24h）、密码修改
- `internal/store/store.go`: SQLite 操作 — `config` 表（AES-256-GCM 主密钥）、`servers` 表（password/privateKey AES-GCM 加密）、`users` 表（bcrypt 哈希）；方法包括 `EnsureUser`、`VerifyPassword`、`ChangePassword`、`UserExists`、`updatePassword`；服务器 CRUD 加解密
- `internal/store/handler.go`: 服务器 CRUD HTTP handlers，接受 `DecryptFunc` 参数
- `static/index.html`: 三栏布局、多会话终端、文件浏览器（拖拽上传、进度条、队列）、OSC 7 CWD、自定义确认/重命名模态框、Toast 通知、批量导入、密码修改、CodeMirror 内联编辑器；`encField()` Web Crypto API AES-GCM 加密；`apiHeaders()` 统一添加 `X-CSRF-Token`；文件下载用 `<a download>`；重命名用自定义模态框替代 `prompt()`
- `static/lib/`: xterm.min.js / xterm.min.css / xterm-addon-fit.min.js / codemirror.min.js / codemirror.min.css（本地嵌入无 CDN）
- `static/favicon.png`: 应用图标

### In Progress
- (无)

### Blocked
- (无)

## Key Decisions
- 使用 `github.com/gorilla/websocket`、`github.com/gorilla/mux`、`github.com/pkg/sftp`
- 使用 `modernc.org/sqlite`（纯 Go，无 CGO）
- 使用 `github.com/tdewolff/minify` 运行时压缩
- 存储加密密钥独立于登录密码：随机 AES-256-GCM 密钥存 `config` 表，改登录密码不影响已存服务器密码
- CSRF token = session token 前 16 字符
- 自动生成密码仅首次创建用户时生成；后续启动检测到已有用户则直接使用

## Next Steps
- 批量导入支持密钥认证
- 支持加密私钥（passphrase）
- 服务器列表搜索/过滤
- 服务器分组/标签

## Relevant Files
- `main.go`: 入口、路由、压缩、CSRF
- `internal/sshterm/handler.go`: WebSocket ↔ SSH、dialSSH
- `internal/sshterm/session.go`: SessionManager、SFTP 重连
- `internal/sshterm/sftp.go`: SFTP handlers、sanitizePath
- `internal/auth/auth.go`: 认证、加密、CSRF
- `internal/store/store.go`: SQLite 操作、加解密
- `internal/store/handler.go`: 服务器 CRUD HTTP handlers
- `static/index.html`: 完整前端
- `static/lib/`: 前端依赖（xterm.js + codemirror）
