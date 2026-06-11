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
- 2FA 启动时自动重置 TOTP secret，每次重启后需重新扫码绑定（无前端管理按钮）

## Progress
### Done
- `main.go`: HTTP 入口，路由注册（WS、静态资源、SFTP API、登录/登出、密码修改、内联编辑器 `/read`/`/write`）；flags: `-addr`, `-user`, `-pass`, `-cert`/`-key`, `-url`, `-maxbody`, `-db`；store 初始化、用户确保、运行时压缩、CSRF 中间件
- `internal/sshterm/handler.go`: WebSocket SSH 中继（双向二进制、resize JSON）；多 shell OSC 7 CWD 注入（bash/zsh/fish 探测 `$SHELL` 后下发对应语法的 hook）；接受 `DecryptFunc` 解密连接参数；`dialSSH` 支持密码（password + keyboard-interactive）和私钥认证，放宽 Cipher/KEX/HostKey 算法兼容老设备
- `internal/sshterm/session.go`: `SessionManager`，`DialSFTP()` 三级回退，`preambleReader`，`hostKeyCallback` TOFU
- `internal/sshterm/sftp.go`: SFTP REST handlers（list/download/upload/remove/rename/mkdir/read/write）；**`sanitizePath()` 拒绝所有 `..` 遍历**；`HandleFSUpload` 添加 `MaxBytesReader` 限制 + `io.Copy` error 检查 + 失败自动清理远端残缺文件；`HandleFSDownload` 设置 `Content-Length` 头支持前端进度条；`HandleFSUpload` 支持 `X-Upload-Offset`/`X-Upload-Name` 头部实现分块上传续写
- `internal/auth/auth.go`: 用户认证、bcrypt 密码校验、每会话 AES-256-GCM 密钥、`KeyHandler` 返回 `{key, csrf, maxBodyMB}`、`CSRFValidate` 中间件、`DecryptField`/`DecryptWithKey`、速率限制（5 次/15 分钟封禁）、token 过期（24h）、密码修改
- `internal/store/store.go`: SQLite 操作 — `config` 表（AES-256-GCM 主密钥）、`servers` 表（password/privateKey AES-GCM 加密、`tags` 字段）、`users` 表（bcrypt 哈希）；方法包括 `EnsureUser`、`VerifyPassword`、`ChangePassword`、`UserExists`、`updatePassword`；服务器 CRUD 加解密；`EnsureUser` 已存在时调用 `updatePassword` 修复 `-pass` 覆盖
- `internal/store/handler.go`: 服务器 CRUD HTTP handlers，接受 `DecryptFunc` 参数
- `static/index.html`: 三栏布局、多会话终端、文件浏览器（拖拽上传、进度条、队列）、OSC 7 CWD、自定义确认/重命名模态框、Toast 通知、批量导入、密码修改、CodeMirror 内联编辑器、服务器搜索/过滤输入框、标签输入与展示、服务器列表 "+" 按钮新建终端、标签栏多会话切换/关闭；`encField()` Web Crypto API AES-GCM 加密；`apiHeaders()` 统一添加 `X-CSRF-Token`；文件下载用 XHR + 进度条替代 `<a download>`；重命名用自定义模态框替代 `prompt()`；修复重复 `api()` 函数导致 CSRF 头丢失；所有图标使用内嵌 SVG（Feather 风格），文件类型用彩色方块替代 emoji；终端 Consolas 字体、GitHub Dark 配色、深绿 `#1f7a2e` 改善 777 目录可读性；选中即复制（`onSelectionChange` → `clipboard.writeText`）；上传前检查 `maxUploadMB`，超限跳过并 toast 提示；大文件 >512KB 自动分块上传（`FileReader.readAsArrayBuffer` + `X-Upload-Offset`）
- `static/lib/`: xterm.min.js / xterm.min.css / xterm-addon-fit.min.js / codemirror.min.js / codemirror.min.css（本地嵌入无 CDN）
- `static/favicon.png`: 应用图标
- `.gitignore`: 排除 `/webssh`、`/release/`、`*.db*`
- `AGENTS.md`: 项目上下文

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
- Three-stage SFTP fallback: subsystem → exec sftp-server → 新 SSH 连接
- `hostKeyCallback` 使用 TOFU（内存 sync.Map）
- `dialSSH` 认证与算法兼容性（修复「命令行能连、webssh 连不上」）：
  - 密码认证同时提供 `password` + `keyboard-interactive`（用同一密码自动应答），覆盖只开 PAM/KbdInteractive 的服务器
  - 密码+私钥都填时先试私钥再试密码（OpenSSH 顺序）
  - 显式放宽 Cipher（加 `aes128-cbc`/`3des-cbc`）、KEX（加 `group14-sha1`/`group1-sha1`/`group-exchange-sha1`）、HostKey（加 `ssh-rsa`），兼容老交换机/嵌入式设备；弱算法排在列表末尾，仅在现代算法不可用时协商，不降级现代服务器
  - 加密私钥（带 passphrase）返回明确中文提示，暂不支持
- CWD 跟踪用多 shell OSC 7 注入（修复原 bash-only 方案在 zsh 失效、fish 报错）：
  - 连接后 `echo $SHELL` 探测登录 shell，按类型下发对应 hook —— bash/sh/ksh 用 `export PROMPT_COMMAND`、zsh 用 `precmd_functions`、fish 用 `--on-event fish_prompt` 函数
  - OSC 7 只输出 `file://$PWD`（去掉 `$HOSTNAME`，前端解析本就忽略 host）
  - 探测失败回落 bash 形式（与旧行为一致，无回归）
- 标签以逗号分隔存 `tags` 字段；ALTER TABLE 迁移兼容旧库
- sessions 以 session UUID 为 key（非 serverId），每个 session 持有 serverId 引用，支持同服务器多终端
- 上传使用 `MaxBytesReader` 限制 body 大小，`io.Copy` 错误不再忽略，失败自动 `sc.Remove` 清理残缺文件
- 前端通过 `/api/key` 获取 `maxBodyMB`，上传前拦截超限文件
- 分块上传：>512KB 文件自动分块，每块用 `X-Upload-Offset` 头部标记偏移，Go 端用 `sc.OpenFile(..., O_APPEND)` 追加写入；分块失败自动重试 3 次
- 下载进度：前端用 XHR `onprogress` 显示进度条，Go 端设置 `Content-Length` 头使 response 可精确计算进度

## Next Steps
- (待定)

## Relevant Files
- `main.go`: 入口、路由、压缩、CSRF
- `internal/sshterm/handler.go`: WebSocket ↔ SSH、dialSSH
- `internal/sshterm/session.go`: SessionManager、SFTP 重连、preambleReader、TOFU
- `internal/sshterm/sftp.go`: SFTP handlers、sanitizePath、上传限流、分块上传续写、Content-Length 下载
- `internal/auth/auth.go`: 认证、加密、CSRF、速率限制、KeyHandler（含 maxBodyMB）
- `internal/store/store.go`: SQLite 操作、加解密、服务器 CRUD、标签
- `internal/store/handler.go`: 服务器 CRUD HTTP handlers
- `static/index.html`: 完整前端（多会话标签栏、服务器列表新建终端、标签搜索/过滤、标签输入/展示、内嵌 SVG 图标、彩色方块文件类型、选中复制、上传前大小检查、大文件分块上传、XHR 下载进度条）
- `static/lib/`: 前端依赖（xterm.js + codemirror）

## Key Bug Fixes
- `connectToServer` 中缺少 `const empty = document.getElementById('empty-state')` 导致 ReferenceError
- `HandleFSUpload` 中 `io.Copy` 错误被忽略，导致上传失败时返回 `{Success: true}`
- 上传无 body 大小限制，`-maxbody` 仅作用于内联编辑器
- 前端上传队列在多批上传时 `totalBytes`/`sentBytes` 不重置导致进度计算错乱
- `main.go` 重复 `EnsureUser` 调用，未传 `-pass` 时用空密码 bcrypt 覆盖数据库
- TOTP 验证页面显示用户名/密码文字，不应暴露已认证凭据
- 重启后 TOTP 验证码失效：启动时自动清除 `totp_secret`
- `fa-overlay` 与 `font-popup` 同为 `z-index:1000`，安全弹窗盖在字体设置上方
