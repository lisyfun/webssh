# WebSSH — 项目上下文

## Goal
构建一个轻量级 JumpServer 风格的 Web SSH 终端，支持服务器列表、终端面板、可折叠 SFTP 文件浏览器（跟随终端 CWD）、内联文件编辑及安全加固。

## Constraints & Preferences
- Go 后端，xterm.js 前端，单二进制内嵌所有静态资源
- 深色主题 UI（GitHub Dark 风格，Catppuccin Mocha 可切换）
- 多服务器连接通过 session ID 管理，切换不断开；支持同一服务器开多个终端
- 服务器列表持久化到 SQLite（非 localStorage）；密码/私钥 AES-GCM 加密存储
- CWD 跟踪必须无感（终端不可见转义输出）
- 支持内网/离线部署（无 CDN 依赖）
- 敏感字段（password/privateKey）API 传输时使用每会话 AES-256-GCM 加密
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
- `wails build` CLI fails with `internal error: package "fmt" without types` — Go 1.26 incompatibility with Wails v2.9.2; workaround: use `go build -tags "desktop,production"` directly

## Key Decisions
- 使用 Wails v2 构建原生桌面应用，无需 HTTP 服务器（支持 macOS/Windows/Linux）
- 前后端通过 Wails 绑定直接通信，无需 fetch/WebSocket/CSRF/传输加密
- SSH 终端输出通过 `runtime.EventsEmit("terminal:output")` 推送 base64 数据
- SSH 终端输入通过 `TerminalInput(sessionID, data)` 方法调用
- 文件上传下载通过 `[]byte` 参数直接传递（Wails JSON 序列化处理）
- 去掉登录页面 — 桌面应用信任当前用户
- 数据存储仍使用 SQLite + AES-GCM 加密（store 包保持不变）
- 存储加密密钥独立于登录密码：随机 AES-256-GCM 密钥存 `config` 表，改登录密码不影响已存服务器密码
- Three-stage SFTP fallback: subsystem → exec sftp-server → 新 SSH 连接
- `hostKeyCallback` 使用 TOFU（内存 sync.Map）
- 标签以逗号分隔存 `tags` 字段；ALTER TABLE 迁移兼容旧库
- sessions 以 session UUID 为 key（非 serverId），每个 session 持有 serverId 引用，支持同服务器多终端
- macOS 构建需额外 `CGO_LDFLAGS="-framework UniformTypeIdentifiers"` 解决 Wails v2.9.2 在 Go 1.26 的链接问题
- Windows 构建需 `mingw-w64` 交叉编译器，`-ldflags="-H=windowsgui"` 隐藏控制台窗口
- Windows 深色标题栏通过 `windows.Options` 的 `Theme: windows.Dark` + `CustomTheme` 实现
- Windows 应用图标由 `frontend/favicon.png` 生成 `.ico`，经 `go-winres` 嵌入 `.syso` 到二进制
- 平台选项通过 build tag 隔离：`options_darwin.go` / `options_windows.go` / `options_default.go`

## Build
- `make build`: 编译当前平台二进制
- `make run`: 编译并运行
- `make package`: 编译并打包为 WebSSH.app（仅 macOS）
- `make release`: 打包为 DMG 或 tar.gz（仅 macOS）
- `make universal`: 编译 arm64 + amd64 通用二进制（仅 macOS）
- `make build-windows`: 交叉编译 Windows 版（需 `brew install mingw-w64`）
- `make build-linux`: 交叉编译 Linux 版
- `make vet`: 代码检查
- `make clean`: 清理构建产物

## Relevant Files
- `main.go`: Wails 入口、flag 解析、wails.Run()、嵌入 `frontend/`
- `options_darwin.go`: macOS 专用选项（`mac.Options`，build tag: darwin）
- `options_windows.go`: Windows 专用选项（`windows.Options` + 深色标题栏，build tag: windows）
- `options_default.go`: 其他平台存根（build tag: !darwin,!windows）
- `app.go`: App struct + 所有绑定方法（服务器 CRUD、终端、SFTP）
- `internal/sshterm/handler.go`: dialSSH（无 WebSocket）
- `internal/sshterm/session.go`: SessionManager、SFTP 重连、preambleReader、TOFU
- `internal/sshterm/sftp.go`: SFTP 核心类型，导出 SanitizePath/RemoveDir/FormatFileEntry
- `internal/store/store.go`: SQLite + AES-GCM 加密（未改动）
- `frontend/index.html`: 完整 Wails 前端（多标签、文件浏览器、编辑器、Wails 事件绑定）
- `frontend/wailsjs/`: Wails 自动生成的 JS 绑定
- `build/darwin/Info.plist`: macOS bundle 元数据

## Key Bug Fixes
- `connectToServer` 中缺少 `const empty = document.getElementById('empty-state')` 导致 ReferenceError
- `HandleFSUpload` 中 `io.Copy` 错误被忽略，导致上传失败时返回 `{Success: true}`
- 上传无 body 大小限制，`-maxbody` 仅作用于内联编辑器
- 前端上传队列在多批上传时 `totalBytes`/`sentBytes` 不重置导致进度计算错乱
