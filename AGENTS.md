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
- `main.go`: Wails v3 应用入口，flag 解析，`application.New` + `Window.NewWithOptions` + `app.Run()`；`fs.Sub` 后嵌入 `frontend/` 目录
- `app.go`: App struct 包含所有 Wails 绑定方法：
  - 服务器 CRUD（ListServers/CreateServer/UpdateServer/DeleteServer/BatchImport）
  - 终端管理（Connect/TerminalInput/TerminalResize/CloseSession/ListSessions）
  - SFTP 操作（SFTPList/SFTPDownload/SFTPUpload/SFTPRemove/SFTPRename/SFTPMkdir/SFTPRead/SFTPWrite）
  - 通过 `app.Event.Emit` 发送 terminal:output/terminal:closed/download:* 事件
  - 通过 Manager 创建会话以供 SFTP 复用；cleanupSession 自动清理
  - 实现 `ServiceStartup` / `ServiceShutdown` 服务生命周期（替代 v2 的 OnStartup/OnShutdown）
- `build/darwin/Info.plist`: macOS 应用配置（深色模式、无 Dock 图标）
- `frontend/index.html`: 单文件前端（从 static/index.html 适配）：
  - 去掉登录页面、退出按钮、修改密码功能
  - 去掉 `__BASE_PATH__`、encField、CSRF 等 HTTP 相关代码
  - `App()` 代理到 `Call.ByName("main.App.<Method>")`，替代 `fetch()` / v2 生成绑定
  - `wails.Events.On("terminal:output")` 接收 `ev.data`，替代 v2 多参数回调
  - 文件上传/下载通过 Go 方法直接传递二进制数据
  - 去掉 keepalive 定时器（WS 不再需要）
- `frontend/lib/`: xterm.js + CodeMirror（从 static/ 复制）
- 动态 `import('/wails/runtime.js')` 加载 v3 ESM 运行时（asset server 内置），不再需要 `frontend/wailsjs/`
- `internal/sshterm/handler.go`: 重构 — 移除 WebSocket handler，导出 DialSSH
- `internal/sshterm/session.go`: Session 增加 Stdin/SSHSession 字段
- `internal/sshterm/sftp.go`: 精简 — 移除 HTTP handler，保留核心类型和辅助函数
- `internal/store/handler.go`: 删除（不再需要 HTTP handler）
- `internal/auth/auth.go`: 删除（不再需要 HTTP 认证）
- `Makefile`: 更新为 Wails 构建目标（build/run/package/vet/clean）
- `.gitignore`: 增加 WebSSH.app 和 build/bin/ 排除

### Done (Wails v3 迁移)
- 依赖从 `wails/v2 v2.12.0` 升级到 `wails/v3 v3.0.0`（CLI 不再参与构建）
- `main.go`: `application.New` + `app.Window.NewWithOptions` + `app.Run()`；资源用 `fs.Sub(assets, "frontend")` 交给 `application.AssetFileServerFS`
- 单实例改为 `application.SingleInstanceOptions`（删除 Linux 专用 pid 锁 + xdotool 激活）
- `app.go`: `OnStartup/OnShutdown` → `ServiceStartup(ctx, options)/ServiceShutdown()`；`runtime.EventsEmit(ctx,...)` → `app.Event.Emit`；`runtime.SaveFileDialog` → `app.Dialog.SaveFile().SetOptions(...).PromptForSingleSelection()`
- 事件载荷统一：`download:progress` 改为 `{fileName, written, total}` 单对象（v3 前端回调签名为 `(ev) => ev.data`）
- `frontend/index.html`: 删除 `frontend/wailsjs/`，改用动态 `import('/wails/runtime.js')`；`App()` 为 Proxy → `Call.ByName("main.App.<Method>")`
- `Makefile`: 直接 `go build -tags production`（macOS `CGO_ENABLED=1` + UniformTypeIdentifiers；Linux `production gtk3`）；新增 `make test`
- 删除 `wails.json`
- 已知限制：统信 UOS V20 的 webkit2gtk-4.0 不被 v3 支持，需 4.1 后重新验证 .deb 流程
- macOS 外观（Ghostty 风格）：`Mac.TitleBar = MacTitleBarHidden` 隐藏系统标题栏；前端单行 `.topbar`（42px，`--wails-draggable: drag`，macOS 下左侧 80px 给交通灯）同时承载品牌区/会话标签/操作按钮，无独立标题栏
- macOS 交通灯默认中心约 16pt，42pt 顶栏中偏高；`trafficlights_darwin.go`（cgo/AppKit）在启动后把按钮容器下移 5pt 居中（Wails 无公开 API），其他平台为 no-op
- 顶栏标签为圆角胶囊（选中 `--surface-active`，未选中透明），refresh 仅 hover/active 显示；次要信息（host、状态）用 `ui-monospace`
- 派生表面色用 `color-mix()` 从主题变量计算（`--border-subtle` / `--surface-hover` / `--surface-active`），亮暗主题自动适配
- 配色/字体对齐 Ghostty：默认主题 `abernathy`（Ghostty 内置主题，背景 #111416，完整 ANSI palette），默认终端字体 `CaskaydiaCove Nerd Font`、13px、行高 1.5、underline 光标
- 顶栏、侧边栏、终端区统一使用 `--bg-primary`，侧边栏只用一条 `--border-color` 竖线分隔；文件面板同理
- `localStorage['webssh-style-v2']` 作为一次性迁移标记：把旧默认（github-dark / Consolas / 1.3 行高）换成新默认，用户显式选择的其他主题不受影响
- `Info.plist` 增加 `CFBundleDisplayName`；`make icns` 从 `frontend/appicon.png` 生成多尺寸 `.icns`，菜单栏与 Dock 显示 WebSSH 图标/名称
- 终端设置弹窗支持：字体/字号/行高/字距/字重、光标样式与闪烁、回滚行数、最小对比度、选中即复制、粗体亮色、窗口透明度、默认窗口宽高、主题
- 磨砂效果：`SetWindowAppearance` 绑定 → `window_darwin.go` 用 `NSVisualEffectView`（HUDWindow / behindWindow）垫在透明 `WKWebView`（`drawsBackground=NO`，@try/@catch 保护）之下；关闭时移除材质并退回 `NSWindow.alphaValue`
- 磨砂模式下透明度滑块控制 `--window-tint`（主题色 rgba）而非材质强度，保证文字对比；`localStorage['webssh-vibrancy-v1']` 一次性迁移把旧默认 1.0 改为 0.72
- 终端画布同样透明：vibrancy 开启时 xterm 主题 background 设为 `rgba(0,0,0,0)`，并覆盖 `.xterm-viewport/.xterm-screen` 背景；切换磨砂/主题时调用 `refreshTermThemes()`
- 默认窗口宽高保存后立即 `Window.SetSize`，下次启动由 `applySavedWindowPrefs()` 恢复（仅当用户显式保存过）
- `Cmd+,` 打开终端设置
- 图标源：`frontend/appicon.png`（深色 squircle + 白色 `>` + 蓝色光标 + 绿色锁），由 `tools/makeicon.py`（Pillow）生成；同脚本生成 256px 的 `frontend/favicon.png`

### In Progress
- (无)

### Done (UOS / Linux)
- `options_linux.go`: Linux 专用选项存根（build tag: linux），与 darwin/windows 解耦
- `build/linux/WebSSH.desktop`: 统信OS/Deepin 桌面快捷方式（中文名 + UOS 分类）
- `build/debian/`: 完整的 .deb 打包目录：
  - `DEBIAN/control`: 包元数据（依赖 libgtk-3, libwebkit2gtk-4.0 → 后精简为仅 libc6）
  - `DEBIAN/postinst`: 安装后刷新桌面数据库、图标缓存、Deepin 启动器
  - `DEBIAN/prerm`: 卸载前脚本
  - `usr/share/icons/hicolor/`: 应用图标（48x48 / 256x256 / scalable）
  - `usr/share/applications/WebSSH.desktop`: 桌面入口
  - `usr/share/doc/webssh/copyright`: 版权信息
- `build/build_uos.sh`: 统信OS 原生构建脚本（编译 + 打包 .deb 一步完成）
- `build/Dockerfile.build`: Docker 交叉编译配置（macOS → Linux amd64 交叉编译）
- `Makefile`: 增加 `build-uos`（统信OS 构建别名）、`deb`（生成 .deb 包）目标
- `webssh-uos-amd64.deb`: 首次构建成功（ARM64/QEMU 超时 → 加 --platform=linux/amd64 重试通过）
  - 二进制 x86-64 ELF，RPATH 设为 `$ORIGIN/../lib/webssh/lib`
  - 247MB 库文件捆绑进 `/usr/lib/webssh/lib/`（GTK3, WebKit, ICU, GStreamer 等）
  - .deb 压缩后 75MB
  - 依赖仅为 `libc6 (>= 2.31)`，离线 UOS 可直接 `dpkg -i` 安装
- `webssh-uos-amd64.deb` v2: 针对 UOS V20（glibc 2.28）降级构建
  - 基础镜像改为 `debian:buster-slim`（archive.debian.org），手动安装 Go 1.26
  - 依赖降为 `libc6 (>= 2.28)`，捆绑库 156MB（Buster 版），.deb 压缩后 48MB

## Key Decisions
- 使用 Wails v3（v3.0.0）构建原生桌面应用，无需外部 HTTP 服务（支持 macOS/Windows/Linux）
- 前后端通过服务绑定直接通信（`Call.ByName`），无需 fetch/CSRF/传输加密
- SSH 终端输出通过 `app.Event.Emit("terminal:output", {sessionId, data})` 推送 base64 数据
- 单实例由 `application.SingleInstanceOptions` 处理（替代 Linux 专用 pid 锁 + xdotool）
- 前端不生成 bindings：用 Proxy 把 `App().X(...)` 映射为 `Call.ByName("main.App.X", ...)`
- SSH 终端输入通过 `TerminalInput(sessionID, data)` 方法调用
- 文件上传下载通过 `[]byte` 参数直接传递（Wails JSON 序列化处理）
- 去掉登录页面 — 桌面应用信任当前用户
- 数据存储仍使用 SQLite + AES-GCM 加密（store 包保持不变）
- 存储加密密钥独立于登录密码：随机 AES-256-GCM 密钥存 `config` 表，改登录密码不影响已存服务器密码
- Three-stage SFTP fallback: subsystem → exec sftp-server → 新 SSH 连接
- `hostKeyCallback` 使用 TOFU（内存 sync.Map）
- 标签以逗号分隔存 `tags` 字段；ALTER TABLE 迁移兼容旧库
- sessions 以 session UUID 为 key（非 serverId），每个 session 持有 serverId 引用，支持同服务器多终端
- 平台选项通过 build tag 隔离：`options_darwin.go` / `options_windows.go` / `options_linux.go` / `options_default.go`
- 构建直接用 `go build -tags production`（macOS CGO + UniformTypeIdentifiers；Linux 用 `gtk3` tag），不再依赖 Wails CLI

## Build
- `make build`: 编译当前平台二进制
- `make run`: 编译并运行
- `make package`: 编译并打包为 WebSSH.app（仅 macOS）
- `make release`: 打包为 DMG 或 tar.gz（仅 macOS）
- `make universal`: 编译 arm64 + amd64 通用二进制（仅 macOS）
- `make build-windows`: 交叉编译 Windows 版（需 `brew install mingw-w64`）
- `make build-linux`: 交叉编译 Linux 版（需 webkit2gtk-4.1 开发库，macOS 上需 Docker）
- `make build-uos`: 统信OS 构建别名（等价于 `make deb`）
- `make deb`: 编译 Linux 二进制 + 构建 .deb 安装包
- `make vet`: 代码检查（CGO_ENABLED=1）
- `make test`: 运行 Go 测试
- `make clean`: 清理构建产物

## Relevant Files
- `main.go`: Wails v3 入口、flag 解析、application.New、单实例、嵌入 `frontend/`
- `options_darwin.go`: macOS 选项（`application.MacOptions` / `MacWindow` 深色外观，build tag: darwin）
- `options_windows.go`: Windows 选项（`application.WindowsWindow` 深色主题 + 自定义标题栏颜色，build tag: windows）
- `options_linux.go`: Linux 选项（`LinuxOptions.ProgramName` + GTK 深色环境，build tag: linux）
- `options_default.go`: 其他平台存根（build tag: !darwin,!windows,!linux）
- `app.go`: App struct + 所有绑定方法（服务器 CRUD、终端、SFTP）
- `internal/sshterm/handler.go`: dialSSH（无 WebSocket）
- `internal/sshterm/session.go`: SessionManager、SFTP 重连、preambleReader、TOFU
- `internal/sshterm/sftp.go`: SFTP 核心类型，导出 SanitizePath/RemoveDir/FormatFileEntry
- `internal/store/store.go`: SQLite + AES-GCM 加密（未改动）
- `frontend/index.html`: 完整 Wails 前端（多标签、文件浏览器、编辑器、v3 事件绑定 + Call.ByName 代理）
- `build/darwin/Info.plist`: macOS bundle 元数据

## Key Bug Fixes
- `connectToServer` 中缺少 `const empty = document.getElementById('empty-state')` 导致 ReferenceError
- `HandleFSUpload` 中 `io.Copy` 错误被忽略，导致上传失败时返回 `{Success: true}`
- 上传无 body 大小限制，`-maxbody` 仅作用于内联编辑器
- 前端上传队列在多批上传时 `totalBytes`/`sentBytes` 不重置导致进度计算错乱
