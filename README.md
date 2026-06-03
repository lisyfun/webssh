# WebSSH

基于 Go + xterm.js + Wails 的原生 macOS SSH 客户端，单二进制部署，无需外部依赖。

## 功能

- SSH 终端 — 原生桌面窗口，多标签 SSH 连接
- 多会话管理 — 多个服务器同时连接，切换不断开；同一服务器可开多个终端
- 文件管理 — 内嵌 SFTP 文件浏览器，跟随终端 CWD 自动切换目录
- 上传下载 — 拖拽上传（带进度、队列）、文件下载、内联编辑
- 服务器列表 — SQLite 持久化，密码/私钥 AES-GCM 加密存储
- 标签分类 — 每个服务器可添加标签，按标签筛选
- 批量导入 — 粘贴 tabular 数据批量添加服务器
- 暗色主题 — GitHub Dark 风格

## 快速开始

```bash
# 编译并启动
make run

# 或直接运行
./webssh

# 可选数据库路径
./webssh -db /path/to/webssh.db
```

## 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-db` | `webssh.db` | SQLite 数据库文件路径 |
| `-maxbody` | `50` | 编辑器/上传最大 body (MB)，0=不限制 |

## 从源码构建

### 前置条件

- Go 1.26+
- [Wails v2](https://wails.io/) CLI（可选，用于 `wails generate module`）
- macOS（当前仅支持 macOS 构建）

```bash
git clone <repo>
cd webssh
make build
```

### macOS .app 打包

```bash
make package
# 产物在 WebSSH.app
```

## 技术栈

- **后端**: Go, Wails v2, golang.org/x/crypto/ssh, pkg/sftp
- **前端**: xterm.js, CodeMirror 5（本地嵌入，无 CDN 依赖）
- **存储**: SQLite (modernc.org/sqlite，纯 Go，无 CGO)
- **嵌入**: go:embed，所有前端资源打进二进制
