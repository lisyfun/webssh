# WebSSH

基于 Go + xterm.js 的轻量级 Web SSH 客户端，单二进制部署，无需外部依赖。

## 功能

- **Web 终端** — 浏览器中通过 SSH 连接远程服务器，支持密码/私钥/双因素认证
- **多会话管理** — 多个服务器同时连接，切换不断开；同一服务器可开多个终端
- **文件管理** — 内嵌 SFTP 文件浏览器，跟随终端 CWD 自动切换目录
- **上传下载** — 拖拽上传（带进度、队列、分块续传）、文件下载、内联编辑
- **服务器列表** — SQLite 持久化（非 localStorage），密码/私钥 AES-GCM 加密存储
- **标签分类** — 每个服务器可添加标签，按标签筛选
- **用户认证** — 登录密码 + 随机访问路径 + 可选双因素 TOTP + HTTPS 四层防护
- **语法高亮** — 内联编辑器支持 18 种语言语法高亮（Go/Python/JS/Rust 等）
- **多主题** — 5 套暗色主题：GitHub Dark、Catppuccin Mocha、One Dark、Tokyo Night、Nord
- **批量导入** — 粘贴 tabular 数据批量添加服务器
- **修改密码** — 登录后可在页面修改密码
- **私钥密码短语** — 支持加密私钥连接时输入密码短语
- **在线编辑** — 直接编辑远程文件，支持 .bashrc 等配置文件

## 快速开始

```bash
# 下载后直接启动
./webssh

# 启动日志会输出随机路径和密码
# access path: /a3f8c9d1b2
# generated password: 4f8e2a1c7b
# login user: admin
```

浏览器访问 `http://your-server:8080/a3f8c9d1b2/`，用打印的用户名密码登录。

## 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-addr` | `:8080` | 监听地址 |
| `-user` | `admin` | 登录用户名 |
| `-pass` | _(随机生成)_ | 登录密码，留空自动随机 |
| `-url` | _(随机生成)_ | 访问路径前缀，填则固定 |
| `-cert` | `""` | TLS 证书文件路径 |
| `-key` | `""` | TLS 私钥文件路径 |
| `-maxbody` | `50` | 编辑器/上传最大 body (MB)，0=不限制 |
| `-db` | `webssh.db` | SQLite 数据库文件路径 |
| `-2fa` | `false` | 启用双因素 TOTP 认证 |

## 安全

- **随机访问路径** — 每次启动生成 10 位 hex 路径，避免扫描
- **随机密码** — `-pass` 留空时自动生成
- **HTTPS** — `-cert cert.pem -key key.pem` 启用 TLS，流量全加密
- **API 传输加密** — password/privateKey 使用每会话 AES-256-GCM 前端加密后传输
- **CSRF 保护** — 所有写 API 需 X-CSRF-Token 验证
- **Cookie** — HttpOnly + SameSite=Strict + Secure（TLS 时），JS 不可读
- **Token 24h 过期** — 过期自动清除，后台每 10 分钟清理
- **登录限速** — 同 IP 5 次失败封 15 分钟
- **IP 绑定** — 会话 token 绑定签发 IP，防劫持
- **安全响应头** — X-Content-Type-Options, X-Frame-Options, HSTS 等
- **双因素 TOTP** — 可选 Time-based One-Time Password 二次验证
- **密码修改** — 登录后页面在线修改
- **路径遍历防护** — SFTP 拒绝所有 `..` 路径

## 使用 HTTPS

```bash
# 生成自签名证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem -subj "/CN=your-server-ip"

./webssh -cert cert.pem -key key.pem
```

## 自定义访问路径

```bash
# 固定路径
./webssh -url myconsole

# 访问 http://your-server:8080/myconsole/
```

## 从源码构建

```bash
git clone <repo>
cd webssh
go build -o webssh .
```

## 打包发布

```bash
# 构建所有平台二进制 + 打包为 .tar.gz
make release

# 产物在 dist/ 目录
ls dist/
# webssh-darwin-amd64.tar.gz  webssh-darwin-arm64.tar.gz
# webssh-linux-amd64.tar.gz   webssh-linux-arm64.tar.gz
```

## 直接部署

单二进制，复制到服务器即可运行：

```bash
scp webssh server:~/
ssh server
./webssh
```

## 技术栈

- **后端**: Go, gorilla/mux, gorilla/websocket, golang.org/x/crypto/ssh, pkg/sftp
- **前端**: xterm.js, CodeMirror 5（18 种语言模式，本地嵌入，无 CDN 依赖）
- **存储**: SQLite (modernc.org/sqlite，纯 Go，无 CGO)
- **加密**: AES-256-GCM（传输层 + 存储层独立密钥）
- **嵌入**: go:embed，所有静态资源打进二进制
