# WebSSH

基于 Go + xterm.js 的轻量级 Web SSH 客户端，单二进制部署，无需外部依赖。

## 功能

- Web 终端 — 浏览器中通过 SSH 连接远程服务器
- 多会话管理 — 多个服务器同时连接，切换不断开
- 文件管理 — 内嵌 SFTP 文件浏览器，随终端 CWD 联动
- 上传下载 — 拖拽上传、目录列表下载
- 用户认证 — 登录密码 + 随机访问路径 + 可选 HTTPS 三层防护
- 批量导入 — 粘贴 tabular 数据批量添加服务器
- 修改密码 — 登录后可在页面修改密码
- 暗色主题 — Luna 风格三栏布局

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

## 安全

- **随机访问路径** — 每次启动生成 10 位 hex 路径，避免扫描
- **随机密码** — `-pass` 留空时自动生成
- **HTTPS** — `-cert cert.pem -key key.pem` 启用 TLS，流量全加密
- **Cookie** — HttpOnly + SameSite=Strict + Secure（TLS 时），JS 不可读
- **Token 24h 过期** — 过期自动清除，后台每 10 分钟清理
- **登录限速** — 同 IP 5 次失败封 15 分钟
- **安全响应头** — X-Content-Type-Options, X-Frame-Options, HSTS 等
- **密码修改** — 登录后页面在线修改

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

## 直接部署

单二进制，复制到服务器即可运行：

```bash
scp webssh server:~/
ssh server
./webssh
```

## 技术栈

- **后端**: Go, gorilla/mux, gorilla/websocket, golang.org/x/crypto/ssh, pkg/sftp
- **前端**: xterm.js (嵌入, 无 CDN 依赖)
- **嵌入**: go:embed，所有静态资源打进二进制
