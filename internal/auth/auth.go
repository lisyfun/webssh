package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

type tokenEntry struct {
	created time.Time
	ip      string
}

type rateEntry struct {
	count    int
	firstTry time.Time
}

type Auth struct {
	username  string
	password  string
	basePath  string
	tokens    map[string]tokenEntry
	rateLimit map[string]*rateEntry
	mu        sync.RWMutex
	tokenTTL  time.Duration
	maxLogins int
	banTime   time.Duration
}

func New(username, password, basePath string) *Auth {
	a := &Auth{
		username:  username,
		password:  password,
		basePath:  basePath,
		tokens:    make(map[string]tokenEntry),
		rateLimit: make(map[string]*rateEntry),
		tokenTTL:  24 * time.Hour,
		maxLogins: 5,
		banTime:   15 * time.Minute,
	}
	go a.cleanupLoop()
	return a
}

func (a *Auth) SetPassword(pass string) {
	a.mu.Lock()
	a.password = pass
	a.mu.Unlock()
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}

		cookie, err := r.Cookie("token")
		if err != nil {
			redirectLogin(w, r, a.basePath)
			return
		}

		a.mu.RLock()
		entry, ok := a.tokens[cookie.Value]
		a.mu.RUnlock()

		if !ok || time.Since(entry.created) > a.tokenTTL {
			if ok {
				a.mu.Lock()
				delete(a.tokens, cookie.Value)
				a.mu.Unlock()
			}
			redirectLogin(w, r, a.basePath)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Auth) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Basic CSRF protection: require same-origin Referer
	ref := r.Header.Get("Referer")
	if ref == "" || !sameOrigin(r, ref) {
		w.Write([]byte(`{"ok":false,"msg":"非法请求来源"}`))
		return
	}

	r.ParseForm()
	oldPass := r.FormValue("old_pass")
	newPass := r.FormValue("new_pass")

	a.mu.RLock()
	passOk := oldPass == a.password
	a.mu.RUnlock()

	if !passOk {
		w.Write([]byte(`{"ok":false,"msg":"旧密码错误"}`))
		return
	}
	if len(newPass) < 4 {
		w.Write([]byte(`{"ok":false,"msg":"新密码至少4位"}`))
		return
	}

	a.SetPassword(newPass)
	w.Write([]byte(`{"ok":true,"msg":"密码已修改"}`))
}

func sameOrigin(r *http.Request, ref string) bool {
	// Extract scheme + host from Referer and compare to request
	scheme := "http://"
	if r.TLS != nil {
		scheme = "https://"
	}
	return len(ref) >= len(scheme+r.Host) && ref[:len(scheme+r.Host)] == scheme+r.Host
}

func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		ip := clientIP(r)

		a.mu.Lock()
		re, exists := a.rateLimit[ip]
		if exists {
			if time.Since(re.firstTry) > a.banTime {
				re.count = 0
				re.firstTry = time.Now()
			} else if re.count >= a.maxLogins {
				a.mu.Unlock()
				w.Write([]byte(loginPage(a.basePath, "登录尝试过多，请15分钟后再试")))
				return
			}
		} else {
			a.rateLimit[ip] = &rateEntry{firstTry: time.Now()}
		}
		a.rateLimit[ip].count++
		a.mu.Unlock()

		r.ParseForm()
		user := r.FormValue("user")
		pass := r.FormValue("pass")

		if user == a.username && pass == a.password {
			token := generateToken()
			a.mu.Lock()
			a.tokens[token] = tokenEntry{created: time.Now(), ip: ip}
			delete(a.rateLimit, ip)
			a.mu.Unlock()

			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    token,
				Path:     a.basePath + "/",
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, a.basePath+"/", http.StatusFound)
			return
		}

		w.Write([]byte(loginPage(a.basePath, "用户名或密码错误")))
		return
	}

	w.Write([]byte(loginPage(a.basePath, "")))
}

func (a *Auth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err == nil {
		a.mu.Lock()
		delete(a.tokens, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "token",
		Value:  "",
		Path:   a.basePath + "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, a.basePath+"/login", http.StatusFound)
}

func redirectLogin(w http.ResponseWriter, r *http.Request, basePath string) {
	if r.Header.Get("Upgrade") == "websocket" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, basePath+"/login", http.StatusFound)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loginPage(basePath, errMsg string) string {
	errStyle := "display:none"
	if errMsg != "" {
		errStyle = ""
	}
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSSH - 登录</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { height: 100%; background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; display: flex; align-items: center; justify-content: center; }
.login-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 32px; width: 360px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
.login-box h1 { font-size: 18px; font-weight: 600; margin-bottom: 4px; }
.login-box .sub { font-size: 12px; color: #8b949e; margin-bottom: 24px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 4px; }
.form-group input { width: 100%; padding: 8px 10px; background: #0d1117; border: 1px solid #30363d; border-radius: 4px; color: #e6edf3; font-size: 14px; outline: none; }
.form-group input:focus { border-color: #4a8cff; }
.btn { width: 100%; padding: 8px; border: none; border-radius: 4px; background: #4a8cff; color: #fff; font-size: 14px; cursor: pointer; }
.btn:hover { background: #3a7ae8; }
.error { color: #ff7b72; font-size: 12px; margin-top: 8px; text-align: center; }
</style>
</head>
<body>
<div class="login-box">
  <h1>WebSSH</h1>
  <div class="sub">请输入登录信息</div>
  <form method="post" action="` + basePath + `/login">
    <div class="form-group">
      <label>用户名</label>
      <input type="text" name="user" autofocus>
    </div>
    <div class="form-group">
      <label>密码</label>
      <input type="password" name="pass">
    </div>
    <button class="btn" type="submit">登录</button>
    <div class="error" style="` + errStyle + `">` + errMsg + `</div>
  </form>
</div>
</body>
</html>`
}

func (a *Auth) cleanupLoop() {
	for {
		time.Sleep(10 * time.Minute)
		a.mu.Lock()
		for k, v := range a.tokens {
			if time.Since(v.created) > a.tokenTTL {
				delete(a.tokens, k)
			}
		}
		now := time.Now()
		for k, v := range a.rateLimit {
			if now.Sub(v.firstTry) > a.banTime {
				delete(a.rateLimit, k)
			}
		}
		a.mu.Unlock()
	}
}
