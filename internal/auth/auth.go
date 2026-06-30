package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

type tokenEntry struct {
	created time.Time
	ip      string
	encKey  []byte
}

type rateEntry struct {
	count    int
	firstTry time.Time
}

type UserStore interface {
	VerifyPassword(ctx context.Context, username, password string) bool
	ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error
	HasTOTPEnabled(ctx context.Context, username string) (bool, error)
	GetTOTPSecret(ctx context.Context, username string) (string, error)
	SetTOTPSecret(ctx context.Context, username, secret string) error
	DisableTOTP(ctx context.Context, username string) error
}

type pendingSetup struct {
	username string
	secret   string
	uri      string
	qr       string
	created  time.Time
}

type pendingLogin struct {
	username string
	created  time.Time
}

type Auth struct {
	store         UserStore
	username      string
	basePath      string
	tokens        map[string]tokenEntry
	rateLimit     map[string]*rateEntry
	pendingSetups map[string]*pendingSetup
	pendingLogins map[string]*pendingLogin
	mu            sync.RWMutex
	tokenTTL      time.Duration
	maxLogins     int
	banTime       time.Duration
	maxBodyMB     int64
	enable2FA     bool
}

var ErrEncryptedFieldRequired = errors.New("encrypted field required")

func New(store UserStore, username, basePath string, maxBodyMB int64, enable2FA bool) *Auth {
	a := &Auth{
		store:         store,
		username:      username,
		basePath:      basePath,
		tokens:        make(map[string]tokenEntry),
		rateLimit:     make(map[string]*rateEntry),
		pendingSetups: make(map[string]*pendingSetup),
		pendingLogins: make(map[string]*pendingLogin),
		tokenTTL:      24 * time.Hour,
		maxLogins:     5,
		banTime:       15 * time.Minute,
		maxBodyMB:     maxBodyMB,
		enable2FA:     enable2FA,
	}
	go a.cleanupLoop()
	return a
}

// SessionEncryptionKey returns the AES-256-GCM key associated with the request's session token.
func (a *Auth) SessionEncryptionKey(r *http.Request) ([]byte, bool) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return nil, false
	}
	a.mu.RLock()
	entry, ok := a.tokens[cookie.Value]
	a.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return entry.encKey, true
}

// DecryptWithKey decrypts a base64(nonce+ciphertext) string using the given AES-256-GCM key.
func (a *Auth) DecryptWithKey(key []byte, s string) string {
	plain, err := a.DecryptWithKeyStrict(key, s)
	if err != nil {
		return s
	}
	return plain
}

// DecryptWithKeyStrict decrypts a base64(nonce+ciphertext) string using the given AES-256-GCM key.
func (a *Auth) DecryptWithKeyStrict(key []byte, s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if len(key) == 0 {
		return "", ErrEncryptedFieldRequired
	}
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(data) < 12 {
		return "", ErrEncryptedFieldRequired
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ae, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, ct := data[:12], data[12:]
	plaintext, err := ae.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrEncryptedFieldRequired
	}
	return string(plaintext), nil
}

// DecryptField decrypts a field using the request's session key. Returns original if not encrypted.
func (a *Auth) DecryptField(r *http.Request, s string) string {
	plain, err := a.DecryptFieldStrict(r, s)
	if err != nil {
		return s
	}
	return plain
}

// DecryptFieldStrict decrypts a sensitive field and rejects malformed non-empty values.
func (a *Auth) DecryptFieldStrict(r *http.Request, s string) (string, error) {
	if s == "" {
		return "", nil
	}
	key, ok := a.SessionEncryptionKey(r)
	if !ok {
		return "", ErrEncryptedFieldRequired
	}
	return a.DecryptWithKeyStrict(key, s)
}

func (a *Auth) KeyHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	key, ok := a.SessionEncryptionKey(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	csrf := cookie.Value[:16]
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"key":"%s","csrf":"%s","maxBodyMB":%d}`, hex.EncodeToString(key), csrf, a.maxBodyMB)
}

// CSRFValidate is middleware that checks the X-CSRF-Token header for state-changing requests.
func (a *Auth) CSRFValidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie("token")
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		expected := cookie.Value[:16]
		token := r.Header.Get("X-CSRF-Token")
		if token == "" || token != expected {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
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

		// Bind the session token to the IP it was issued to, so a stolen
		// token cannot be replayed from another address.
		if entry.ip != clientIP(r) {
			a.mu.Lock()
			delete(a.tokens, cookie.Value)
			a.mu.Unlock()
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
	w.Header().Set("Content-Type", "application/json")

	ref := r.Header.Get("Referer")
	if ref == "" || !sameOrigin(r, ref) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "非法请求来源"})
		return
	}

	r.ParseForm()
	oldPass := r.FormValue("old_pass")
	newPass := r.FormValue("new_pass")

	if len(newPass) < 4 {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "新密码至少4位"})
		return
	}

	err := a.store.ChangePassword(context.Background(), a.username, oldPass, newPass)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "密码已修改"})
}

func sameOrigin(r *http.Request, ref string) bool {
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
				w.Write([]byte(loginPage(a.basePath, "登录尝试过多，请15分钟后再试", "")))
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

		if user != a.username || !a.store.VerifyPassword(context.Background(), user, pass) {
			w.Write([]byte(loginPage(a.basePath, "用户名或密码错误", "")))
			return
		}

		// Password correct — handle 2FA
		if a.enable2FA {
			hasSecret, _ := a.store.HasTOTPEnabled(context.Background(), user)
			if hasSecret {
				loginToken := generateToken()
				a.mu.Lock()
				a.pendingLogins[loginToken] = &pendingLogin{username: user, created: time.Now()}
				a.mu.Unlock()
				http.Redirect(w, r, a.basePath+"/login/2fa?token="+loginToken, http.StatusFound)
				return
			}

			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "WebSSH",
				AccountName: user,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			qr, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			qrData := "data:image/png;base64," + base64.StdEncoding.EncodeToString(qr)

			setupToken := generateToken()
			a.mu.Lock()
			a.pendingSetups[setupToken] = &pendingSetup{
				username: user,
				secret:   key.Secret(),
				uri:      key.URL(),
				qr:       qrData,
				created:  time.Now(),
			}
			a.mu.Unlock()

			w.Write([]byte(setup2FAPage(a.basePath, setupToken, qrData, key.Secret())))
			return
		}

		a.mu.Lock()
		delete(a.rateLimit, ip)
		a.mu.Unlock()
		a.establishSession(w, r, ip)
		return
	}

	w.Write([]byte(loginPage(a.basePath, "", "")))
}

func (a *Auth) establishSession(w http.ResponseWriter, r *http.Request, ip string) {
	token := generateToken()
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, encKey); err != nil {
		http.Error(w, "failed to initialize session", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	a.tokens[token] = tokenEntry{created: time.Now(), ip: ip, encKey: encKey}
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
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func loginPage(basePath, errMsg string, _ string) string {
	errShow := ""
	if errMsg == "" {
		errShow = "hidden"
	}
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSSH</title>
<style>
:root {
  --bg: #0d1117; --card: #161b22; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e; --accent: #4a8cff; --accent-hover: #3a7ae8;
  --danger: #ff7b72; --danger-bg: rgba(255,123,114,0.08);
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;display:flex;align-items:center;justify-content:center}
body::before{content:"";position:fixed;top:0;left:0;width:100%;height:100%;background:radial-gradient(ellipse at 50% 0%,rgba(74,140,255,0.06) 0%,transparent 70%);pointer-events:none}

.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:36px;width:380px;box-shadow:0 4px 24px rgba(0,0,0,0.3),0 0 0 1px rgba(255,255,255,0.03)}
.logo{width:44px;height:44px;margin:0 auto 20px;background:linear-gradient(135deg,#4a8cff,#58a6ff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;font-weight:700}
h1{font-size:18px;font-weight:600;text-align:center;margin-bottom:6px;letter-spacing:-0.2px}
.sub{font-size:13px;color:var(--muted);text-align:center;margin-bottom:28px}

.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:11px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;font-weight:500}
.form-group input{width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;outline:none;transition:border-color .2s,box-shadow .2s}
.form-group input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(74,140,255,0.15)}
.form-group input::placeholder{color:#484f58}

.btn{width:100%;padding:10px;border:none;border-radius:6px;background:var(--accent);color:#fff;font-size:14px;font-weight:500;cursor:pointer;transition:background .2s,transform .1s;margin-top:4px}
.btn:hover{background:var(--accent-hover)}
.btn:active{transform:scale(0.98)}

.error{margin-top:14px;padding:8px 12px;border-radius:6px;background:var(--danger-bg);border:1px solid rgba(255,123,114,0.2);color:var(--danger);font-size:12px;text-align:center;line-height:1.4}
.error.hidden{display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">&gt;_</div>
  <h1>WebSSH</h1>
  <div class="sub">安全远程终端管理</div>
  <form method="post" action="` + basePath + `/login">
    <div class="form-group">
      <label>用户名</label>
      <input type="text" name="user" placeholder="admin" autofocus autocomplete="username">
    </div>
    <div class="form-group">
      <label>密码</label>
      <input type="password" name="pass" placeholder="········" autocomplete="current-password">
    </div>
    <button class="btn" type="submit">登录</button>
    <div class="error ` + errShow + `">` + errMsg + `</div>
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
		for k, v := range a.pendingSetups {
			if now.Sub(v.created) > 10*time.Minute {
				delete(a.pendingSetups, k)
			}
		}
		for k, v := range a.pendingLogins {
			if now.Sub(v.created) > 10*time.Minute {
				delete(a.pendingLogins, k)
			}
		}
		a.mu.Unlock()
	}
}
