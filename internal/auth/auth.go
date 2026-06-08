package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

type Auth struct {
	store     UserStore
	username  string
	password  string
	basePath  string
	tokens    map[string]tokenEntry
	rateLimit map[string]*rateEntry
	mu        sync.RWMutex
	tokenTTL  time.Duration
	maxLogins int
	banTime   time.Duration
	maxBodyMB int64
	enable2FA bool
}

func New(store UserStore, username, password, basePath string, maxBodyMB int64, enable2FA bool) *Auth {
	a := &Auth{
		store:     store,
		username:  username,
		password:  password,
		basePath:  basePath,
		tokens:    make(map[string]tokenEntry),
		rateLimit: make(map[string]*rateEntry),
		tokenTTL:  24 * time.Hour,
		maxLogins: 5,
		banTime:   15 * time.Minute,
		maxBodyMB: maxBodyMB,
		enable2FA: enable2FA,
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
	if len(key) == 0 || s == "" {
		return s
	}
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(data) < 12 {
		return s
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return s
	}
	ae, err := cipher.NewGCM(block)
	if err != nil {
		return s
	}
	nonce, ct := data[:12], data[12:]
	plaintext, err := ae.Open(nil, nonce, ct, nil)
	if err != nil {
		return s
	}
	return string(plaintext)
}

// DecryptField decrypts a field using the request's session key. Returns original if not encrypted.
func (a *Auth) DecryptField(r *http.Request, s string) string {
	key, ok := a.SessionEncryptionKey(r)
	if !ok {
		return s
	}
	return a.DecryptWithKey(key, s)
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

	ref := r.Header.Get("Referer")
	if ref == "" || !sameOrigin(r, ref) {
		w.Write([]byte(`{"ok":false,"msg":"非法请求来源"}`))
		return
	}

	r.ParseForm()
	oldPass := r.FormValue("old_pass")
	newPass := r.FormValue("new_pass")

	if len(newPass) < 4 {
		w.Write([]byte(`{"ok":false,"msg":"新密码至少4位"}`))
		return
	}

	err := a.store.ChangePassword(context.Background(), a.username, oldPass, newPass)
	if err != nil {
		w.Write([]byte(`{"ok":false,"msg":"` + err.Error() + `"}`))
		return
	}

	a.mu.Lock()
	a.password = newPass
	a.mu.Unlock()

	w.Write([]byte(`{"ok":true,"msg":"密码已修改"}`))
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
				w.Write([]byte(loginPage(a.basePath, "登录尝试过多，请15分钟后再试", false, "", "")))
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
		totpCode := r.FormValue("totp_code")

		ok := false
		if user == a.username && pass == a.password {
			ok = true
		} else {
			ok = a.store.VerifyPassword(context.Background(), user, pass)
			if ok {
				a.mu.Lock()
				a.password = pass
				a.mu.Unlock()
			}
		}

		if ok {
			if a.enable2FA {
				totpEnabled, _ := a.store.HasTOTPEnabled(context.Background(), user)
				if totpEnabled {
					if totpCode == "" {
						w.Write([]byte(loginPage(a.basePath, "需要双因素认证码", true, user, pass)))
						return
					}
					secret, err := a.store.GetTOTPSecret(context.Background(), user)
					if err != nil || !totp.Validate(totpCode, secret) {
						w.Write([]byte(loginPage(a.basePath, "双因素认证码无效", true, user, pass)))
						return
					}
				}
			}

			token := generateToken()
			encKey := make([]byte, 32)
			io.ReadFull(rand.Reader, encKey)
			a.mu.Lock()
			a.tokens[token] = tokenEntry{created: time.Now(), ip: ip, encKey: encKey}
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

		w.Write([]byte(loginPage(a.basePath, "用户名或密码错误", false, "", "")))
		return
	}

	w.Write([]byte(loginPage(a.basePath, "", false, "", "")))
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

// ---- TOTP/2FA Handlers ----

func (a *Auth) TOTPStatusHandler(w http.ResponseWriter, r *http.Request) {
	enabled, _ := a.store.HasTOTPEnabled(context.Background(), a.username)
	json.NewEncoder(w).Encode(map[string]interface{}{"enabled": enabled, "available": a.enable2FA})
}

func (a *Auth) TOTPSetupHandler(w http.ResponseWriter, r *http.Request) {
	if !a.enable2FA {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "双因素认证未启用"})
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "WebSSH",
		AccountName: a.username,
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
	json.NewEncoder(w).Encode(map[string]string{
		"secret": key.Secret(),
		"uri":    key.URL(),
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(qr),
	})
}

func (a *Auth) TOTPEnableHandler(w http.ResponseWriter, r *http.Request) {
	if !a.enable2FA {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "双因素认证未启用"})
		return
	}
	r.ParseForm()
	secret := r.FormValue("secret")
	code := r.FormValue("code")
	if secret == "" || code == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "参数不完整"})
		return
	}
	if !totp.Validate(code, secret) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "验证码无效"})
		return
	}
	a.store.SetTOTPSecret(context.Background(), a.username, secret)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "双因素认证已启用"})
}

func (a *Auth) TOTPDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	code := r.FormValue("code")
	if code != "" {
		secret, err := a.store.GetTOTPSecret(context.Background(), a.username)
		if err != nil || !totp.Validate(code, secret) {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "验证码无效"})
			return
		}
	}
	a.store.DisableTOTP(context.Background(), a.username)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "双因素认证已禁用"})
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

func loginPage(basePath, errMsg string, showTOTP bool, savedUser, savedPass string) string {
	errStyle := "display:none"
	if errMsg != "" {
		errStyle = ""
	}
	totpStyle := "display:none"
	totpAutofocus := ""
	userAutofocus := "autofocus"
	if showTOTP {
		totpStyle = ""
		totpAutofocus = "autofocus"
		userAutofocus = ""
	}
	userField := `<input type="text" name="user" ` + userAutofocus + `>`
	passField := `<input type="password" name="pass">`
	if showTOTP {
		userField = `<input type="hidden" name="user" value="` + savedUser + `">` +
			`<div style="font-size:13px;color:#8b949e;margin-bottom:4px">用户: ` + savedUser + `</div>`
		passField = `<input type="hidden" name="pass" value="` + savedPass + `">`
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
      ` + userField + `
    </div>
    <div class="form-group">
      <label>密码</label>
      ` + passField + `
    </div>
    <div class="form-group" style="` + totpStyle + `">
      <label>双因素认证码</label>
      <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" ` + totpAutofocus + `>
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
