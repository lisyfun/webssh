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

type pendingSetup struct {
	username  string
	secret    string
	uri       string
	qr        string
	setupPass string // one-time password hash to re-auth during setup
	created   time.Time
}

type Auth struct {
	store         UserStore
	username      string
	password      string
	basePath      string
	tokens        map[string]tokenEntry
	rateLimit     map[string]*rateEntry
	pendingSetups map[string]*pendingSetup
	mu            sync.RWMutex
	tokenTTL      time.Duration
	maxLogins     int
	banTime       time.Duration
	maxBodyMB     int64
	enable2FA     bool
}

func New(store UserStore, username, password, basePath string, maxBodyMB int64, enable2FA bool) *Auth {
	a := &Auth{
		store:         store,
		username:      username,
		password:      password,
		basePath:      basePath,
		tokens:        make(map[string]tokenEntry),
		rateLimit:     make(map[string]*rateEntry),
		pendingSetups: make(map[string]*pendingSetup),
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

		if !ok {
			w.Write([]byte(loginPage(a.basePath, "用户名或密码错误", false, "", "")))
			return
		}

		// Password correct — handle 2FA
		if a.enable2FA {
			hasSecret, _ := a.store.HasTOTPEnabled(context.Background(), user)
			if hasSecret {
				// Already set up — verify TOTP code
				if totpCode == "" {
					w.Write([]byte(loginPage(a.basePath, "需要双因素认证码", true, user, pass)))
					return
				}
				secret, err := a.store.GetTOTPSecret(context.Background(), user)
				if err != nil || !totp.Validate(totpCode, secret) {
					w.Write([]byte(loginPage(a.basePath, "双因素认证码无效", true, user, pass)))
					return
				}
			} else {
				// First-time setup — generate TOTP and show QR
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
					username:  user,
					secret:    key.Secret(),
					uri:       key.URL(),
					qr:        qrData,
					created:   time.Now(),
				}
				a.mu.Unlock()

				w.Write([]byte(setup2FAPage(a.basePath, setupToken, qrData, key.Secret())))
				return
			}
		}

		// Login success
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

func (a *Auth) CompleteTOTPSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	setupToken := r.FormValue("setup_token")
	code := r.FormValue("code")

	a.mu.Lock()
	ps, ok := a.pendingSetups[setupToken]
	if !ok || time.Since(ps.created) > 10*time.Minute {
		delete(a.pendingSetups, setupToken)
		a.mu.Unlock()
		w.Write([]byte(setup2FAPage(a.basePath, setupToken, ps.qr, ps.secret)))
		return
	}
	delete(a.pendingSetups, setupToken)
	a.mu.Unlock()

	if !totp.Validate(code, ps.secret) {
		http.Error(w, "验证码无效，请返回重新登录", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	if err := a.store.SetTOTPSecret(ctx, ps.username, ps.secret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ip := clientIP(r)
	token := generateToken()
	encKey := make([]byte, 32)
	io.ReadFull(rand.Reader, encKey)
	a.mu.Lock()
	a.tokens[token] = tokenEntry{created: time.Now(), ip: ip, encKey: encKey}
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: "token", Value: token, Path: a.basePath + "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, a.basePath+"/", http.StatusFound)
}

func (a *Auth) TOTPResetHandler(w http.ResponseWriter, r *http.Request) {
	// Logged-in user resets 2FA — verify password, generate new secret, clear old one
	r.ParseForm()
	pass := r.FormValue("pass")
	ok := a.store.VerifyPassword(context.Background(), a.username, pass)
	if !ok && (a.username != a.username || pass != a.password) {
		// Also check in-memory password
		if pass != a.password {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "密码错误"})
			return
		}
	}
	if !ok {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "密码错误"})
		return
	}

	// Generate new secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "WebSSH", AccountName: a.username,
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

	// Clear old secret so next login triggers setup
	a.store.DisableTOTP(context.Background(), a.username)

	json.NewEncoder(w).Encode(map[string]string{
		"secret": key.Secret(),
		"uri":    key.URL(),
		"qr":     qrData,
	})
}

func setup2FAPage(basePath, setupToken, qrData, secret string) string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSSH - 双因素认证</title>
<style>
:root {
  --bg: #0d1117; --card: #161b22; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e; --accent: #4a8cff; --accent-hover: #3a7ae8;
  --danger: #ff7b72;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;display:flex;align-items:center;justify-content:center}
body::before{content:"";position:fixed;top:0;left:0;width:100%;height:100%;background:radial-gradient(ellipse at 50% 0%,rgba(74,140,255,0.06) 0%,transparent 70%);pointer-events:none}

.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:36px;width:400px;box-shadow:0 4px 24px rgba(0,0,0,0.3),0 0 0 1px rgba(255,255,255,0.03);text-align:center}
.logo{width:44px;height:44px;margin:0 auto 16px;background:linear-gradient(135deg,#4a8cff,#58a6ff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;font-weight:700}
h1{font-size:18px;font-weight:600;margin-bottom:4px;letter-spacing:-0.2px}
.sub{font-size:13px;color:var(--muted);margin-bottom:24px;line-height:1.5}

.qr-wrap{background:#fff;border-radius:10px;padding:12px;display:inline-block;margin-bottom:16px;box-shadow:0 2px 8px rgba(0,0,0,0.2)}
.qr{width:180px;height:180px;display:block}

.secret-box{font-family:"SF Mono","Fira Code","Consolas",monospace;font-size:12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin:0 auto 18px;word-break:break-all;color:#58a6ff;max-width:320px;letter-spacing:0.5px;user-select:all}
.secret-box::before{content:"手动输入密钥: ";color:var(--muted);font-family:-apple-system,BlinkMacSystemFont,sans-serif;letter-spacing:0}

.form-group{margin-bottom:18px}
.form-group label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;font-weight:500}
.form-group input{width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:15px;outline:none;text-align:center;letter-spacing:5px;transition:border-color .2s,box-shadow .2s}
.form-group input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(74,140,255,0.15)}
.form-group input::placeholder{color:#484f58;letter-spacing:normal}

.btn{width:100%;padding:10px;border:none;border-radius:6px;background:var(--accent);color:#fff;font-size:14px;font-weight:500;cursor:pointer;transition:background .2s,transform .1s}
.btn:hover{background:var(--accent-hover)}
.btn:active{transform:scale(0.98)}

.tip{font-size:12px;color:var(--muted);margin-top:18px;line-height:1.6}
.tip a{color:var(--accent);text-decoration:none}
.tip a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
  <div class="logo">&gt;_</div>
  <h1>双因素认证</h1>
  <div class="sub">使用 Google Authenticator / Authy / Microsoft Authenticator 扫码绑定</div>
  <div class="qr-wrap">
    <img class="qr" src="` + qrData + `" alt="QR Code">
  </div>
  <div class="secret-box">` + secret + `</div>
  <form method="post" action="` + basePath + `/complete-2fa-setup">
    <input type="hidden" name="setup_token" value="` + setupToken + `">
    <div class="form-group">
      <label>六位验证码</label>
      <input type="text" name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="off" autofocus placeholder="000 000">
    </div>
    <button class="btn" type="submit">验证并登录</button>
  </form>
  <div class="tip">首次绑定，扫码或手动输入密钥后输入 App 中的 6 位数字即可。</div>
</div>
</body>
</html>`
}

func loginPage(basePath, errMsg string, showTOTP bool, savedUser, savedPass string) string {
	errShow := ""
	if errMsg == "" {
		errShow = "hidden"
	}
	totpShow := "hidden"
	userPassShow := ""
	totpAutofocus := ""
	userAutofocus := "autofocus"
	if showTOTP {
		totpShow = ""
		userPassShow = "hidden"
		totpAutofocus = "autofocus"
		userAutofocus = ""
	}
	userField := `<input type="text" name="user" placeholder="admin" ` + userAutofocus + ` autocomplete="username">`
	passField := `<input type="password" name="pass" placeholder="········" autocomplete="current-password">`
	if showTOTP {
		userField = `<input type="hidden" name="user" value="` + savedUser + `">`
		passField = `<input type="hidden" name="pass" value="` + savedPass + `">`
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

.totp-hint{text-align:center;font-size:12px;color:var(--muted);margin-bottom:18px;padding:10px;background:rgba(74,140,255,0.06);border-radius:6px;border:1px solid rgba(74,140,255,0.1)}
.totp-hint strong{color:var(--accent)}
.totp-hint.hidden{display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">&gt;_</div>
  <h1>WebSSH</h1>
  <div class="sub" id="card-sub">安全远程终端管理</div>
  <div class="totp-hint ` + userPassShow + `">
    已通过密码验证 &mdash; 请输入 <strong>认证器 App 中的 6 位动态码</strong>
  </div>
  <form method="post" action="` + basePath + `/login">
    <div class="form-group ` + userPassShow + `">
      <label>用户名</label>
      ` + userField + `
    </div>
    <div class="form-group ` + userPassShow + `">
      <label>密码</label>
      ` + passField + `
    </div>
    <div class="form-group ` + totpShow + `">
      <label>双因素认证码</label>
      <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" ` + totpAutofocus + ` placeholder="000 000">
    </div>
    <button class="btn" type="submit">` + map[bool]string{true: "验证并登录", false: "登录"}[showTOTP] + `</button>
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
		a.mu.Unlock()
	}
}
