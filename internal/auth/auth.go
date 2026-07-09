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
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

type tokenEntry struct {
	created time.Time
	ip      string
	encKey  []byte
	csrf    string
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
	trustedProxy  bool
}

var ErrEncryptedFieldRequired = errors.New("encrypted field required")

func New(store UserStore, username, basePath string, maxBodyMB int64, enable2FA, trustedProxy bool) *Auth {
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
		trustedProxy:  trustedProxy,
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
	a.mu.RLock()
	entry, ok := a.tokens[cookie.Value]
	a.mu.RUnlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"key":"%s","csrf":"%s","maxBodyMB":%d}`, hex.EncodeToString(entry.encKey), entry.csrf, a.maxBodyMB)
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
		a.mu.RLock()
		entry, ok := a.tokens[cookie.Value]
		a.mu.RUnlock()
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if token == "" || token != entry.csrf {
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
		if entry.ip != a.clientIP(r) {
			a.mu.Lock()
			delete(a.tokens, cookie.Value)
			a.mu.Unlock()
			redirectLogin(w, r, a.basePath)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) clientIP(r *http.Request) string {
	if a.trustedProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if i := strings.IndexByte(fwd, ','); i >= 0 {
				fwd = fwd[:i]
			}
			return strings.TrimSpace(fwd)
		}
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return strings.TrimSpace(real)
		}
	}
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

// rateLimitCheck returns true if the request should be rejected (rate limit exceeded).
// On first call from an IP it initializes the counter; on excess it writes the error.
func (a *Auth) rateLimitCheck(w http.ResponseWriter, ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	re, exists := a.rateLimit[ip]
	if exists {
		if time.Since(re.firstTry) > a.banTime {
			re.count = 0
			re.firstTry = time.Now()
		} else if re.count >= a.maxLogins {
			http.Error(w, "尝试过多，请15分钟后再试", http.StatusTooManyRequests)
			return true
		}
	} else {
		a.rateLimit[ip] = &rateEntry{firstTry: time.Now()}
	}
	a.rateLimit[ip].count++
	return false
}

func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		ip := a.clientIP(r)

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
	csrfToken := generateToken()[:16]
	a.mu.Lock()
	a.tokens[token] = tokenEntry{created: time.Now(), ip: ip, encKey: encKey, csrf: csrfToken}
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
	errColor := ""
	if errMsg != "" {
		errColor = "color:#ff5555"
	}
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSSH Terminal</title>
<style id="theme-style">
:root {
  --bg: #0c0c0c;
  --fg: #e3b341;
  --dim: #8a6e20;
  --dim2: #4a3a10;
  --border: #3a2e0a;
  --bar-bg: #1a1a1a;
  --bar-title: #666;
  --err-fg: #ff5555;
  --err-border: rgba(255,85,85,.2);
}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:var(--bg);color:var(--fg);font-family:"Consolas","Menlo","Monaco","Courier New",monospace;display:flex;align-items:center;justify-content:center}

.term{border:1px solid var(--border);border-radius:8px;width:580px;overflow:hidden;box-shadow:0 0 40px color-mix(in srgb, var(--fg) 6%, transparent)}
.term-bar{background:var(--bar-bg);padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border)}
.dot{width:10px;height:10px;border-radius:50%}
.dot.r{background:#ff5f56}
.dot.y{background:#ffbd2e}
.dot.g{background:#27c93f}
.term-title{font-size:12px;color:var(--bar-title);margin-left:8px}

.term-body{padding:28px 32px 32px}

.banner{font-size:13px;line-height:1.6;margin-bottom:24px;color:var(--fg)}
.banner .dim{color:var(--dim)}

.prompt{margin-bottom:6px;display:flex;align-items:center;gap:0}
.prompt .prefix{color:var(--dim);font-size:14px;white-space:pre}
.prompt input{background:transparent;border:none;color:var(--fg);font-family:inherit;font-size:14px;outline:none;flex:1;padding:4px 0;caret-color:var(--fg)}
.prompt input::placeholder{color:var(--dim2)}

.btn{margin-top:18px;padding:8px 20px;background:transparent;border:1px solid var(--fg);color:var(--fg);font-family:inherit;font-size:13px;cursor:pointer;transition:background .2s}
.btn:hover{background:color-mix(in srgb, var(--fg) 8%, transparent)}
.btn:active{background:color-mix(in srgb, var(--fg) 15%, transparent)}

.error{margin-top:16px;padding:6px 0;font-size:13px;color:var(--err-fg);border-top:1px solid var(--err-border)}
.error.hidden{display:none}

.cursor{display:inline-block;width:8px;height:15px;background:var(--fg);animation:blink 1s step-end infinite;margin-left:4px;vertical-align:middle}

.footer{font-size:11px;color:var(--dim2);margin-top:20px;text-align:center}
</style>
<script>
(function(){
  // 读取终端主题配色，使登录页跟随用户已选主题
  var themes = {
    'github-dark':       {bg:'#0d1117',border:'#30363d',bar:'#161b22',title:'#8b949e'},
    'catppuccin-mocha':  {bg:'#1e1e2e',border:'#313244',bar:'#181825',title:'#6c7086'},
    'one-dark-pro':      {bg:'#282c34',border:'#3e4451',bar:'#21252b',title:'#5c6370'},
    'tokyo-night':       {bg:'#1a1b26',border:'#2f3346',bar:'#13141f',title:'#565f89'},
    'nord':              {bg:'#2e3440',border:'#4c566a',bar:'#242933',title:'#6c7a96'},
    'github-light':      {bg:'#ffffff',border:'#d0d7de',bar:'#f6f8fa',title:'#656d76'},
    'catppuccin-latte':  {bg:'#eff1f5',border:'#ccd0da',bar:'#e6e9ef',title:'#6c7086'},
    'one-light':         {bg:'#fafafa',border:'#d8d8d8',bar:'#f0f0f0',title:'#6c6c6c'},
    'solarized-light':   {bg:'#fdf6e3',border:'#d5d8c9',bar:'#eee8d5',title:'#839496'},
    'ibm-light':         {bg:'#e1e2e7',border:'#c0c5d8',bar:'#d5d7e0',title:'#5c7fc7'}
  };
  try {
    var saved = JSON.parse(localStorage.getItem('webssh-font') || '{}');
    var t = themes[saved.theme];
    if (t) {
      var s = document.documentElement.style;
      s.setProperty('--bg', t.bg);
      s.setProperty('--border', t.border);
      s.setProperty('--bar-bg', t.bar);
      s.setProperty('--bar-title', t.title);
    }
  } catch(e){}
})();
</script>
</head>
<body>
<div class="term">
  <div class="term-bar">
    <div class="dot r"></div>
    <div class="dot y"></div>
    <div class="dot g"></div>
    <span class="term-title">admin@webssh — ssh</span>
  </div>
  <div class="term-body">
    <div class="banner">
      Welcome to WebSSH Terminal Server<br>
      <span class="dim">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span><br>
      <span class="dim">»  secure remote terminal management</span>
    </div>
    <form method="post" action="` + basePath + `/login" autocomplete="off">
      <div class="prompt">
        <span class="prefix">login: </span>
        <input type="text" name="user" placeholder="admin" autofocus autocomplete="username" spellcheck="false">
      </div>
      <div class="prompt">
        <span class="prefix">password: </span>
        <input type="password" name="pass" placeholder="········" autocomplete="current-password" spellcheck="false">
      </div>
      <button class="btn" type="submit">[ 连接 ]</button>
      <div class="error ` + errShow + `" style="` + errColor + `">` + errMsg + `</div>
    </form>
    <div class="footer">WebSSH v1.0 — <span class="cursor"></span></div>
  </div>
</div>
</body>
</html>`
}
func (a *Auth) cleanupLoop() {
	for {
		time.Sleep(5 * time.Minute)
		now := time.Now()
		a.mu.Lock()
		for k, v := range a.tokens {
			if time.Since(v.created) > a.tokenTTL {
				delete(a.tokens, k)
			}
		}
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
