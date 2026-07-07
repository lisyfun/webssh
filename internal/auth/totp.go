package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

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

func (a *Auth) CompleteTOTPSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.rateLimitCheck(w, a.clientIP(r)) {
		return
	}
	r.ParseForm()
	setupToken := r.FormValue("setup_token")
	code := r.FormValue("code")

	a.mu.Lock()
	ps, ok := a.pendingSetups[setupToken]
	if !ok {
		a.mu.Unlock()
		http.Error(w, "双因素认证设置会话无效，请重新登录", http.StatusBadRequest)
		return
	}
	if time.Since(ps.created) > 10*time.Minute {
		delete(a.pendingSetups, setupToken)
		a.mu.Unlock()
		http.Error(w, "双因素认证设置会话已过期，请重新登录", http.StatusBadRequest)
		return
	}
	a.mu.Unlock()

	if !totp.Validate(code, ps.secret) {
		w.Write([]byte(setup2FAPage(a.basePath, setupToken, ps.qr, ps.secret, "验证码无效，请重试")))
		return
	}
	a.mu.Lock()
	delete(a.pendingSetups, setupToken)
	a.mu.Unlock()

	ctx := context.Background()
	if err := a.store.SetTOTPSecret(ctx, ps.username, ps.secret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.establishSession(w, r, a.clientIP(r))
}

func (a *Auth) TOTPResetHandler(w http.ResponseWriter, r *http.Request) {
	// Logged-in user resets 2FA — verify password, generate new secret, clear old one
	r.ParseForm()
	pass := r.FormValue("pass")
	if !a.store.VerifyPassword(context.Background(), a.username, pass) {
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

func setup2FAPage(basePath, setupToken, qrData, secret string, errMsg ...string) string {
	errText := ""
	errClass := "hidden"
	if len(errMsg) > 0 && errMsg[0] != "" {
		errText = errMsg[0]
		errClass = ""
	}
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSSH Terminal — 2FA Setup</title>
<style>
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:#0c0c0c;color:#33ff33;font-family:"Consolas","Menlo","Monaco","Courier New",monospace;display:flex;align-items:center;justify-content:center}

.term{border:1px solid #1a3a1a;border-radius:8px;width:580px;overflow:hidden;box-shadow:0 0 40px rgba(51,255,51,.04)}
.term-bar{background:#1a1a1a;padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #1a3a1a}
.dot{width:10px;height:10px;border-radius:50%}
.dot.r{background:#ff5f56}
.dot.y{background:#ffbd2e}
.dot.g{background:#27c93f}
.term-title{font-size:12px;color:#666;margin-left:8px}

.term-body{padding:28px 32px 32px;text-align:center}

.banner{font-size:13px;line-height:1.6;margin-bottom:20px;color:#33ff33;text-align:left}
.banner .dim{color:#1a8c1a}

.qr-wrap{background:#fff;border-radius:6px;padding:10px;display:inline-block;margin-bottom:20px}
.qr{width:170px;height:170px;display:block}

.prompt{margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:0}
.prompt .prefix{color:#1a8c1a;font-size:14px;white-space:pre}
.prompt input{background:transparent;border:none;color:#33ff33;font-family:inherit;font-size:14px;outline:none;padding:4px 0;caret-color:#33ff33;max-width:160px;letter-spacing:4px;text-align:center}
.prompt input::placeholder{color:#1a4a1a}

.btn{margin-top:18px;padding:8px 20px;background:transparent;border:1px solid #33ff33;color:#33ff33;font-family:inherit;font-size:13px;cursor:pointer;transition:background .2s}
.btn:hover{background:rgba(51,255,51,.08)}
.btn:active{background:rgba(51,255,51,.15)}

.error{margin-top:16px;padding:6px 0;font-size:13px;color:#ff5555;border-top:1px solid rgba(255,85,85,.2)}
.error.hidden{display:none}

.tip{font-size:11px;color:#1a4a1a;margin-top:18px;line-height:1.6;text-align:left}
</style>
</head>
<body>
<div class="term">
  <div class="term-bar">
    <div class="dot r"></div>
    <div class="dot y"></div>
    <div class="dot g"></div>
    <span class="term-title">admin@webssh — 2fa-setup</span>
  </div>
  <div class="term-body">
    <div class="banner">
      two-factor authentication setup<br>
      <span class="dim">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>
    </div>
    <div class="qr-wrap">
      <img class="qr" src="` + qrData + `" alt="QR Code">
    </div>
    <form method="post" action="` + basePath + `/complete-2fa-setup" autocomplete="off" style="text-align:center">
      <input type="hidden" name="setup_token" value="` + setupToken + `">
      <div class="prompt" style="justify-content:center">
        <span class="prefix">verify: </span>
        <input type="text" name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="off" autofocus placeholder="000000" spellcheck="false">
      </div>
      <button class="btn" type="submit">[ 绑定 ]</button>
      <div class="error ` + errClass + `">` + errText + `</div>
    </form>
    <div class="tip">» scan QR code with Authenticator, then enter the 6-digit code</div>
  </div>
</div>
</body>
</html>`
}

func (a *Auth) TOTPLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, a.basePath+"/login", http.StatusFound)
			return
		}
		a.mu.RLock()
		_, ok := a.pendingLogins[token]
		a.mu.RUnlock()
		if !ok {
			http.Redirect(w, r, a.basePath+"/login", http.StatusFound)
			return
		}
		w.Write([]byte(login2FAPage(a.basePath, "", token)))
		return
	}

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	token := r.FormValue("login_token")
	code := r.FormValue("totp_code")
	ip := a.clientIP(r)

	if a.rateLimitCheck(w, ip) {
		return
	}

	a.mu.Lock()
	pl, ok := a.pendingLogins[token]
	if !ok || time.Since(pl.created) > 10*time.Minute {
		if ok {
			delete(a.pendingLogins, token)
		}
		a.mu.Unlock()
		w.Write([]byte(login2FAPage(a.basePath, "双因素认证会话已过期，请重新登录", "")))
		return
	}
	a.mu.Unlock()

	if code == "" {
		w.Write([]byte(login2FAPage(a.basePath, "请输入验证码", token)))
		return
	}

	secret, err := a.store.GetTOTPSecret(context.Background(), pl.username)
	if err != nil || !totp.Validate(code, secret) {
		w.Write([]byte(login2FAPage(a.basePath, "验证码无效", token)))
		return
	}

	a.mu.Lock()
	delete(a.pendingLogins, token)
	delete(a.rateLimit, ip)
	a.mu.Unlock()
	a.establishSession(w, r, ip)
}

func login2FAPage(basePath, errMsg, token string) string {
	errClass := "hidden"
	if errMsg != "" {
		errClass = ""
	}
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSSH Terminal — 2FA</title>
<style>
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:#0c0c0c;color:#33ff33;font-family:"Consolas","Menlo","Monaco","Courier New",monospace;display:flex;align-items:center;justify-content:center}

.term{border:1px solid #1a3a1a;border-radius:8px;width:580px;overflow:hidden;box-shadow:0 0 40px rgba(51,255,51,.04)}
.term-bar{background:#1a1a1a;padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #1a3a1a}
.dot{width:10px;height:10px;border-radius:50%}
.dot.r{background:#ff5f56}
.dot.y{background:#ffbd2e}
.dot.g{background:#27c93f}
.term-title{font-size:12px;color:#666;margin-left:8px}

.term-body{padding:28px 32px 32px}

.banner{font-size:13px;line-height:1.6;margin-bottom:24px;color:#33ff33}
.banner .dim{color:#1a8c1a}

.prompt{margin-bottom:6px;display:flex;align-items:center;gap:0}
.prompt .prefix{color:#1a8c1a;font-size:14px;white-space:pre}
.prompt input{background:transparent;border:none;color:#33ff33;font-family:inherit;font-size:14px;outline:none;flex:1;padding:4px 0;caret-color:#33ff33;max-width:200px}
.prompt input::placeholder{color:#1a4a1a}

.btn{margin-top:18px;padding:8px 20px;background:transparent;border:1px solid #33ff33;color:#33ff33;font-family:inherit;font-size:13px;cursor:pointer;transition:background .2s}
.btn:hover{background:rgba(51,255,51,.08)}
.btn:active{background:rgba(51,255,51,.15)}

.error{margin-top:16px;padding:6px 0;font-size:13px;color:#ff5555;border-top:1px solid rgba(255,85,85,.2)}
.error.hidden{display:none}

.cursor{display:inline-block;width:8px;height:15px;background:#33ff33;animation:blink 1s step-end infinite;margin-left:4px;vertical-align:middle}
</style>
</head>
<body>
<div class="term">
  <div class="term-bar">
    <div class="dot r"></div>
    <div class="dot y"></div>
    <div class="dot g"></div>
    <span class="term-title">admin@webssh — 2fa</span>
  </div>
  <div class="term-body">
    <div class="banner">
      two-factor authentication required<br>
      <span class="dim">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>
    </div>
    <form method="post" action="` + basePath + `/login/2fa" autocomplete="off">
      <input type="hidden" name="login_token" value="` + token + `">
      <div class="prompt">
        <span class="prefix">2fa code: </span>
        <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" autofocus placeholder="000000" spellcheck="false" style="max-width:160px;letter-spacing:4px">
      </div>
      <button class="btn" type="submit">[ 验证 ]</button>
      <div class="error ` + errClass + `">` + errMsg + `</div>
    </form>
  </div>
</div>
</body>
</html>`
}
