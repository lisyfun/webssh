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

	a.establishSession(w, r, clientIP(r))
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
	.error{margin-top:14px;padding:8px 12px;border-radius:6px;background:rgba(255,123,114,0.08);border:1px solid rgba(255,123,114,0.2);color:var(--danger);font-size:12px}
	.error.hidden{display:none}
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
  <form method="post" action="` + basePath + `/complete-2fa-setup">
    <input type="hidden" name="setup_token" value="` + setupToken + `">
    <div class="form-group">
      <label>六位验证码</label>
      <input type="text" name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="off" autofocus placeholder="000 000">
	    </div>
	    <button class="btn" type="submit">验证并登录</button>
	    <div class="error ` + errClass + `">` + errText + `</div>
	  </form>
  <div class="tip">首次绑定，扫码或手动输入密钥后输入 App 中的 6 位数字即可。</div>
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
	ip := clientIP(r)

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
<title>WebSSH - 双因素认证</title>
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
h1{font-size:18px;font-weight:600;text-align:center;margin-bottom:4px;letter-spacing:-0.2px}
.sub{font-size:13px;color:var(--muted);text-align:center;margin-bottom:28px}

.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:11px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;font-weight:500}
.form-group input{width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;outline:none;text-align:center;letter-spacing:5px;transition:border-color .2s,box-shadow .2s}
.form-group input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(74,140,255,0.15)}
.form-group input::placeholder{color:#484f58;letter-spacing:normal}

.btn{width:100%;padding:10px;border:none;border-radius:6px;background:var(--accent);color:#fff;font-size:14px;font-weight:500;cursor:pointer;transition:background .2s,transform .1s}
.btn:hover{background:var(--accent-hover)}
.btn:active{transform:scale(0.98)}

.error{margin-top:14px;padding:8px 12px;border-radius:6px;background:var(--danger-bg);border:1px solid rgba(255,123,114,0.2);color:var(--danger);font-size:12px;text-align:center}
.error.hidden{display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">&gt;_</div>
  <h1>双因素认证</h1>
  <div class="sub">请输入认证器中的 6 位动态码</div>
  <form method="post" action="` + basePath + `/login/2fa">
    <input type="hidden" name="login_token" value="` + token + `">
    <div class="form-group">
      <label>双因素认证码</label>
      <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" autofocus placeholder="000 000">
    </div>
    <button class="btn" type="submit">验证</button>
    <div class="error ` + errClass + `">` + errMsg + `</div>
  </form>
</div>
</body>
</html>`
}
