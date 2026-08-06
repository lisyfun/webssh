package sshterm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// detectShell runs a quick exec to read the remote login shell ($SHELL).
// Returns the shell basename (e.g. "bash", "zsh", "fish") or "" if it
// cannot be determined. Used to inject the correct CWD-reporting hook.
func detectShell(client *ssh.Client) string {
	sess, err := client.NewSession()
	if err != nil {
		return ""
	}
	defer sess.Close()
	out, err := sess.Output(`echo "$SHELL"`)
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(string(out))
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}

// cwdReportSnippet returns a one-line shell command that installs an OSC 7
// hook so the terminal emits its working directory after every prompt. The
// frontend ignores the host part of the OSC 7 URI, so we emit file://$PWD.
//
// The bash form (export PROMPT_COMMAND) is also valid syntax in zsh/sh/dash/
// ksh — it just has no effect outside bash — so only fish, whose syntax is
// incompatible, needs special routing. zsh gets a proper precmd hook so it
// tracks cd too.
func cwdReportSnippet(shell string) string {
	switch shell {
	case "fish":
		// --on-variable PWD fires immediately on any cd (real-time);
		// fish_prompt covers the initial directory after connect.
		return "function __webssh_cwd --on-variable PWD --on-event fish_prompt; printf '\\033]7;file://%s\\033\\\\' \"$PWD\"; end"
	case "zsh":
		// chpwd fires immediately after cd; precmd covers prompt-time
		// directory changes (pushd, manual chdir via other means).
		return "__webssh_cwd(){ printf '\\033]7;file://%s\\033\\\\' \"$PWD\" }; chpwd_functions+=(__webssh_cwd); precmd_functions+=(__webssh_cwd)"
	default:
		// bash 4.4+: PS0 must NOT hold a command — bash expands and *displays*
		// PS0's value (prompt-style expansion: \033 octal, $PWD, \\) before
		// executing it, so a printf command leaks visible text. Instead PS0
		// holds the raw OSC 7 sequence itself, which expands to pure control
		// text. PROMPT_COMMAND stays the compatible fallback (plain command,
		// no prompt expansion).
		return "export PS0='\\033]7;file://$PWD\\033\\\\'; export PROMPT_COMMAND='printf \"\\033]7;file://%s\\033\\\\\" \"$PWD\"'"
	}
}

type DecryptFunc func(r *http.Request, value string) (string, error)
type ServerResolver func(id string) (*ConnectParams, error)

type ConnectParams struct {
	SessionID  string `json:"sessionId"`
	ServerID   string `json:"serverId"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase,omitempty"`
	Cols       int    `json:"cols"`
	Rows       int    `json:"rows"`
}

type ResizeMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:   4096,
	WriteBufferSize:  4096,
	HandshakeTimeout: 10 * time.Second,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false
		}
		scheme := "http://"
		if r.TLS != nil {
			scheme = "https://"
		}
		return origin == scheme+r.Host
	},
}

func HandleWebSocket(decrypt DecryptFunc) http.HandlerFunc {
	return HandleWebSocketWithResolver(nil, decrypt)
}

func HandleWebSocketWithResolver(resolve ServerResolver, decrypt DecryptFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade failed: %v", err)
			return
		}

		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("read connect params failed: %v", err)
			conn.Close()
			return
		}

		var params ConnectParams
		if err := json.Unmarshal(msg, &params); err != nil {
			log.Printf("invalid connect params: %v", err)
			conn.Close()
			return
		}

		if resolve != nil && params.ServerID != "" {
			serverParams, err := resolve(params.ServerID)
			if err != nil {
				log.Printf("resolve server failed: %v", err)
				_ = conn.WriteMessage(websocket.TextMessage, []byte("SSH connection failed: server not found"))
				conn.Close()
				return
			}
			// 保存前端发送的终端尺寸，resolve 返回的 serverParams 不含这些字段
			cols, rows := params.Cols, params.Rows
			serverParams.SessionID = params.SessionID
			serverParams.ServerID = params.ServerID
			serverParams.Passphrase = params.Passphrase
			params = *serverParams
			params.Cols, params.Rows = cols, rows
		} else if decrypt != nil {
			if params.Password, err = decrypt(r, params.Password); err != nil {
				_ = conn.WriteMessage(websocket.TextMessage, []byte("SSH connection failed: invalid encrypted password"))
				conn.Close()
				return
			}
			if params.PrivateKey, err = decrypt(r, params.PrivateKey); err != nil {
				_ = conn.WriteMessage(websocket.TextMessage, []byte("SSH connection failed: invalid encrypted private key"))
				conn.Close()
				return
			}
		}
		if decrypt != nil && params.Passphrase != "" {
			if params.Passphrase, err = decrypt(r, params.Passphrase); err != nil {
				_ = conn.WriteMessage(websocket.TextMessage, []byte("SSH connection failed: invalid encrypted passphrase"))
				conn.Close()
				return
			}
		}

		if params.Port == 0 {
			params.Port = 22
		}
		if params.SessionID == "" || params.Host == "" || params.Username == "" {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("SSH connection failed: missing connection parameters"))
			conn.Close()
			return
		}

		var writeMu sync.Mutex
		writeText := func(msg string) {
			writeMu.Lock()
			defer writeMu.Unlock()
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(msg))
		}
		writeBinary := func(data []byte) bool {
			writeMu.Lock()
			defer writeMu.Unlock()
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			return conn.WriteMessage(websocket.BinaryMessage, data) == nil
		}

		sshClient, cfg, err := dialSSH(&params)
		if err != nil {
			log.Printf("SSH dial failed: %v", err)
			writeText("SSH connection failed: " + err.Error())
			conn.Close()
			return
		}

		session, err := sshClient.NewSession()
		if err != nil {
			log.Printf("SSH session failed: %v", err)
			writeText("SSH session failed: " + err.Error())
			sshClient.Close()
			conn.Close()
			return
		}

		// SSH 保活: 每 30s 发 keepalive，防止 NAT/防火墙超时断开
		done := make(chan struct{})
		var closeOnce sync.Once
		closeAll := func() {
			closeOnce.Do(func() {
				close(done)
				session.Close()
				sshClient.Close()
				Manager.Remove(params.SessionID)
				conn.Close()
			})
		}
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
					if err != nil {
						writeText("SSH connection closed: " + err.Error())
						closeAll()
						return
					}
				}
			}
		}()

		stdin, err := session.StdinPipe()
		if err != nil {
			log.Printf("stdin pipe failed: %v", err)
			closeAll()
			return
		}

		stdout, err := session.StdoutPipe()
		if err != nil {
			log.Printf("stdout pipe failed: %v", err)
			closeAll()
			return
		}

		stderr, err := session.StderrPipe()
		if err != nil {
			log.Printf("stderr pipe failed: %v", err)
			closeAll()
			return
		}

		// Detect the remote login shell and try to set PROMPT_COMMAND via
		// SSH env request before the shell starts (silent, no PTY echo).
		// bash/zsh/sh/ksh/dash all support PROMPT_COMMAND; fish does not.
		// If the SSH server rejects Setenv (e.g., AcceptEnv restriction),
		// fall back to stdin injection with stty -echo.
		shell := detectShell(sshClient)
		cwdSnippet := cwdReportSnippet(shell)
		cwdInjected := false
		switch shell {
		case "", "bash", "sh", "ksh", "dash":
			// Env-var injection works for bash-family shells: PROMPT_COMMAND
			// (compat) is imported and run as a command; PS0 (real-time on
			// bash 4.4+) holds the raw OSC 7 sequence, which bash expands and
			// displays as pure control text. zsh/fish have no env var that
			// can install hooks, so they always use stdin injection below.
			cwdHook := "printf '\\033]7;file://%s\\033\\\\' \"$PWD\""
			ps0Hook := "\\033]7;file://$PWD\\033\\\\"
			if err := session.Setenv("PROMPT_COMMAND", cwdHook); err == nil {
				session.Setenv("PS0", ps0Hook) // failure harmless (old bash / restricted server)
				cwdInjected = true
			}
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,   // 回显输入
			ssh.ICRNL:         1,   // 输入 CR → NL
			ssh.OPOST:         1,   // 启用输出处理（ONLCR 等生效的前提）
			ssh.ONLCR:         1,   // 输出 NL → CR+NL，修复方向键换行错位
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		ptyCols := params.Cols
		if ptyCols <= 0 {
			ptyCols = 80
		}
		ptyRows := params.Rows
		if ptyRows <= 0 {
			ptyRows = 40
		}
		if err := session.RequestPty("xterm-256color", ptyRows, ptyCols, modes); err != nil {
			log.Printf("request pty failed: %v", err)
			closeAll()
			return
		}

		if err := session.Shell(); err != nil {
			log.Printf("shell failed: %v", err)
			closeAll()
			return
		}

		// Register the session only after the shell is fully up. Doing it
		// earlier would leave a dead entry (holding a closed client) in the
		// manager if any of the pipe/PTY/Shell steps above failed, since the
		// cleanup defer below is not yet in scope at those points.
		Manager.Create(params.SessionID, sshClient, cfg, params.Host, params.Port, params.Username)

		var injectedOnce sync.Once
		lastInput := time.Now() // idle-gate CWD hook injection so it never lands inside vi etc.
		writePROMPT := func() {
			if cwdInjected {
				return
			}
			injectedOnce.Do(func() {
				// Single combined line so only one prompt appears;
				// the whole line is filtered from visible output.
				stdin.Write([]byte("stty -echo 2>/dev/null; " + cwdSnippet + "; stty echo 2>/dev/null\n"))
			})
		}

		go func() {
			buf := make([]byte, 4096)
			first := true
			var inAlt atomic.Bool // full-screen apps (vi/less/top) switch to the alternate screen
			filterCwdEcho := func(data []byte) []byte {
				if cwdInjected {
					return data
				}
				lines := strings.SplitAfter(string(data), "\n")
				var out strings.Builder
				for _, line := range lines {
					if strings.Contains(line, "stty -echo") ||
						strings.Contains(line, "stty echo") ||
						strings.Contains(line, "PS0=") ||
						strings.Contains(line, "PROMPT_COMMAND=") ||
						strings.Contains(line, "chpwd_functions+=") ||
						strings.Contains(line, "__webssh_cwd") ||
						strings.Contains(line, "precmd_functions+=") {
						continue
					}
					out.WriteString(line)
				}
				return []byte(out.String())
			}
			for {
				n, err := stdout.Read(buf)
				if err != nil {
					break
				}
				data := buf[:n]
				// Track alternate-screen entry/exit so the CWD hook is never
				// written while a full-screen program owns the terminal.
				if bytes.Contains(data, []byte("\x1b[?1049h")) {
					inAlt.Store(true)
				}
				if bytes.Contains(data, []byte("\x1b[?1049l")) {
					inAlt.Store(false)
				}
				data = filterCwdEcho(buf[:n])
				if len(data) > 0 && !writeBinary(data) {
					break
				}
				if first {
					first = false
					go func() {
						// Inject only while the user is idle AND no full-screen
						// program owns the terminal (vi/less/top switch to the
						// alternate screen; writing the hook there garbles the
						// session — feels like vi cannot be quit).
						// ponytail: fixed 30s budget.
						for i := 0; i < 60; i++ {
							if time.Since(lastInput) > 500*time.Millisecond && !inAlt.Load() {
								writePROMPT()
								return
							}
							time.Sleep(500 * time.Millisecond)
						}
					}()
				}
			}
		}()

		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stderr.Read(buf)
				if err != nil {
					break
				}
				if !writeBinary(buf[:n]) {
					break
				}
			}
		}()
		defer closeAll()

		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				break
			}

			if msgType == websocket.BinaryMessage {
				lastInput = time.Now()
				stdin.Write(data)
			} else if msgType == websocket.TextMessage {
				var resize ResizeMsg
				if err := json.Unmarshal(data, &resize); err != nil {
					continue
				}
				if resize.Type == "resize" {
					session.WindowChange(resize.Rows, resize.Cols)
				}
			}
		}
	}
}

func dialSSH(params *ConnectParams) (*ssh.Client, *ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            params.Username,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
		// Widen the negotiated algorithms so we can reach older servers and
		// network gear (legacy switches, embedded Linux) that only speak CBC
		// ciphers and SHA-1 key exchange. OpenSSH's CLI still offers many of
		// these for compatibility; the Go library defaults to a much narrower,
		// modern-only set, which is the usual reason a host that connects from
		// the terminal fails here.
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-cbc", "3des-cbc",
			},
			KeyExchanges: []string{
				"mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
				"diffie-hellman-group-exchange-sha1",
			},
		},
		HostKeyAlgorithms: []string{
			"ssh-ed25519",
			"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
			"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
		},
	}

	var methods []ssh.AuthMethod
	if params.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if params.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(params.PrivateKey), []byte(params.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(params.PrivateKey))
		}
		if err != nil {
			if _, ok := err.(*ssh.PassphraseMissingError); ok {
				return nil, nil, fmt.Errorf("私钥已加密，请输入密码短语")
			}
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if params.Password != "" {
		// Offer both "password" and "keyboard-interactive". Many servers
		// (PAM-backed, or with PasswordAuthentication disabled but
		// KbdInteractiveAuthentication enabled) only accept the latter, so a
		// correct password is rejected if we offer "password" alone. The CLI
		// tries both automatically; we mirror that by answering the
		// interactive challenge with the same password.
		methods = append(methods, ssh.Password(params.Password))
		methods = append(methods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = params.Password
				}
				return answers, nil
			}))
	}
	if len(methods) == 0 {
		return nil, nil, fmt.Errorf("missing SSH auth credentials")
	}
	config.Auth = methods

	addr := fmt.Sprintf("%s:%d", params.Host, params.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	return client, config, nil
}
