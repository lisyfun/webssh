package sshterm

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
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
		return "function __webssh_cwd --on-event fish_prompt; printf '\\033]7;file://%s\\033\\\\' \"$PWD\"; end\n"
	case "zsh":
		return "__webssh_cwd(){ printf '\\033]7;file://%s\\033\\\\' \"$PWD\" }; precmd_functions+=(__webssh_cwd)\n"
	default:
		return "export PROMPT_COMMAND='printf \"\\033]7;file://%s\\033\\\\\" \"$PWD\"'\n"
	}
}

type DecryptFunc func(r *http.Request, value string) string
type ServerResolver func(id string) (*ConnectParams, error)

type ConnectParams struct {
	SessionID  string `json:"sessionId"`
	ServerID   string `json:"serverId"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"privateKey"`
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
			return true
		}
		scheme := "http://"
		if r.TLS != nil {
			scheme = "https://"
		}
		expected := scheme + r.Host
		return origin == expected
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
			serverParams.SessionID = params.SessionID
			serverParams.ServerID = params.ServerID
			params = *serverParams
		} else if decrypt != nil {
			params.Password = decrypt(r, params.Password)
			params.PrivateKey = decrypt(r, params.PrivateKey)
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

		// SSH 保活: 每 30s 发 keepalive，防止 NAT/防火墙超时断开
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					return
				}
			}
		}()

		session, err := sshClient.NewSession()
		if err != nil {
			log.Printf("SSH session failed: %v", err)
			writeText("SSH session failed: " + err.Error())
			sshClient.Close()
			conn.Close()
			return
		}

		stdin, err := session.StdinPipe()
		if err != nil {
			log.Printf("stdin pipe failed: %v", err)
			session.Close()
			sshClient.Close()
			conn.Close()
			return
		}

		stdout, err := session.StdoutPipe()
		if err != nil {
			log.Printf("stdout pipe failed: %v", err)
			session.Close()
			sshClient.Close()
			conn.Close()
			return
		}

		stderr, err := session.StderrPipe()
		if err != nil {
			log.Printf("stderr pipe failed: %v", err)
			session.Close()
			sshClient.Close()
			conn.Close()
			return
		}

		// Detect the remote login shell so we can inject the correct
		// CWD-reporting hook below. Falls back to the bash form, which is
		// harmless (just inert) in sh/zsh/ksh.
		shell := detectShell(sshClient)
		cwdSnippet := cwdReportSnippet(shell)

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		if err := session.RequestPty("xterm-256color", 40, 80, modes); err != nil {
			log.Printf("request pty failed: %v", err)
			session.Close()
			sshClient.Close()
			conn.Close()
			return
		}

		if err := session.Shell(); err != nil {
			log.Printf("shell failed: %v", err)
			session.Close()
			sshClient.Close()
			conn.Close()
			return
		}

		// Register the session only after the shell is fully up. Doing it
		// earlier would leave a dead entry (holding a closed client) in the
		// manager if any of the pipe/PTY/Shell steps above failed, since the
		// cleanup defer below is not yet in scope at those points.
		Manager.Create(params.SessionID, sshClient, cfg, params.Host, params.Port, params.Username)

		var injectedOnce sync.Once
		writePROMPT := func() {
			injectedOnce.Do(func() {
				stdin.Write([]byte(cwdSnippet))
			})
		}

		go func() {
			buf := make([]byte, 4096)
			first := true
			for {
				n, err := stdout.Read(buf)
				if err != nil {
					break
				}
				if !writeBinary(buf[:n]) {
					break
				}
				if first {
					first = false
					go func() { time.Sleep(200 * time.Millisecond); writePROMPT() }()
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
		defer func() {
			Manager.Remove(params.SessionID)
			conn.Close()
		}()

		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				break
			}

			if msgType == websocket.BinaryMessage {
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
		signer, err := ssh.ParsePrivateKey([]byte(params.PrivateKey))
		if err != nil {
			if _, ok := err.(*ssh.PassphraseMissingError); ok {
				return nil, nil, fmt.Errorf("私钥已加密（带密码短语），暂不支持，请使用未加密的私钥")
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
