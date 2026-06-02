package sshterm

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// No origin header = direct browser/API call, allow
			return true
		}
		// Require same-origin for WebSocket connections
		scheme := "http://"
		if r.TLS != nil {
			scheme = "https://"
		}
		expected := scheme + r.Host
		return origin == expected
	},
}

type ConnectParams struct {
	SessionID  string `json:"sessionId"`
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

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
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

	if params.Port == 0 {
		params.Port = 22
	}

	sshClient, cfg, err := dialSSH(&params)
	if err != nil {
		log.Printf("SSH dial failed: %v", err)
		conn.WriteMessage(websocket.TextMessage, []byte("SSH connection failed: "+err.Error()))
		conn.Close()
		return
	}

	session, err := sshClient.NewSession()
	if err != nil {
		log.Printf("SSH session failed: %v", err)
		conn.WriteMessage(websocket.TextMessage, []byte("SSH session failed: "+err.Error()))
		sshClient.Close()
		conn.Close()
		return
	}

	Manager.Create(params.SessionID, sshClient, cfg, params.Host, params.Port, params.Username)

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

	// Set PROMPT_COMMAND via SSH env (works if server accepts PermitUserEnvironment)
	// This is the most reliable method — variable is set before shell starts
	session.Setenv("PROMPT_COMMAND", `printf "\033]7;file://$HOSTNAME$PWD\033\\"`)

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

	// Inject PROMPT_COMMAND via stdin after shell startup output (MOTD, banner) has been sent
	// Write from stdout reader goroutine so the export line appears after the login banner
	var injectedOnce sync.Once
	writePROMPT := func() {
		injectedOnce.Do(func() {
			stdin.Write([]byte("export PROMPT_COMMAND='printf \"\\033]7;file://$HOSTNAME$PWD\\033\\\\\"'\n"))
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
			conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			if first {
				first = false
				// Wait a short moment after first output for MOTD to display
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
			conn.WriteMessage(websocket.BinaryMessage, buf[:n])
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

func dialSSH(params *ConnectParams) (*ssh.Client, *ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            params.Username,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	if params.Password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(params.Password)}
	} else if params.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(params.PrivateKey))
		if err != nil {
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}

	addr := fmt.Sprintf("%s:%d", params.Host, params.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	return client, config, nil
}
