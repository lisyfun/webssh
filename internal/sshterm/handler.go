package sshterm

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type ConnectParams struct {
	SessionID  string
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
}

func DialSSH(params *ConnectParams) (*ssh.Client, *ssh.ClientConfig, error) {
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

// DetectShell runs a quick exec to read the remote login shell ($SHELL).
// Returns the shell basename (e.g. "bash", "zsh", "fish") or "" if it
// cannot be determined. Used to inject the correct CWD-reporting hook.
func DetectShell(client *ssh.Client) string {
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

// CWDReportSnippet returns a one-line shell command that installs an OSC 7
// hook so the terminal emits its working directory after every prompt. The
// frontend ignores the host part of the OSC 7 URI, so we emit file://$PWD.
//
// The bash form (export PROMPT_COMMAND) is also valid syntax in zsh/sh/dash/
// ksh — it just has no effect outside bash — so only fish, whose syntax is
// incompatible, needs special routing. zsh gets a proper precmd hook so it
// tracks cd too.
func CWDReportSnippet(shell string) string {
	switch shell {
	case "fish":
		return "function __webssh_cwd --on-event fish_prompt; printf '\\033]7;file://%s\\033\\\\' \"$PWD\"; end\n"
	case "zsh":
		return "__webssh_cwd(){ printf '\\033]7;file://%s\\033\\\\' \"$PWD\" }; precmd_functions+=(__webssh_cwd)\n"
	default:
		return "export PROMPT_COMMAND='printf \"\\033]7;file://%s\\033\\\\\" \"$PWD\"'\n"
	}
}
