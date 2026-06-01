package sshterm

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Session struct {
	ID         string
	Client     *ssh.Client
	CreatedAt  time.Time
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string
}

var sftpServerPaths = []string{
	"sftp-server",
	"/usr/lib/openssh/sftp-server",
	"/usr/libexec/sftp-server",
	"/usr/lib/ssh/sftp-server",
	"/usr/libexec/openssh/sftp-server",
}

// execSFTP tries all sftp-server paths and returns the first successful client.
func execSFTP(client *ssh.Client) (*sftp.Client, error) {
	var lastErr error
	for _, cmd := range sftpServerPaths {
		sc, err := execSFTPCmd(client, cmd)
		if err == nil {
			return sc, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all sftp-server paths failed: %w", lastErr)
}

func execSFTPCmd(client *ssh.Client, cmd string) (*sftp.Client, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	pw, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	pr, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, err
	}

	if err := session.Start(cmd); err != nil {
		session.Close()
		return nil, err
	}

	sc, err := newSFTPClient(pr, pw)
	if err != nil {
		pw.Close()
		session.Close()
		return nil, err
	}
	return sc, nil
}

func (s *Session) DialSFTP() (*sftp.Client, error) {
	var subErr error
	{
		sc, err := trySubsystem(s.Client)
		if err == nil {
			return sc, nil
		}
		subErr = err
	}

	var execErr error
	{
		sc, err := execSFTP(s.Client)
		if err == nil {
			return sc, nil
		}
		execErr = err
	}

	log.Printf("DialSFTP: both failed (sub: %v; exec: %v), trying fresh connection", subErr, execErr)
	sc, err := s.sftpViaFreshConn()
	if err != nil {
		return nil, fmt.Errorf("subsystem: %w; exec: %w; fresh: %w", subErr, execErr, err)
	}
	return sc, nil
}

func (s *Session) sftpViaFreshConn() (*sftp.Client, error) {
	config := &ssh.ClientConfig{
		User:            s.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	if s.Password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(s.Password)}
	} else if s.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(s.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		return nil, fmt.Errorf("no auth method available")
	}

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("fresh dial: %w", err)
	}

	sc, err := trySubsystem(client)
	if err == nil {
		return sc, nil
	}
	subErr := err

	sc, err = execSFTP(client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("fresh subsystem: %w; exec: %w", subErr, err)
	}
	return sc, nil
}

func trySubsystem(client *ssh.Client) (*sftp.Client, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	if err := session.RequestSubsystem("sftp"); err != nil {
		session.Close()
		return nil, err
	}
	pw, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	pr, err := session.StdoutPipe()
	if err != nil {
		pw.Close()
		session.Close()
		return nil, err
	}

	sc, err := newSFTPClient(pr, pw)
	if err != nil {
		pw.Close()
		session.Close()
		return nil, err
	}
	return sc, nil
}

// newSFTPClient wraps pr with a preamble filter that discards any
// shell rc output (like "hello world") before the first valid SFTP
// packet, then creates an sftp.Client.
func newSFTPClient(pr io.Reader, pw io.WriteCloser) (*sftp.Client, error) {
	r := &preambleReader{rd: pr}
	return sftp.NewClientPipe(r, pw)
}

// preambleReader drops everything before the first valid SFTP packet
// header (4-byte uint32 length <= 32768). This handles shell rc files
// that output text to stdout during SFTP initialization.
type preambleReader struct {
	rd    io.Reader
	buf   []byte
	ready bool
	discarded int
}

func (r *preambleReader) Read(p []byte) (int, error) {
	if !r.ready {
		r.buf = make([]byte, 0, 4096)
		tmp := make([]byte, 256)
		for {
			n, err := r.rd.Read(tmp)
			if err != nil {
				return 0, err
			}
			r.buf = append(r.buf, tmp[:n]...)

			// Scan for valid SFTP packet start
			for i := 0; i < len(r.buf)-3; i++ {
				length := binary.BigEndian.Uint32(r.buf[i:])
				if length <= 32768 {
					r.discarded = i
					r.ready = true
					if r.discarded > 0 {
						log.Printf("preambleReader: discarded %d bytes before valid SFTP packet", r.discarded)
						log.Printf("preambleReader: discarded content: %x", r.buf[:r.discarded])
					}
					r.buf = r.buf[i:]
					goto done
				}
			}
		}
	}

done:
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	return r.rd.Read(p)
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var Manager = &SessionManager{
	sessions: make(map[string]*Session),
}

func (sm *SessionManager) Create(id string, client *ssh.Client, host string, port int, username string, password string, privateKey string) *Session {
	s := &Session{
		ID:         id,
		Client:     client,
		CreatedAt:  time.Now(),
		Host:       host,
		Port:       port,
		Username:   username,
		Password:   password,
		PrivateKey: privateKey,
	}
	sm.mu.Lock()
	sm.sessions[id] = s
	sm.mu.Unlock()
	return s
}

func (sm *SessionManager) Get(id string) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return s, nil
}

func (sm *SessionManager) Remove(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[id]; ok {
		s.Client.Close()
		delete(sm.sessions, id)
	}
}
