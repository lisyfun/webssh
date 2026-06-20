package sshterm

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// hostKeyStore implements Trust On First Use (TOFU) for SSH host keys.
// On first connection to a host, the key is accepted and recorded; on
// subsequent connections, the key is verified against the recorded one.
// A mismatch is rejected (potential MITM attack).
//
// Keys are held in an in-memory cache and, when a persister is registered
// (see SetHostKeyPersister), also written through to durable storage so the
// trust survives application restarts.
var hostKeyStore sync.Map

// HostKeyPersister durably stores TOFU host keys across restarts. addr is
// "host:port"; keyB64 is base64 of the wire-format public key.
type HostKeyPersister interface {
	LoadHostKey(addr string) (string, error)
	StoreHostKey(addr, keyB64 string) error
}

var hostKeyPersister HostKeyPersister

// SetHostKeyPersister registers durable storage for TOFU host keys. Call once
// at startup before any connections are made.
func SetHostKeyPersister(p HostKeyPersister) {
	hostKeyPersister = p
}

func ForgetHostKey(addr string) {
	hostKeyStore.Delete(addr)
}

func hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	addr := net.JoinHostPort(hostname, "22")
	if _, port, err := net.SplitHostPort(hostname); err == nil && port != "" {
		addr = hostname
	}
	keyB64 := base64.StdEncoding.EncodeToString(key.Marshal())

	// 1. Memory cache (fast path, also covers the no-persister case).
	if stored, loaded := hostKeyStore.Load(addr); loaded {
		return verifyHostKey(addr, stored.(string), keyB64)
	}

	// 2. Durable store, if configured — promote into the cache on hit.
	if hostKeyPersister != nil {
		if storedB64, err := hostKeyPersister.LoadHostKey(addr); err == nil && storedB64 != "" {
			hostKeyStore.Store(addr, storedB64)
			return verifyHostKey(addr, storedB64, keyB64)
		}
	}

	// 3. First contact (TOFU): accept and record in both cache and store.
	// LoadOrStore guards against a concurrent first-connect to the same host.
	if existing, loaded := hostKeyStore.LoadOrStore(addr, keyB64); loaded {
		return verifyHostKey(addr, existing.(string), keyB64)
	}
	log.Printf("TOFU: accepted host key for %s (%s)", addr, ssh.FingerprintSHA256(key))
	if hostKeyPersister != nil {
		if err := hostKeyPersister.StoreHostKey(addr, keyB64); err != nil {
			log.Printf("warning: failed to persist host key for %s: %v", addr, err)
		}
	}
	return nil
}

func verifyHostKey(addr, storedB64, gotB64 string) error {
	if storedB64 != gotB64 {
		return fmt.Errorf("host key mismatch for %s (possible MITM); "+
			"remove the saved key to re-trust this host", addr)
	}
	return nil
}

type Session struct {
	ID           string
	Client       *ssh.Client
	ClientConfig *ssh.ClientConfig
	CreatedAt    time.Time
	Host         string
	Port         int
	Username     string
	Stdin        io.WriteCloser
	SSHSession   *ssh.Session

	sftpMu     sync.Mutex
	sftpClient *sftp.Client
}

// SFTP returns a per-session SFTP client, reused across file-browser
// requests to avoid paying the subsystem handshake on every call.
// The client is built lazily on first use.
func (s *Session) SFTP() (*sftp.Client, error) {
	s.sftpMu.Lock()
	defer s.sftpMu.Unlock()
	if s.sftpClient != nil {
		return s.sftpClient, nil
	}
	sc, err := s.DialSFTP()
	if err != nil {
		return nil, err
	}
	s.sftpClient = sc
	return sc, nil
}

// invalidateSFTP closes and drops the cached SFTP client so the next
// SFTP call rebuilds it. Call this when an operation fails due to a
// dead connection.
func (s *Session) invalidateSFTP() {
	s.sftpMu.Lock()
	defer s.sftpMu.Unlock()
	if s.sftpClient != nil {
		s.sftpClient.Close()
		s.sftpClient = nil
	}
}

// isConnError reports whether err indicates the underlying SFTP/SSH
// connection is dead (as opposed to a normal filesystem error like
// "file not found"), meaning the cached client should be rebuilt.
func isConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{"EOF", "connection lost", "broken pipe", "use of closed", "connection reset"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// WithSFTP runs fn with the session's cached SFTP client, rebuilding the
// client once and retrying if the operation fails due to a dropped
// connection. Use only for non-streaming operations that are safe to
// retry.
func (s *Session) WithSFTP(fn func(*sftp.Client) error) error {
	sc, err := s.SFTP()
	if err != nil {
		return err
	}
	err = fn(sc)
	if isConnError(err) {
		s.invalidateSFTP()
		sc, err2 := s.SFTP()
		if err2 != nil {
			return err2
		}
		err = fn(sc)
	}
	return err
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
	if s.ClientConfig == nil {
		return nil, fmt.Errorf("no client config available")
	}

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	client, err := ssh.Dial("tcp", addr, s.ClientConfig)
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
	rd        io.Reader
	buf       []byte
	ready     bool
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

func (sm *SessionManager) Create(id string, client *ssh.Client, cfg *ssh.ClientConfig, host string, port int, username string) *Session {
	s := &Session{
		ID:           id,
		Client:       client,
		ClientConfig: cfg,
		CreatedAt:    time.Now(),
		Host:         host,
		Port:         port,
		Username:     username,
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
		s.invalidateSFTP()
		s.Client.Close()
		delete(sm.sessions, id)
	}
}
