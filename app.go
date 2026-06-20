package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	gostatic "runtime"
	"strings"
	"sync"
	"time"

	"webssh/internal/sshterm"
	"webssh/internal/store"

	"github.com/pkg/sftp"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/ssh"
)

type Terminal struct {
	Client     *ssh.Client
	SSHSession *ssh.Session
	Stdin      io.WriteCloser
	done       chan struct{} // closed on cleanup to stop the keepalive goroutine
	doneOnce   sync.Once
}

type App struct {
	ctx       context.Context
	store     *store.Store
	terminals map[string]*Terminal
	mu        sync.Mutex
	maxBodyMB int64
}

type ServerView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	AuthType      string `json:"authType"`
	HasPassword   bool   `json:"hasPassword"`
	HasPrivateKey bool   `json:"hasPrivateKey"`
	Tags          string `json:"tags,omitempty"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

type FileStat struct {
	Exists bool  `json:"exists"`
	Size   int64 `json:"size"`
	IsDir  bool  `json:"isDir"`
}

func NewApp(dbPath string, maxBodyMB int64) *App {
	st, err := store.New(dbPath)
	if err != nil {
		log.Fatal("failed to init store:", err)
	}
	// Persist TOFU host keys so trust survives restarts.
	sshterm.SetHostKeyPersister(st)
	return &App{
		store:     st,
		terminals: make(map[string]*Terminal),
		maxBodyMB: maxBodyMB,
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if gostatic.GOOS == "linux" {
		go func() {
			time.Sleep(500 * time.Millisecond)
			pid := os.Getpid()
			exec.Command("sh", "-c", fmt.Sprintf(
				`WID=$(xdotool search --pid %d 2>/dev/null | tail -1); [ -n "$WID" ] && xprop -id "$WID" -f _GTK_THEME_VARIANT 32a -set _GTK_THEME_VARIANT dark`,
				pid,
			)).Run()
		}()
	}
}

func (a *App) shutdown(ctx context.Context) {
	a.mu.Lock()
	for id, t := range a.terminals {
		if t.done != nil {
			t.doneOnce.Do(func() { close(t.done) })
		}
		t.SSHSession.Close()
		t.Client.Close()
		delete(a.terminals, id)
	}
	a.mu.Unlock()
	a.store.Close()
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- Server CRUD ----

func toServerView(s store.Server) ServerView {
	return ServerView{
		ID:            s.ID,
		Name:          s.Name,
		Host:          s.Host,
		Port:          s.Port,
		User:          s.User,
		AuthType:      s.AuthType,
		HasPassword:   s.Password != "",
		HasPrivateKey: s.PrivateKey != "",
		Tags:          s.Tags,
		CreatedAt:     s.CreatedAt,
		UpdatedAt:     s.UpdatedAt,
	}
}

func (a *App) ListServers() ([]ServerView, error) {
	servers, err := a.store.ListServers(context.Background())
	if err != nil {
		return nil, err
	}
	views := make([]ServerView, 0, len(servers))
	for _, svr := range servers {
		views = append(views, toServerView(svr))
	}
	return views, nil
}

func (a *App) CreateServer(svr store.Server) error {
	if svr.ID == "" {
		svr.ID = generateID()
	}
	if svr.Port == 0 {
		svr.Port = 22
	}
	if err := validateServerSecrets(svr); err != nil {
		return err
	}
	return a.store.CreateServer(context.Background(), &svr)
}

func (a *App) UpdateServer(svr store.Server) error {
	if svr.Port == 0 {
		svr.Port = 22
	}
	if err := validateServerSecrets(svr); err != nil {
		return err
	}
	return a.store.UpdateServer(context.Background(), &svr)
}

func (a *App) UpdateServerPreserveSecrets(svr store.Server, preservePassword, preservePrivateKey bool) error {
	if svr.Port == 0 {
		svr.Port = 22
	}
	existing, err := a.store.GetServer(context.Background(), svr.ID)
	if err != nil {
		return err
	}
	if preservePassword {
		svr.Password = existing.Password
	}
	if preservePrivateKey {
		svr.PrivateKey = existing.PrivateKey
	}
	if err := validateServerSecrets(svr); err != nil {
		return err
	}
	return a.store.UpdateServer(context.Background(), &svr)
}

func (a *App) CopyServer(id string) error {
	svr, err := a.store.GetServer(context.Background(), id)
	if err != nil {
		return err
	}
	svr.ID = generateID()
	if svr.Name == "" {
		svr.Name = svr.Host + " (副本)"
	} else {
		svr.Name += " (副本)"
	}
	return a.store.CreateServer(context.Background(), svr)
}

func validateServerSecrets(svr store.Server) error {
	switch svr.AuthType {
	case "key":
		if svr.PrivateKey == "" {
			return fmt.Errorf("请提供私钥")
		}
	default:
		if svr.Password == "" {
			return fmt.Errorf("请提供密码")
		}
	}
	return nil
}

func (a *App) DeleteServer(id string) error {
	return a.store.DeleteServer(context.Background(), id)
}

func (a *App) BatchImport(servers []store.Server) error {
	for i := range servers {
		svr := &servers[i]
		if svr.Host == "" {
			continue
		}
		if svr.Port == 0 {
			svr.Port = 22
		}
		if svr.User == "" {
			svr.User = "root"
		}
		if svr.ID == "" {
			svr.ID = generateID()
		}
		if err := validateServerSecrets(*svr); err != nil {
			return fmt.Errorf("import %s failed: %w", svr.Host, err)
		}
		if err := a.store.CreateServer(context.Background(), svr); err != nil {
			return fmt.Errorf("import failed: %w", err)
		}
	}
	return nil
}

// ---- Terminal (SSH) ----

func (a *App) ConnectServer(serverID string) (string, error) {
	return a.ConnectServerWithPassphrase(serverID, "")
}

func (a *App) ConnectServerWithPassphrase(serverID, passphrase string) (string, error) {
	svr, err := a.store.GetServer(context.Background(), serverID)
	if err != nil {
		return "", fmt.Errorf("load server failed: %w", err)
	}
	return a.connect(svr.Host, svr.Port, svr.User, svr.Password, svr.PrivateKey, passphrase)
}

func (a *App) Connect(host string, port int, username, password, privateKey string) (string, error) {
	return a.connect(host, port, username, password, privateKey, "")
}

func (a *App) connect(host string, port int, username, password, privateKey, passphrase string) (string, error) {
	params := &sshterm.ConnectParams{
		Host:       host,
		Port:       port,
		Username:   username,
		Password:   password,
		PrivateKey: privateKey,
		Passphrase: passphrase,
	}
	if params.Port == 0 {
		params.Port = 22
	}

	client, config, err := sshterm.DialSSH(params)
	if err != nil {
		return "", fmt.Errorf("SSH dial failed: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return "", fmt.Errorf("SSH session failed: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return "", fmt.Errorf("stdin pipe failed: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return "", fmt.Errorf("stdout pipe failed: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		session.Close()
		client.Close()
		return "", fmt.Errorf("stderr pipe failed: %w", err)
	}

	// Detect the remote login shell so we can inject the correct
	// CWD-reporting hook below (bash/zsh/fish each need different syntax).
	shell := sshterm.DetectShell(client)
	cwdSnippet := sshterm.CWDReportSnippet(shell)

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", 40, 80, modes); err != nil {
		session.Close()
		client.Close()
		return "", fmt.Errorf("request pty failed: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return "", fmt.Errorf("shell failed: %w", err)
	}

	sessionID := generateID()

	// Store in Manager (for SFTP operations)
	sshterm.Manager.Create(sessionID, client, config, host, port, username)

	// Store terminal state
	done := make(chan struct{})
	a.mu.Lock()
	a.terminals[sessionID] = &Terminal{
		Client:     client,
		SSHSession: session,
		Stdin:      stdin,
		done:       done,
	}
	a.mu.Unlock()

	// SSH keepalive — stops cleanly when the session is closed (done closed)
	// or the connection drops (SendRequest errors).
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
					a.cleanupSession(sessionID)
					runtime.EventsEmit(a.ctx, "terminal:closed", sessionID)
					return
				}
			}
		}
	}()

	// Read stdout → emit terminal:output events
	go func() {
		buf := make([]byte, 4096)
		first := true
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				break
			}
			data := base64.StdEncoding.EncodeToString(buf[:n])
			runtime.EventsEmit(a.ctx, "terminal:output", map[string]string{
				"sessionId": sessionID,
				"data":      data,
			})
			if first {
				first = false
				go func() {
					time.Sleep(200 * time.Millisecond)
					stdin.Write([]byte(cwdSnippet))
				}()
			}
		}
		a.cleanupSession(sessionID)
	}()

	// Read stderr → emit terminal:error events
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				break
			}
			data := base64.StdEncoding.EncodeToString(buf[:n])
			runtime.EventsEmit(a.ctx, "terminal:output", map[string]string{
				"sessionId": sessionID,
				"data":      data,
			})
		}
	}()

	runtime.EventsEmit(a.ctx, "terminal:connected", sessionID)
	return sessionID, nil
}

func (a *App) ListHostKeys() ([]store.HostKey, error) {
	keys, err := a.store.ListHostKeys()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		data, err := base64.StdEncoding.DecodeString(keys[i].KeyB64)
		if err != nil {
			continue
		}
		pub, err := ssh.ParsePublicKey(data)
		if err != nil {
			continue
		}
		keys[i].Fingerprint = ssh.FingerprintSHA256(pub)
		keys[i].KeyB64 = ""
	}
	return keys, nil
}

func (a *App) DeleteHostKey(addr string) error {
	if err := a.store.DeleteHostKey(addr); err != nil {
		return err
	}
	sshterm.ForgetHostKey(addr)
	return nil
}

func (a *App) TerminalInput(sessionID string, data string) error {
	a.mu.Lock()
	t, ok := a.terminals[sessionID]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}
	_, err := t.Stdin.Write([]byte(data))
	return err
}

func (a *App) TerminalResize(sessionID string, cols, rows int) error {
	a.mu.Lock()
	t, ok := a.terminals[sessionID]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}
	return t.SSHSession.WindowChange(rows, cols)
}

func (a *App) CloseSession(sessionID string) {
	a.cleanupSession(sessionID)
	runtime.EventsEmit(a.ctx, "terminal:closed", sessionID)
}

func (a *App) ListSessions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	ids := make([]string, 0, len(a.terminals))
	for id := range a.terminals {
		ids = append(ids, id)
	}
	return ids
}

func (a *App) cleanupSession(sessionID string) {
	a.mu.Lock()
	t, ok := a.terminals[sessionID]
	if ok {
		delete(a.terminals, sessionID)
	}
	a.mu.Unlock()
	if ok {
		if t.done != nil {
			t.doneOnce.Do(func() { close(t.done) })
		}
		t.SSHSession.Close()
		t.Client.Close()
		sshterm.Manager.Remove(sessionID)
	}
}

// ---- SFTP ----

// getSession returns the session for the given ID. Callers obtain the cached
// SFTP client from it: session.SFTP() for streaming download/upload,
// session.WithSFTP(...) for non-streaming ops that are safe to retry.
func (a *App) getSession(sessionID string) (*sshterm.Session, error) {
	s, err := sshterm.Manager.Get(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}
	return s, nil
}

func (a *App) SFTPList(sessionID, reqPath string) ([]sshterm.FileEntry, error) {
	reqPath, err := sshterm.SanitizePath(reqPath)
	if err != nil {
		return nil, err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return nil, err
	}

	var files []sshterm.FileEntry
	err = s.WithSFTP(func(sc *sftp.Client) error {
		entries, err := sc.ReadDir(reqPath)
		if err != nil {
			return err
		}
		files = make([]sshterm.FileEntry, 0, len(entries))
		for _, e := range entries {
			files = append(files, sshterm.FormatFileEntry(e))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func (a *App) SFTPStat(sessionID, filePath string) (FileStat, error) {
	filePath, err := sshterm.SanitizePath(filePath)
	if err != nil {
		return FileStat{}, err
	}
	s, err := a.getSession(sessionID)
	if err != nil {
		return FileStat{}, err
	}
	var stat FileStat
	err = s.WithSFTP(func(sc *sftp.Client) error {
		info, err := sc.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				stat.Exists = false
				return nil
			}
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "not exist") || strings.Contains(msg, "no such file") {
				stat.Exists = false
				return nil
			}
			return err
		}
		stat.Exists = true
		stat.Size = info.Size()
		stat.IsDir = info.IsDir()
		return nil
	})
	return stat, err
}

type downloadProgressWriter struct {
	ctx      context.Context
	dst      io.Writer
	total    int64
	written  int64
	fileName string
	lastTick time.Time
}

func (w *downloadProgressWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.written += int64(n)
	if time.Since(w.lastTick) > 100*time.Millisecond {
		w.lastTick = time.Now()
		runtime.EventsEmit(w.ctx, "download:progress", w.fileName, w.written, w.total)
	}
	return n, err
}

func (a *App) SFTPDownloadDialog(sessionID, remotePath string) error {
	remotePath, err := sshterm.SanitizePath(remotePath)
	if err != nil {
		return err
	}

	fileName := path.Base(remotePath)
	savePath, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: fileName,
		Title:           "保存文件 - " + fileName,
	})
	if err != nil || savePath == "" {
		// User cancelled or dialog failed — not a real download error.
		runtime.EventsEmit(a.ctx, "download:complete", map[string]interface{}{
			"fileName": fileName, "success": false, "cancelled": true,
		})
		return err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return err
	}
	// Streaming read uses the cached client directly (not WithSFTP, which is
	// for retryable non-streaming ops).
	sc, err := s.SFTP()
	if err != nil {
		return fmt.Errorf("sftp init failed: %w", err)
	}

	stat, err := sc.Stat(remotePath)
	if err != nil {
		return fmt.Errorf("stat remote file failed: %w", err)
	}

	f, err := sc.Open(remotePath)
	if err != nil {
		return err
	}
	defer f.Close()

	dst, err := os.Create(savePath)
	if err != nil {
		return err
	}
	defer dst.Close()

	pw := &downloadProgressWriter{
		ctx:      a.ctx,
		dst:      dst,
		total:    stat.Size(),
		fileName: fileName,
	}
	_, err = io.Copy(pw, f)
	if err != nil {
		runtime.EventsEmit(a.ctx, "download:complete", map[string]interface{}{
			"fileName": fileName, "success": false, "error": err.Error(),
		})
		return err
	}
	runtime.EventsEmit(a.ctx, "download:complete", map[string]interface{}{
		"fileName": fileName, "success": true,
	})
	return nil
}

// MaxChunkSize caps a single upload chunk payload. The frontend uses 512 KB
// chunks; this is a generous safety ceiling against a malformed call.
const MaxChunkSize = 4 << 20 // 4 MB

func (a *App) SFTPUpload(sessionID, destPath, fileName string, data []byte) error {
	return a.sftpUploadInternal(sessionID, destPath, fileName, data, 0, true)
}

// SFTPUploadChunk appends a chunk at the given offset. offset==0 (first chunk)
// truncates/creates the file; subsequent chunks are validated against the
// current remote size to catch out-of-order or duplicated chunks.
func (a *App) SFTPUploadChunk(sessionID, destPath, fileName string, data []byte, offset int64) error {
	return a.sftpUploadInternal(sessionID, destPath, fileName, data, offset, offset == 0)
}

func (a *App) sftpUploadInternal(sessionID, destPath, fileName string, data []byte, offset int64, create bool) error {
	if len(data) > MaxChunkSize {
		return fmt.Errorf("chunk too large (%d > %d bytes)", len(data), MaxChunkSize)
	}

	destPath, err := sshterm.SanitizePath(destPath)
	if err != nil {
		return err
	}
	remotePath := path.Join(destPath, fileName)
	remotePath, err = sshterm.SanitizePath(remotePath)
	if err != nil {
		return err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return err
	}
	// Streaming write uses the cached client directly.
	sc, err := s.SFTP()
	if err != nil {
		return fmt.Errorf("sftp init failed: %w", err)
	}

	var dst io.WriteCloser
	if create {
		dst, err = sc.Create(remotePath)
	} else {
		// Verify the remote size matches the expected offset before appending,
		// so a dropped/duplicated/out-of-order chunk fails loudly instead of
		// silently corrupting the file.
		info, statErr := sc.Stat(remotePath)
		if statErr != nil {
			return fmt.Errorf("stat remote file failed: %w", statErr)
		}
		if info.Size() != offset {
			return fmt.Errorf("upload offset mismatch (remote %d, expected %d)", info.Size(), offset)
		}
		dst, err = sc.OpenFile(remotePath, os.O_WRONLY|os.O_APPEND)
	}
	if err != nil {
		return fmt.Errorf("open remote file failed: %w", err)
	}
	defer dst.Close()

	if _, err = dst.Write(data); err != nil {
		dst.Close()
		if create {
			sc.Remove(remotePath) // clean up the partial file we just created
		}
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

func (a *App) SFTPRemove(sessionID, filePath string) error {
	filePath, err := sshterm.SanitizePath(filePath)
	if err != nil {
		return err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return err
	}

	return s.WithSFTP(func(sc *sftp.Client) error {
		info, err := sc.Stat(filePath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return sshterm.RemoveDir(sc, filePath)
		}
		return sc.Remove(filePath)
	})
}

func (a *App) SFTPRename(sessionID, oldPath, newPath string) error {
	oldPath, err := sshterm.SanitizePath(oldPath)
	if err != nil {
		return err
	}
	newPath, err = sshterm.SanitizePath(newPath)
	if err != nil {
		return err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return err
	}

	return s.WithSFTP(func(sc *sftp.Client) error {
		return sc.Rename(oldPath, newPath)
	})
}

func (a *App) SFTPMkdir(sessionID, dirPath string) error {
	dirPath, err := sshterm.SanitizePath(dirPath)
	if err != nil {
		return err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return err
	}

	return s.WithSFTP(func(sc *sftp.Client) error {
		return sc.Mkdir(dirPath)
	})
}

func (a *App) SFTPRead(sessionID, filePath string) (string, error) {
	filePath, err := sshterm.SanitizePath(filePath)
	if err != nil {
		return "", err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return "", err
	}

	var content string
	err = s.WithSFTP(func(sc *sftp.Client) error {
		info, err := sc.Stat(filePath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("不能编辑目录")
		}
		if a.maxBodyMB > 0 && info.Size() > a.maxBodyMB<<20 {
			return fmt.Errorf("文件超过内联编辑大小限制 (%d 字节 > %d MB)", info.Size(), a.maxBodyMB)
		}
		f, err := sc.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		if looksBinary(data) {
			return fmt.Errorf("疑似二进制文件，已阻止内联编辑")
		}
		content = string(data)
		return nil
	})
	if err != nil {
		return "", err
	}
	return content, nil
}

func looksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	controls := 0
	for _, b := range sample {
		if b == 0 {
			return true
		}
		if b < 32 && !strings.ContainsRune("\t\r\n\b\f", rune(b)) {
			controls++
		}
	}
	return controls > len(sample)/20
}

func (a *App) SFTPWrite(sessionID, filePath, content string) error {
	// Enforce the -maxbody limit on inline-editor saves.
	if a.maxBodyMB > 0 && int64(len(content)) > a.maxBodyMB<<20 {
		return fmt.Errorf("内容超过大小限制 (%d 字节 > %d MB)", len(content), a.maxBodyMB)
	}

	filePath, err := sshterm.SanitizePath(filePath)
	if err != nil {
		return err
	}

	s, err := a.getSession(sessionID)
	if err != nil {
		return err
	}

	return s.WithSFTP(func(sc *sftp.Client) error {
		tmpPath := fmt.Sprintf("%s.webssh-tmp-%s", filePath, generateID())
		dst, err := sc.Create(tmpPath)
		if err != nil {
			return fmt.Errorf("create remote file failed: %w", err)
		}
		if _, err := dst.Write([]byte(content)); err != nil {
			dst.Close()
			sc.Remove(tmpPath)
			return fmt.Errorf("write remote file failed: %w", err)
		}
		if err := dst.Close(); err != nil {
			sc.Remove(tmpPath)
			return fmt.Errorf("close remote file failed: %w", err)
		}
		if err := sc.Rename(tmpPath, filePath); err != nil {
			if removeErr := sc.Remove(filePath); removeErr != nil {
				sc.Remove(tmpPath)
				return fmt.Errorf("replace remote file failed: %w", err)
			}
			if renameErr := sc.Rename(tmpPath, filePath); renameErr != nil {
				sc.Remove(tmpPath)
				return fmt.Errorf("replace remote file failed: %w", renameErr)
			}
		}
		return nil
	})
}
