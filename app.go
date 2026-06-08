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
	"sync"
	"time"

	"webssh/internal/sshterm"
	"webssh/internal/store"

	"github.com/pkg/sftp"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/ssh"
)

type Terminal struct {
	Client    *ssh.Client
	SSHSession *ssh.Session
	Stdin     io.WriteCloser
}

type App struct {
	ctx       context.Context
	store     *store.Store
	terminals map[string]*Terminal
	mu        sync.Mutex
	maxBodyMB int64
}

func NewApp(dbPath string, maxBodyMB int64) *App {
	st, err := store.New(dbPath)
	if err != nil {
		log.Fatal("failed to init store:", err)
	}
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

func (a *App) ListServers() ([]store.Server, error) {
	return a.store.ListServers(context.Background())
}

func (a *App) CreateServer(svr store.Server) error {
	if svr.ID == "" {
		svr.ID = generateID()
	}
	if svr.Port == 0 {
		svr.Port = 22
	}
	return a.store.CreateServer(context.Background(), &svr)
}

func (a *App) UpdateServer(svr store.Server) error {
	if svr.Port == 0 {
		svr.Port = 22
	}
	return a.store.UpdateServer(context.Background(), &svr)
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
		if err := a.store.CreateServer(context.Background(), svr); err != nil {
			return fmt.Errorf("import failed: %w", err)
		}
	}
	return nil
}

// ---- Terminal (SSH) ----

func (a *App) Connect(host string, port int, username, password, privateKey string) (string, error) {
	params := &sshterm.ConnectParams{
		Host:       host,
		Port:       port,
		Username:   username,
		Password:   password,
		PrivateKey: privateKey,
	}
	if params.Port == 0 {
		params.Port = 22
	}

	client, config, err := sshterm.DialSSH(params)
	if err != nil {
		return "", fmt.Errorf("SSH dial failed: %w", err)
	}

	// SSH keepalive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}()

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

	session.Setenv("PROMPT_COMMAND", `printf "\033]7;file://$HOSTNAME$PWD\033\\"`)

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
	a.mu.Lock()
	a.terminals[sessionID] = &Terminal{
		Client:    client,
		SSHSession: session,
		Stdin:     stdin,
	}
	a.mu.Unlock()

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
					stdin.Write([]byte("export PROMPT_COMMAND='printf \"\\033]7;file://$HOSTNAME$PWD\\033\\\\\"'\n"))
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
		t.SSHSession.Close()
		t.Client.Close()
		sshterm.Manager.Remove(sessionID)
	}
}

// ---- SFTP ----

func (a *App) getSFTPClient(sessionID string) (*sftp.Client, error) {
	s, err := sshterm.Manager.Get(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}
	sc, err := s.DialSFTP()
	if err != nil {
		return nil, fmt.Errorf("sftp init failed: %w", err)
	}
	return sc, nil
}

func (a *App) SFTPList(sessionID, reqPath string) ([]sshterm.FileEntry, error) {
	reqPath, err := sshterm.SanitizePath(reqPath)
	if err != nil {
		return nil, err
	}

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return nil, err
	}
	defer sc.Close()

	entries, err := sc.ReadDir(reqPath)
	if err != nil {
		return nil, err
	}

	files := make([]sshterm.FileEntry, 0, len(entries))
	for _, e := range entries {
		files = append(files, sshterm.FormatFileEntry(e))
	}
	return files, nil
}

func (a *App) SFTPDownload(sessionID, filePath string) ([]byte, error) {
	filePath, err := sshterm.SanitizePath(filePath)
	if err != nil {
		return nil, err
	}

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return nil, err
	}
	defer sc.Close()

	f, err := sc.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
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
	if err != nil {
		runtime.EventsEmit(a.ctx, "download:complete", fileName)
		return err
	}
	if savePath == "" {
		runtime.EventsEmit(a.ctx, "download:complete", fileName)
		return nil
	}

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return err
	}
	defer sc.Close()

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
	if err == nil {
		runtime.EventsEmit(a.ctx, "download:complete", fileName)
	}
	return err
}

func (a *App) SFTPUpload(sessionID, destPath, fileName string, data []byte) error {
	return a.sftpUploadInternal(sessionID, destPath, fileName, data, true)
}

func (a *App) SFTPUploadChunk(sessionID, destPath, fileName string, data []byte, isFirst bool) error {
	return a.sftpUploadInternal(sessionID, destPath, fileName, data, isFirst)
}

func (a *App) sftpUploadInternal(sessionID, destPath, fileName string, data []byte, create bool) error {
	destPath, err := sshterm.SanitizePath(destPath)
	if err != nil {
		return err
	}

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return err
	}
	defer sc.Close()

	remotePath := path.Join(destPath, fileName)
	remotePath, err = sshterm.SanitizePath(remotePath)
	if err != nil {
		return err
	}

	var dst io.WriteCloser
	if create {
		dst, err = sc.Create(remotePath)
	} else {
		dst, err = sc.OpenFile(remotePath, os.O_WRONLY|os.O_APPEND)
	}
	if err != nil {
		return fmt.Errorf("open remote file failed: %w", err)
	}
	defer dst.Close()

	_, err = dst.Write(data)
	if err != nil {
		dst.Close()
		if create {
			sc.Remove(remotePath)
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

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return err
	}
	defer sc.Close()

	info, err := sc.Stat(filePath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return sshterm.RemoveDir(sc, filePath)
	}
	return sc.Remove(filePath)
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

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return err
	}
	defer sc.Close()

	return sc.Rename(oldPath, newPath)
}

func (a *App) SFTPMkdir(sessionID, dirPath string) error {
	dirPath, err := sshterm.SanitizePath(dirPath)
	if err != nil {
		return err
	}

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return err
	}
	defer sc.Close()

	return sc.Mkdir(dirPath)
}

func (a *App) SFTPRead(sessionID, filePath string) (string, error) {
	filePath, err := sshterm.SanitizePath(filePath)
	if err != nil {
		return "", err
	}

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return "", err
	}
	defer sc.Close()

	f, err := sc.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (a *App) SFTPWrite(sessionID, filePath, content string) error {
	filePath, err := sshterm.SanitizePath(filePath)
	if err != nil {
		return err
	}

	sc, err := a.getSFTPClient(sessionID)
	if err != nil {
		return err
	}
	defer sc.Close()

	dst, err := sc.Create(filePath)
	if err != nil {
		return fmt.Errorf("create remote file failed: %w", err)
	}
	defer dst.Close()

	_, err = dst.Write([]byte(content))
	if err != nil {
		return fmt.Errorf("write remote file failed: %w", err)
	}
	return nil
}
