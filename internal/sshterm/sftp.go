package sshterm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/sftp"
)

func sanitizePath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains NUL")
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", errors.New("path contains traversal")
		}
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	return cleaned, nil
}

func sanitizeUploadName(name string) (string, error) {
	if name == "" || name == "." || name == ".." {
		return "", errors.New("invalid file name")
	}
	if strings.ContainsRune(name, 0) || strings.ContainsAny(name, `/\`) {
		return "", errors.New("invalid file name")
	}
	return name, nil
}

// MaxWriteBodySize limits the request body size for the inline editor
// save endpoint (HandleFSWrite). 0 = no limit. Default 50MB.
var MaxWriteBodySize int64 = 50 << 20

type FileEntry struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	IsDir    bool   `json:"isDir"`
	ModTime  string `json:"modTime"`
	TextLike bool   `json:"textLike"`
	TooLarge bool   `json:"tooLarge"`
	Editable bool   `json:"editable"`
}

type ListResponse struct {
	Success bool        `json:"success"`
	Data    []FileEntry `json:"data"`
	Error   string      `json:"error,omitempty"`
}

type ActionResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
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

func isTextLikeName(name string) bool {
	lower := strings.ToLower(name)
	base := path.Base(lower)
	switch base {
	case "dockerfile", "makefile", "rakefile", "gemfile", "go.mod", "go.sum", "readme", "license", "hosts", "fstab", "crontab":
		return true
	}
	ext := strings.TrimPrefix(path.Ext(lower), ".")
	// Dotfiles without extension: .bashrc, .profile, etc.
	if ext == "" && strings.HasPrefix(lower, ".") {
		ext = lower[1:]
	}
	if ext == "" {
		return false
	}
	textExt := map[string]bool{
		"txt": true, "log": true, "md": true, "markdown": true, "rst": true,
		"json": true, "jsonl": true, "yaml": true, "yml": true, "toml": true, "ini": true, "conf": true, "cfg": true, "env": true,
		"xml": true, "html": true, "htm": true, "css": true, "scss": true, "less": true,
		"js": true, "mjs": true, "cjs": true, "ts": true, "tsx": true, "jsx": true,
		"go": true, "py": true, "rb": true, "php": true, "java": true, "kt": true, "kts": true, "scala": true,
		"c": true, "h": true, "cc": true, "cpp": true, "hpp": true, "rs": true, "swift": true,
		"sh": true, "bash": true, "zsh": true, "fish": true, "ps1": true, "bat": true, "cmd": true,
		"sql": true, "lua": true, "pl": true, "pm": true, "r": true, "dart": true, "vue": true, "svelte": true,
		"dockerfile": true, "gitignore": true, "gitattributes": true, "editorconfig": true,
		"bashrc": true, "zshrc": true, "profile": true, "gitconfig": true, "tmux.conf": true, "vimrc": true,
		"inputrc": true, "aliases": true, "exports": true, "functions": true, "path": true,
	}
	return textExt[ext]
}

func HandleFSList(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	reqPath := r.URL.Query().Get("path")
	if reqPath == "" {
		reqPath = "/"
	}
	reqPath, err := sanitizePath(reqPath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	var files []FileEntry
	err = s.withSFTP(func(sc *sftp.Client) error {
		entries, err := sc.ReadDir(reqPath)
		if err != nil {
			return err
		}
		files = make([]FileEntry, 0, len(entries))
		for _, e := range entries {
			textLike := !e.IsDir() && isTextLikeName(e.Name())
			tooLarge := !e.IsDir() && MaxWriteBodySize > 0 && e.Size() > MaxWriteBodySize
			files = append(files, FileEntry{
				Name:     e.Name(),
				Size:     e.Size(),
				Mode:     e.Mode().String(),
				IsDir:    e.IsDir(),
				ModTime:  e.ModTime().Format(time.RFC3339),
				TextLike: textLike,
				TooLarge: tooLarge,
				Editable: textLike && !tooLarge,
			})
		}
		return nil
	})
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	json.NewEncoder(w).Encode(ListResponse{Success: true, Data: files})
}

func HandleFSDownload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}
	filePath, err := sanitizePath(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	sc, err := s.SFTP()
	if err != nil {
		http.Error(w, "sftp init failed", http.StatusInternalServerError)
		return
	}

	stat, err := sc.Stat(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	f, err := sc.Open(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fileName := path.Base(filePath)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fileName+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	io.Copy(w, f)
}

func HandleFSUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	destPath := r.URL.Query().Get("path")
	if destPath == "" {
		destPath = "/"
	}
	destPath, err := sanitizePath(destPath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := s.SFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}

	if offsetStr := r.Header.Get("X-Upload-Offset"); offsetStr != "" {
		offset, err := strconv.ParseInt(offsetStr, 10, 64)
		if err != nil || offset < 0 {
			jsonError(w, "invalid offset")
			return
		}
		fileName := r.Header.Get("X-Upload-Name")
		if fileName == "" {
			jsonError(w, "X-Upload-Name header required")
			return
		}
		fileName, err = sanitizeUploadName(fileName)
		if err != nil {
			jsonError(w, err.Error())
			return
		}
		totalSize, err := strconv.ParseInt(r.Header.Get("X-Upload-Size"), 10, 64)
		if err != nil || totalSize < 0 {
			jsonError(w, "X-Upload-Size header required")
			return
		}
		if offset > totalSize {
			jsonError(w, "upload offset exceeds file size")
			return
		}
		if MaxWriteBodySize > 0 && totalSize > MaxWriteBodySize {
			jsonError(w, "file too large")
			return
		}
		remaining := totalSize - offset
		if r.ContentLength > remaining {
			jsonError(w, "chunk exceeds declared file size")
			return
		}
		remotePath := path.Join(destPath, fileName)
		remotePath, err = sanitizePath(remotePath)
		if err != nil {
			jsonError(w, err.Error())
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, remaining)
		var dst io.WriteCloser
		if offset == 0 {
			dst, err = sc.Create(remotePath)
		} else {
			info, statErr := sc.Stat(remotePath)
			if statErr != nil {
				jsonError(w, "stat remote file failed: "+statErr.Error())
				return
			}
			if info.Size() != offset {
				jsonError(w, "upload offset mismatch")
				return
			}
			dst, err = sc.OpenFile(remotePath, os.O_WRONLY|os.O_APPEND)
		}
		if err != nil {
			jsonError(w, "open remote file failed: "+err.Error())
			return
		}
		defer dst.Close()
		written, err := io.Copy(dst, r.Body)
		if err != nil {
			dst.Close()
			if offset == 0 {
				sc.Remove(remotePath)
			}
			jsonError(w, "write failed: "+err.Error())
			return
		}
		if written > remaining {
			dst.Close()
			if offset == 0 {
				sc.Remove(remotePath)
			}
			jsonError(w, "chunk exceeds declared file size")
			return
		}
		json.NewEncoder(w).Encode(ActionResponse{Success: true})
		return
	}

	if MaxWriteBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, MaxWriteBodySize)
	}
	mr, err := r.MultipartReader()
	if err != nil {
		jsonError(w, "multipart reader failed: "+err.Error())
		return
	}

	part, err := mr.NextPart()
	if err != nil {
		jsonError(w, "read part failed: "+err.Error())
		return
	}

	fileName, err := sanitizeUploadName(part.FileName())
	if err != nil {
		jsonError(w, err.Error())
		return
	}
	remotePath := path.Join(destPath, fileName)
	remotePath, err = sanitizePath(remotePath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}
	dst, err := sc.Create(remotePath)
	if err != nil {
		jsonError(w, "create remote file failed: "+err.Error())
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, part)
	if err != nil {
		dst.Close()
		sc.Remove(remotePath)
		jsonError(w, "write failed: "+err.Error())
		return
	}
	json.NewEncoder(w).Encode(ActionResponse{Success: true})
}

func HandleFSRemove(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req struct {
		Path string `json:"path"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Path == "" {
		jsonError(w, "path required")
		return
	}
	reqPath, err := sanitizePath(req.Path)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	err = s.withSFTP(func(sc *sftp.Client) error {
		info, err := sc.Stat(reqPath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return removeDir(sc, reqPath)
		}
		return sc.Remove(reqPath)
	})
	if err != nil {
		jsonError(w, err.Error())
		return
	}
	json.NewEncoder(w).Encode(ActionResponse{Success: true})
}

func HandleFSRename(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req struct {
		OldPath string `json:"oldPath"`
		NewPath string `json:"newPath"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.OldPath == "" || req.NewPath == "" {
		jsonError(w, "oldPath and newPath required")
		return
	}
	oldPath, err := sanitizePath(req.OldPath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}
	newPath, err := sanitizePath(req.NewPath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	err = s.withSFTP(func(sc *sftp.Client) error {
		return sc.Rename(oldPath, newPath)
	})
	if err != nil {
		jsonError(w, err.Error())
		return
	}
	json.NewEncoder(w).Encode(ActionResponse{Success: true})
}

func HandleFSMkdir(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req struct {
		Path string `json:"path"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Path == "" {
		jsonError(w, "path required")
		return
	}
	reqPath, err := sanitizePath(req.Path)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	err = s.withSFTP(func(sc *sftp.Client) error {
		return sc.Mkdir(reqPath)
	})
	if err != nil {
		jsonError(w, err.Error())
		return
	}
	json.NewEncoder(w).Encode(ActionResponse{Success: true})
}

func HandleFSRead(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}
	filePath, err := sanitizePath(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	sc, err := s.SFTP()
	if err != nil {
		http.Error(w, "sftp init failed", http.StatusInternalServerError)
		return
	}

	f, err := sc.Open(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if stat.IsDir() {
		http.Error(w, "cannot edit directory", http.StatusBadRequest)
		return
	}
	if MaxWriteBodySize > 0 && stat.Size() > MaxWriteBodySize {
		http.Error(w, fmt.Sprintf("file too large for inline editor (%d bytes)", stat.Size()), http.StatusRequestEntityTooLarge)
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if looksBinary(data) {
		http.Error(w, "binary file cannot be edited inline", http.StatusUnsupportedMediaType)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

func HandleFSWrite(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		jsonError(w, "path required")
		return
	}
	filePath, err := sanitizePath(filePath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := s.SFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}

	var bodyReader io.Reader = r.Body
	if MaxWriteBodySize > 0 {
		bodyReader = http.MaxBytesReader(w, r.Body, MaxWriteBodySize)
	}
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		jsonError(w, "read body failed: "+err.Error())
		return
	}

	tmpPath := fmt.Sprintf("%s.webssh-tmp-%d", filePath, time.Now().UnixNano())
	dst, err := sc.Create(tmpPath)
	if err != nil {
		jsonError(w, "create remote file failed: "+err.Error())
		return
	}

	_, err = dst.Write(body)
	if err != nil {
		dst.Close()
		sc.Remove(tmpPath)
		jsonError(w, "write remote file failed: "+err.Error())
		return
	}
	if err := dst.Close(); err != nil {
		sc.Remove(tmpPath)
		jsonError(w, "close remote file failed: "+err.Error())
		return
	}
	if err := replaceRemoteFile(sc, tmpPath, filePath); err != nil {
		sc.Remove(tmpPath)
		jsonError(w, "replace remote file failed: "+err.Error())
		return
	}
	json.NewEncoder(w).Encode(ActionResponse{Success: true})
}

type sftpRenamer interface {
	Rename(oldname, newname string) error
	Remove(name string) error
	Stat(name string) (os.FileInfo, error)
}

func replaceRemoteFile(sc sftpRenamer, tmpPath, filePath string) error {
	if err := sc.Rename(tmpPath, filePath); err == nil {
		return nil
	}

	if _, err := sc.Stat(filePath); err != nil {
		return err
	}

	backupPath := fmt.Sprintf("%s.webssh-bak-%d", filePath, time.Now().UnixNano())
	if err := sc.Rename(filePath, backupPath); err != nil {
		return err
	}
	if err := sc.Rename(tmpPath, filePath); err != nil {
		_ = sc.Rename(backupPath, filePath)
		return err
	}
	_ = sc.Remove(backupPath)
	return nil
}

func removeDir(sc *sftp.Client, dirPath string) error {
	entries, err := sc.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := path.Join(dirPath, e.Name())
		if e.IsDir() {
			if err := removeDir(sc, p); err != nil {
				return err
			}
		} else {
			if err := sc.Remove(p); err != nil {
				return err
			}
		}
	}
	return sc.RemoveDirectory(dirPath)
}

func jsonError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ActionResponse{Success: false, Error: msg})
}
