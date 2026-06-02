package sshterm

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/sftp"
)

func sanitizePath(p string) (string, error) {
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	if strings.HasPrefix(cleaned, "..") || cleaned == ".." {
		return "", errors.New("path contains traversal")
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == ".." {
			return "", errors.New("path contains traversal")
		}
	}
	return cleaned, nil
}

// MaxWriteBodySize limits the request body size for the inline editor
// save endpoint (HandleFSWrite). 0 = no limit. Default 50MB.
var MaxWriteBodySize int64 = 50 << 20

type FileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	IsDir   bool   `json:"isDir"`
	ModTime string `json:"modTime"`
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

	sc, err := s.DialSFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	entries, err := sc.ReadDir(reqPath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	files := make([]FileEntry, 0, len(entries))
	for _, e := range entries {
		files = append(files, FileEntry{
			Name:    e.Name(),
			Size:    e.Size(),
			Mode:    e.Mode().String(),
			IsDir:   e.IsDir(),
			ModTime: e.ModTime().Format(time.RFC3339),
		})
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

	sc, err := s.DialSFTP()
	if err != nil {
		http.Error(w, "sftp init failed", http.StatusInternalServerError)
		return
	}
	defer sc.Close()

	f, err := sc.Open(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fileName := path.Base(filePath)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fileName+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
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

	sc, err := s.DialSFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

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

	remotePath := path.Join(destPath, part.FileName())
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

	sc, err := s.DialSFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	info, err := sc.Stat(reqPath)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	if info.IsDir() {
		err = removeDir(sc, reqPath)
	} else {
		err = sc.Remove(reqPath)
	}

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

	sc, err := s.DialSFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	err = sc.Rename(oldPath, newPath)
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

	sc, err := s.DialSFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	err = sc.Mkdir(reqPath)
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

	sc, err := s.DialSFTP()
	if err != nil {
		http.Error(w, "sftp init failed", http.StatusInternalServerError)
		return
	}
	defer sc.Close()

	f, err := sc.Open(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, f)
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

	sc, err := s.DialSFTP()
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	var bodyReader io.Reader = r.Body
	if MaxWriteBodySize > 0 {
		bodyReader = http.MaxBytesReader(w, r.Body, MaxWriteBodySize)
	}
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		jsonError(w, "read body failed: "+err.Error())
		return
	}

	dst, err := sc.Create(filePath)
	if err != nil {
		jsonError(w, "create remote file failed: "+err.Error())
		return
	}
	defer dst.Close()

	_, err = dst.Write(body)
	if err != nil {
		jsonError(w, "write remote file failed: "+err.Error())
		return
	}
	json.NewEncoder(w).Encode(ActionResponse{Success: true})
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
