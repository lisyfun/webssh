package sshterm

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/sftp"
)

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
	reqPath = path.Clean(reqPath)

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := sftp.NewClient(s.Client)
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
	filePath = path.Clean(filePath)

	s, err := Manager.Get(sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	sc, err := sftp.NewClient(s.Client)
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

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := sftp.NewClient(s.Client)
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

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
	dst, err := sc.Create(remotePath)
	if err != nil {
		jsonError(w, "create remote file failed: "+err.Error())
		return
	}
	defer dst.Close()

	bw := bufio.NewWriterSize(dst, 1<<20)
	io.Copy(bw, part)
	bw.Flush()
	json.NewEncoder(w).Encode(ActionResponse{Success: true})
}

func HandleFSRemove(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var req struct {
		Path string `json:"path"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := sftp.NewClient(s.Client)
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	info, err := sc.Stat(req.Path)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	if info.IsDir() {
		err = removeDir(sc, req.Path)
	} else {
		err = sc.Remove(req.Path)
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

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := sftp.NewClient(s.Client)
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	err = sc.Rename(req.OldPath, req.NewPath)
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

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := sftp.NewClient(s.Client)
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	err = sc.Mkdir(req.Path)
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
	filePath = path.Clean(filePath)

	s, err := Manager.Get(sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	sc, err := sftp.NewClient(s.Client)
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
	filePath = path.Clean(filePath)

	s, err := Manager.Get(sessionID)
	if err != nil {
		jsonError(w, "session not found")
		return
	}

	sc, err := sftp.NewClient(s.Client)
	if err != nil {
		jsonError(w, "sftp init failed: "+err.Error())
		return
	}
	defer sc.Close()

	body, err := io.ReadAll(r.Body)
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

	dst.Write(body)
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


