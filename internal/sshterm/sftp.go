package sshterm

import (
	"errors"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

func SanitizePath(p string) (string, error) {
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

type FileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	IsDir   bool   `json:"isDir"`
	ModTime string `json:"modTime"`
}

func RemoveDir(sc *sftp.Client, dirPath string) error {
	entries, err := sc.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := path.Join(dirPath, e.Name())
		if e.IsDir() {
			if err := RemoveDir(sc, p); err != nil {
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

func FormatFileEntry(e os.FileInfo) FileEntry {
	return FileEntry{
		Name:    e.Name(),
		Size:    e.Size(),
		Mode:    e.Mode().String(),
		IsDir:   e.IsDir(),
		ModTime: e.ModTime().Format(time.RFC3339),
	}
}
