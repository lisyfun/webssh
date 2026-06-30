package sshterm

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

func TestSanitizePathRejectsTraversalBeforeClean(t *testing.T) {
	bad := []string{
		"../etc/passwd",
		"/var/../etc/passwd",
		"a/../b",
		"..",
	}
	for _, p := range bad {
		if got, err := sanitizePath(p); err == nil {
			t.Fatalf("sanitizePath(%q) = %q, nil; want error", p, got)
		}
	}
}

func TestSanitizePathAllowsNormalAbsoluteAndRelativePaths(t *testing.T) {
	tests := map[string]string{
		"":        "/",
		".":       "/",
		"/tmp//x": "/tmp/x",
		"tmp/x":   "tmp/x",
	}
	for in, want := range tests {
		got, err := sanitizePath(in)
		if err != nil {
			t.Fatalf("sanitizePath(%q) unexpected error: %v", in, err)
		}
		if got != want {
			t.Fatalf("sanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeUploadNameRejectsPathNames(t *testing.T) {
	bad := []string{"", ".", "..", "a/b", `a\b`, "bad\x00name"}
	for _, name := range bad {
		if got, err := sanitizeUploadName(name); err == nil {
			t.Fatalf("sanitizeUploadName(%q) = %q, nil; want error", name, got)
		}
	}
}

func TestReplaceRemoteFileRestoresBackupWhenReplacementFails(t *testing.T) {
	r := &fakeRenamer{
		files: map[string]bool{
			"/file": true,
			"/tmp":  true,
		},
		failTmpToFile: errors.New("replacement failed"),
	}

	err := replaceRemoteFile(r, "/tmp", "/file")
	if err == nil {
		t.Fatal("replaceRemoteFile returned nil, want error")
	}
	if !r.files["/file"] {
		t.Fatal("original file was not restored")
	}
	if !r.files["/tmp"] {
		t.Fatal("tmp file should remain for caller cleanup")
	}
}

type fakeRenamer struct {
	files         map[string]bool
	failTmpToFile error
}

func (f *fakeRenamer) Rename(oldname, newname string) error {
	if oldname == "/tmp" && strings.HasPrefix(newname, "/file") && f.failTmpToFile != nil {
		return f.failTmpToFile
	}
	if !f.files[oldname] {
		return fs.ErrNotExist
	}
	delete(f.files, oldname)
	f.files[newname] = true
	return nil
}

func (f *fakeRenamer) Remove(name string) error {
	delete(f.files, name)
	return nil
}

func (f *fakeRenamer) Stat(name string) (fs.FileInfo, error) {
	if !f.files[name] {
		return nil, fs.ErrNotExist
	}
	return fakeFileInfo{}, nil
}

type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() fs.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
