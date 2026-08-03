package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sshConfigEntry is one Host block from ~/.ssh/config.
type sshConfigEntry struct {
	host, hostName, user, port, identityFile string
}

// parseSSHConfigEntries extracts Host blocks from ssh config text. Only the
// fields relevant to server import (Host/HostName/User/Port/IdentityFile) are
// kept; everything else is ignored.
func parseSSHConfigEntries(data []byte) []*sshConfigEntry {
	var entries []*sshConfigEntry
	var cur *sshConfigEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		key := strings.ToLower(fields[0])
		if key == "host" {
			cur = &sshConfigEntry{host: strings.Join(fields[1:], " ")}
			entries = append(entries, cur)
			continue
		}
		if cur == nil {
			continue
		}
		val := strings.Join(fields[1:], " ")
		switch key {
		case "hostname":
			cur.hostName = val
		case "user":
			cur.user = val
		case "port":
			cur.port = val
		case "identityfile":
			cur.identityFile = val
		}
	}
	return entries
}

func genID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// HandleSSHConfigImport parses ~/.ssh/config on the server machine and imports
// its Host entries as servers. ssh config carries no passwords, so entries
// without a readable IdentityFile are imported credential-less (fill in
// later). IdentityFile paths are expanded and read into PrivateKey when
// possible. Already-imported hosts (same name+host) are skipped, so the import
// is idempotent. Hosts blocked by validateHost (SSRF guard) are skipped.
func HandleSSHConfigImport(st *Store, w http.ResponseWriter, r *http.Request) {
	home, err := os.UserHomeDir()
	if err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: "读取 ~/.ssh/config 失败: " + err.Error()})
		return
	}
	entries := parseSSHConfigEntries(data)

	existing, _ := st.ListServers(r.Context())
	imported := 0
	for _, e := range entries {
		// Skip wildcard patterns like "Host *" or "foo*.bar".
		if e.host == "" || strings.ContainsAny(e.host, "*?") {
			continue
		}
		host := e.hostName
		if host == "" {
			host = e.host
		}
		if err := validateHost(host); err != nil {
			continue
		}
		port := 22
		if p, err := strconv.Atoi(e.port); err == nil && p > 0 {
			port = p
		}
		user := e.user
		if user == "" {
			user = os.Getenv("USER")
		}
		if user == "" {
			user = "root"
		}
		dup := false
		for _, s := range existing {
			if s.Name == e.host && s.Host == host {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		svr := &Server{
			ID:       genID(),
			Name:     e.host,
			Host:     host,
			Port:     port,
			User:     user,
			AuthType: "password",
		}
		if e.identityFile != "" {
			p := e.identityFile
			if strings.HasPrefix(p, "~") {
				p = filepath.Join(home, p[2:])
			}
			if keyData, err := os.ReadFile(p); err == nil && len(keyData) > 0 {
				svr.AuthType = "key"
				svr.PrivateKey = string(keyData)
			}
		}
		if err := st.CreateServer(context.Background(), svr); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: "import " + e.host + " failed: " + err.Error()})
			return
		}
		imported++
	}

	jsonResp(w, ServerResponse{Success: true, Data: map[string]int{"imported": imported}})
}
