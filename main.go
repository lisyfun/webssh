package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"webssh/internal/auth"
	"webssh/internal/sshterm"

	"github.com/gorilla/mux"
)

var (
	addr      = flag.String("addr", ":8080", "listen address")
	staticDir = flag.String("static", "static", "static files directory")
	user      = flag.String("user", "admin", "login username")
	pass      = flag.String("pass", "admin", "login password")
	certFile  = flag.String("cert", "", "TLS certificate file (enables HTTPS)")
	keyFile   = flag.String("key", "", "TLS private key file")
	urlPath   = flag.String("url", "", "access path prefix (empty = auto-generate random)")
)

func main() {
	flag.Parse()

	basePath := *urlPath
	if basePath == "" {
		basePath = "/" + generateSecret()
	} else {
		basePath = "/" + strings.Trim(basePath, "/")
		if basePath == "/" {
			log.Fatal("-url cannot be / (use empty string to auto-generate)")
		}
	}
	log.Printf("access path: %s", basePath)

	indexBytes, err := os.ReadFile(filepath.Join(*staticDir, "index.html"))
	if err != nil {
		log.Fatal("failed to read index.html:", err)
	}
	indexContent := bytes.ReplaceAll(indexBytes, []byte("__BASE_PATH__"), []byte(basePath))

	a := auth.New(*user, *pass, basePath)
	r := mux.NewRouter()

	r.HandleFunc(basePath+"/login", a.LoginHandler)
	r.HandleFunc(basePath+"/logout", a.LogoutHandler)

	s := r.PathPrefix(basePath).Subrouter()
	s.Use(a.Middleware)
	s.HandleFunc("/ws", sshterm.HandleWebSocket)

	api := s.PathPrefix("/api/fs/{id}").Subrouter()
	api.HandleFunc("/list", sshterm.HandleFSList).Methods("GET")
	api.HandleFunc("/download", sshterm.HandleFSDownload).Methods("GET")
	api.HandleFunc("/upload", sshterm.HandleFSUpload).Methods("POST")
	api.HandleFunc("/remove", sshterm.HandleFSRemove).Methods("POST")
	api.HandleFunc("/rename", sshterm.HandleFSRename).Methods("POST")
	api.HandleFunc("/mkdir", sshterm.HandleFSMkdir).Methods("POST")

	fs := http.FileServer(http.Dir(*staticDir))
	s.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexContent)
			return
		}
		fs.ServeHTTP(w, r)
	}))

	r.PathPrefix("/").Handler(http.NotFoundHandler())

	if *certFile != "" && *keyFile != "" {
		log.Printf("TLS enabled")
		log.Fatal(http.ListenAndServeTLS(*addr, *certFile, *keyFile, r))
	} else {
		log.Println("WARNING: plain HTTP — all traffic including passwords is visible on the network!")
		log.Println("         use -cert and -key to enable HTTPS encryption")
		log.Fatal(http.ListenAndServe(*addr, r))
	}
}

func generateSecret() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
