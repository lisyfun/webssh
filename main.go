package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"webssh/internal/auth"
	"webssh/internal/sshterm"
	"webssh/internal/store"

	"github.com/gorilla/mux"
)

var (
	addr     = flag.String("addr", "8080", "listen port or address (e.g. 8080 or :8080)")
	user     = flag.String("user", "admin", "login username")
	pass     = flag.String("pass", "", "login password (empty = auto-generate random)")
	certFile = flag.String("cert", "", "TLS certificate file (enables HTTPS)")
	keyFile  = flag.String("key", "", "TLS private key file")
	urlPath  = flag.String("url", "", "access path prefix (empty = auto-generate random)")
	maxBody  = flag.Int64("maxbody", 50, "max editor body size in MB (0 = no limit)")
	dbPath   = flag.String("db", "webssh.db", "path to SQLite database file")
)

//go:embed all:static
var staticFS embed.FS

func main() {
	flag.Parse()

	listenAddr := *addr
	if !strings.HasPrefix(listenAddr, ":") {
		listenAddr = ":" + listenAddr
	}

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

	password := *pass
	if password == "" {
		password = generatePassword()
		log.Printf("generated password: %s", password)
	}
	log.Printf("login user: %s", *user)

	if *maxBody < 0 {
		log.Fatal("-maxbody must be >= 0")
	}
	if *maxBody == 0 {
		sshterm.MaxWriteBodySize = 0
	} else {
		sshterm.MaxWriteBodySize = *maxBody << 20
	}

	st, err := store.New(*dbPath)
	if err != nil {
		log.Fatal("failed to init store:", err)
	}
	defer st.Close()

	if err := st.EnsureUser(context.Background(), *user, password); err != nil {
		log.Fatal("failed to create user:", err)
	}
	// Start with empty cached password; auth will verify via DB and cache on first successful login.
	a := auth.New(st, *user, "", basePath)

	indexBytes, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		log.Fatal("failed to read index.html:", err)
	}
	indexContent := bytes.ReplaceAll(indexBytes, []byte("__BASE_PATH__"), []byte(basePath))
	r := mux.NewRouter()

	r.HandleFunc(basePath+"/login", a.LoginHandler)
	r.HandleFunc(basePath+"/logout", a.LogoutHandler)
	r.HandleFunc(basePath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, basePath+"/", http.StatusFound)
	})

	s := r.PathPrefix(basePath).Subrouter()
	s.Use(a.Middleware)
	s.HandleFunc("/ws", sshterm.HandleWebSocket)
	s.HandleFunc("/change-password", a.ChangePasswordHandler).Methods("POST")

	api := s.PathPrefix("/api").Subrouter()

	api.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			store.HandleListServers(st, w, r)
		case "POST":
			store.HandleCreateServer(st, w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	api.HandleFunc("/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			store.HandleUpdateServer(st, w, r)
		case "DELETE":
			store.HandleDeleteServer(st, w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}).Methods("PUT", "DELETE")
	api.HandleFunc("/servers/batch", func(w http.ResponseWriter, r *http.Request) {
		store.HandleBatchImport(st, w, r)
	}).Methods("POST")

	fsAPI := api.PathPrefix("/fs/{id}").Subrouter()
	fsAPI.HandleFunc("/list", sshterm.HandleFSList).Methods("GET")
	fsAPI.HandleFunc("/download", sshterm.HandleFSDownload).Methods("GET")
	fsAPI.HandleFunc("/upload", sshterm.HandleFSUpload).Methods("POST")
	fsAPI.HandleFunc("/remove", sshterm.HandleFSRemove).Methods("POST")
	fsAPI.HandleFunc("/rename", sshterm.HandleFSRename).Methods("POST")
	fsAPI.HandleFunc("/mkdir", sshterm.HandleFSMkdir).Methods("POST")
	fsAPI.HandleFunc("/read", sshterm.HandleFSRead).Methods("GET")
	fsAPI.HandleFunc("/write", sshterm.HandleFSWrite).Methods("POST")

	staticSub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticSub))
	s.PathPrefix("/").Handler(http.StripPrefix(basePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" {
			http.Redirect(w, r, basePath+"/", http.StatusFound)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexContent)
			return
		}
		fileServer.ServeHTTP(w, r)
	})))

	r.PathPrefix("/").Handler(http.NotFoundHandler())

	if *certFile != "" && *keyFile != "" {
		log.Printf("TLS enabled")
		log.Fatal(http.ListenAndServeTLS(listenAddr, *certFile, *keyFile, r))
	} else {
		log.Fatal(http.ListenAndServe(listenAddr, r))
	}
}

func generateSecret() string {
	b := make([]byte, 5)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generatePassword() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=?"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
