package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"webssh/internal/auth"
	"webssh/internal/sshterm"
	"webssh/internal/store"

	"github.com/gorilla/mux"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
	"golang.org/x/crypto/ssh"
)

var (
	addr      = flag.String("addr", "8080", "listen port or address (e.g. 8080 or :8080)")
	user      = flag.String("user", "admin", "login username")
	pass      = flag.String("pass", "", "login password (empty = auto-generate random)")
	certFile  = flag.String("cert", "", "TLS certificate file (enables HTTPS)")
	keyFile   = flag.String("key", "", "TLS private key file")
	urlPath   = flag.String("url", "", "access path prefix (empty = auto-generate random)")
	maxBody   = flag.Int64("maxbody", 50, "max editor body size in MB (0 = no limit)")
	dbPath    = flag.String("db", "webssh.db", "path to SQLite database file")
	enable2FA = flag.Bool("2fa", false, "enable two-factor authentication (TOTP)")
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
	sshterm.SetHostKeyPersister(st)

	password := *pass
	if password == "" {
		exists, err := st.UserExists(context.Background(), *user)
		if err != nil || !exists {
			password = generatePassword()
			log.Printf("generated password: %s", password)
		}
	}
	if password == "" {
		log.Printf("login user: %s (use existing password)", *user)
	} else {
		log.Printf("login user: %s", *user)
		if err := st.EnsureUser(context.Background(), *user, password); err != nil {
			log.Fatal("failed to create user:", err)
		}
	}

	if *enable2FA {
		st.DisableTOTP(context.Background(), *user)
		log.Printf("双因素认证已重置，下次登录将引导扫码设置")
	}

	a := auth.New(st, *user, basePath, *maxBody, *enable2FA)

	indexBytes, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		log.Fatal("failed to read index.html:", err)
	}

	m := minify.New()
	m.Add("text/html", &html.Minifier{
		KeepDocumentTags: true,
		KeepEndTags:      true,
	})
	m.Add("text/javascript", &js.Minifier{})
	indexBytes, err = m.Bytes("text/html", indexBytes)
	if err != nil {
		log.Fatal("failed to minify index.html:", err)
	}

	indexContent := bytes.ReplaceAll(indexBytes, []byte("__BASE_PATH__"), []byte(basePath))
	log.Printf("index.html: %d bytes (%d minified)", len(indexBytes), len(indexContent))

	decryptField := func(r *http.Request, s string) (string, error) {
		return a.DecryptFieldStrict(r, s)
	}
	resolveServer := func(id string) (*sshterm.ConnectParams, error) {
		svr, err := st.GetServer(context.Background(), id)
		if err != nil {
			return nil, err
		}
		return &sshterm.ConnectParams{
			ServerID:   svr.ID,
			Host:       svr.Host,
			Port:       svr.Port,
			Username:   svr.User,
			Password:   svr.Password,
			PrivateKey: svr.PrivateKey,
		}, nil
	}

	r := mux.NewRouter()
	r.HandleFunc(basePath+"/login", a.LoginHandler)
	r.HandleFunc(basePath+"/login/2fa", a.TOTPLoginHandler)
	r.HandleFunc(basePath+"/logout", a.LogoutHandler)
	r.HandleFunc(basePath+"/complete-2fa-setup", a.CompleteTOTPSetupHandler)
	r.HandleFunc(basePath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, basePath+"/", http.StatusFound)
	})

	s := r.PathPrefix(basePath).Subrouter()
	s.Use(a.Middleware)
	s.HandleFunc("/ws", sshterm.HandleWebSocketWithResolver(resolveServer, decryptField))
	s.HandleFunc("/api/key", a.KeyHandler).Methods("GET")
	s.HandleFunc("/api/2fa/status", a.TOTPStatusHandler).Methods("GET")

	api := s.PathPrefix("/api").Subrouter()
	api.Use(a.CSRFValidate)
	api.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			store.HandleListServers(st, w, r)
		case "POST":
			store.HandleCreateServer(st, decryptField, w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	api.HandleFunc("/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			store.HandleUpdateServer(st, decryptField, w, r)
		case "DELETE":
			store.HandleDeleteServer(st, w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}).Methods("PUT", "DELETE")
	api.HandleFunc("/servers/batch", func(w http.ResponseWriter, r *http.Request) {
		store.HandleBatchImport(st, decryptField, w, r)
	}).Methods("POST")
	api.HandleFunc("/change-password", a.ChangePasswordHandler).Methods("POST")
	api.HandleFunc("/host-keys", func(w http.ResponseWriter, r *http.Request) {
		keys, err := st.ListHostKeys()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": keys})
	}).Methods("GET")
	api.HandleFunc("/host-keys/{addr}", func(w http.ResponseWriter, r *http.Request) {
		addr := mux.Vars(r)["addr"]
		if err := st.DeleteHostKey(addr); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sshterm.ForgetHostKey(addr)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}).Methods("DELETE")

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

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		var err error
		if *certFile != "" && *keyFile != "" {
			log.Printf("TLS enabled")
			err = server.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	stop() // restore default signal handling so a second Ctrl+C forces exit
	log.Printf("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func generateSecret() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatal("failed to generate random path:", err)
	}
	return hex.EncodeToString(b)
}

func generatePassword() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_+=?"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatal("failed to generate random password:", err)
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
