package main

import (
	"flag"
	"log"
	"net/http"

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
)

func main() {
	flag.Parse()

	a := auth.New(*user, *pass)
	r := mux.NewRouter()

	r.HandleFunc("/login", a.LoginHandler)
	r.HandleFunc("/logout", a.LogoutHandler)

	api := r.PathPrefix("/api/fs/{id}").Subrouter()
	api.HandleFunc("/list", sshterm.HandleFSList).Methods("GET")
	api.HandleFunc("/download", sshterm.HandleFSDownload).Methods("GET")
	api.HandleFunc("/upload", sshterm.HandleFSUpload).Methods("POST")
	api.HandleFunc("/remove", sshterm.HandleFSRemove).Methods("POST")
	api.HandleFunc("/rename", sshterm.HandleFSRename).Methods("POST")
	api.HandleFunc("/mkdir", sshterm.HandleFSMkdir).Methods("POST")

	r.HandleFunc("/ws", sshterm.HandleWebSocket)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(*staticDir)))

	handler := a.Middleware(r)

	if *certFile != "" && *keyFile != "" {
		log.Printf("WebSSH server starting on %s (user=%s, TLS)", *addr, *user)
		log.Fatal(http.ListenAndServeTLS(*addr, *certFile, *keyFile, handler))
	} else {
		log.Printf("WebSSH server starting on %s (user=%s, plain HTTP)", *addr, *user)
		log.Println("WARNING: plain HTTP — all traffic including passwords is visible on the network!")
		log.Println("         use -cert and -key to enable HTTPS encryption")
		log.Fatal(http.ListenAndServe(*addr, handler))
	}
}
