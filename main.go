package main

import (
	"flag"
	"log"
	"net/http"

	"webssh/internal/sshterm"

	"github.com/gorilla/mux"
)

var (
	addr      = flag.String("addr", ":8080", "listen address")
	staticDir = flag.String("static", "static", "static files directory")
)

func main() {
	flag.Parse()

	r := mux.NewRouter()
	api := r.PathPrefix("/api/fs/{id}").Subrouter()
	api.HandleFunc("/list", sshterm.HandleFSList).Methods("GET")
	api.HandleFunc("/download", sshterm.HandleFSDownload).Methods("GET")
	api.HandleFunc("/upload", sshterm.HandleFSUpload).Methods("POST")
	api.HandleFunc("/remove", sshterm.HandleFSRemove).Methods("POST")
	api.HandleFunc("/rename", sshterm.HandleFSRename).Methods("POST")
	api.HandleFunc("/mkdir", sshterm.HandleFSMkdir).Methods("POST")
	r.HandleFunc("/ws", sshterm.HandleWebSocket)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(*staticDir)))

	log.Printf("WebSSH server starting on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, r))
}
