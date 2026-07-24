package store

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

type ServerResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type DecryptFunc func(r *http.Request, value string) (string, error)

func jsonResp(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func publicServer(svr Server) Server {
	svr.HasPassword = svr.Password != "" || svr.HasPassword
	svr.HasPrivateKey = svr.PrivateKey != "" || svr.HasPrivateKey
	svr.Password = ""
	svr.PrivateKey = ""
	return svr
}

func HandleListServers(st *Store, w http.ResponseWriter, r *http.Request) {
	servers, err := st.ListServers(context.Background())
	if err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	jsonResp(w, ServerResponse{Success: true, Data: servers})
}

func HandleCreateServer(st *Store, decrypt DecryptFunc, w http.ResponseWriter, r *http.Request) {
	var svr Server
	if err := json.NewDecoder(r.Body).Decode(&svr); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: "invalid json: " + err.Error()})
		return
	}
	if svr.Host == "" || svr.User == "" {
		jsonResp(w, ServerResponse{Success: false, Error: "host and user are required"})
		return
	}
	if err := validateHost(svr.Host); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	if svr.Port == 0 {
		svr.Port = 22
	}
	if decrypt != nil {
		var err error
		if svr.Password, err = decrypt(r, svr.Password); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: "invalid encrypted password"})
			return
		}
		if svr.PrivateKey, err = decrypt(r, svr.PrivateKey); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: "invalid encrypted private key"})
			return
		}
	}
	if svr.AuthType == "key" {
		if svr.PrivateKey == "" {
			jsonResp(w, ServerResponse{Success: false, Error: "private key is required"})
			return
		}
		svr.Password = ""
	} else {
		svr.AuthType = "password"
		if svr.Password == "" {
			jsonResp(w, ServerResponse{Success: false, Error: "password is required"})
			return
		}
		svr.PrivateKey = ""
	}

	if err := st.CreateServer(context.Background(), &svr); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	jsonResp(w, ServerResponse{Success: true, Data: publicServer(svr)})
}

func HandleUpdateServer(st *Store, decrypt DecryptFunc, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var svr Server
	if err := json.NewDecoder(r.Body).Decode(&svr); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: "invalid json: " + err.Error()})
		return
	}
	svr.ID = id

	if svr.Host == "" || svr.User == "" {
		jsonResp(w, ServerResponse{Success: false, Error: "host and user are required"})
		return
	}
	if err := validateHost(svr.Host); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	if svr.Port == 0 {
		svr.Port = 22
	}
	if decrypt != nil {
		var err error
		if svr.Password, err = decrypt(r, svr.Password); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: "invalid encrypted password"})
			return
		}
		if svr.PrivateKey, err = decrypt(r, svr.PrivateKey); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: "invalid encrypted private key"})
			return
		}
	}

	existing, err := st.GetServer(context.Background(), id)
	if err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	if svr.AuthType == "key" {
		if svr.PrivateKey == "" {
			svr.PrivateKey = existing.PrivateKey
		}
		svr.Password = ""
	} else {
		if svr.Password == "" {
			svr.Password = existing.Password
		}
		svr.PrivateKey = ""
	}

	if err := st.UpdateServer(context.Background(), &svr); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	jsonResp(w, ServerResponse{Success: true, Data: publicServer(svr)})
}

func HandleDeleteServer(st *Store, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := st.DeleteServer(context.Background(), id); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	jsonResp(w, ServerResponse{Success: true})
}

func HandleBatchImport(st *Store, decrypt DecryptFunc, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Servers []Server `json:"servers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: "invalid json: " + err.Error()})
		return
	}

	imported := 0
	for i := range req.Servers {
		svr := &req.Servers[i]
		if svr.Host == "" {
			continue
		}
		if err := validateHost(svr.Host); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
			return
		}
		if svr.Port == 0 {
			svr.Port = 22
		}
		if svr.User == "" {
			svr.User = "root"
		}
		if decrypt != nil {
			var err error
			if svr.Password, err = decrypt(r, svr.Password); err != nil {
				jsonResp(w, ServerResponse{Success: false, Error: "invalid encrypted password"})
				return
			}
			if svr.PrivateKey, err = decrypt(r, svr.PrivateKey); err != nil {
				jsonResp(w, ServerResponse{Success: false, Error: "invalid encrypted private key"})
				return
			}
		}
		if err := st.CreateServer(context.Background(), svr); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: "import failed: " + err.Error()})
			return
		}
		imported++
	}

	jsonResp(w, ServerResponse{Success: true, Data: map[string]int{"imported": imported}})
}

var blockedHosts = []string{
	"localhost",
	"127.0.0.1",
	"::1",
	"0.0.0.0",
	"169.254.169.254",
	"metadata.google.internal",
	"100.100.100.200", // aliyun metadata
}

func validateHost(host string) error {
	lower := strings.ToLower(host)
	for _, b := range blockedHosts {
		if lower == b {
			return errors.New("host not allowed")
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return errors.New("host not allowed")
		}
	}
	return nil
}
