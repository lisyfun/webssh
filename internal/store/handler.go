package store

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

type ServerResponse struct {
	Success bool     `json:"success"`
	Data    any      `json:"data,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func jsonResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func HandleListServers(st *Store, w http.ResponseWriter, r *http.Request) {
	servers, err := st.ListServers(context.Background())
	if err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	jsonResp(w, ServerResponse{Success: true, Data: servers})
}

func HandleCreateServer(st *Store, w http.ResponseWriter, r *http.Request) {
	var svr Server
	if err := json.NewDecoder(r.Body).Decode(&svr); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: "invalid json: " + err.Error()})
		return
	}
	if svr.Host == "" || svr.User == "" {
		jsonResp(w, ServerResponse{Success: false, Error: "host and user are required"})
		return
	}
	if svr.Port == 0 {
		svr.Port = 22
	}

	if err := st.CreateServer(context.Background(), &svr); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	jsonResp(w, ServerResponse{Success: true, Data: svr})
}

func HandleUpdateServer(st *Store, w http.ResponseWriter, r *http.Request) {
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
	if svr.Port == 0 {
		svr.Port = 22
	}

	if err := st.UpdateServer(context.Background(), &svr); err != nil {
		jsonResp(w, ServerResponse{Success: false, Error: err.Error()})
		return
	}
	jsonResp(w, ServerResponse{Success: true, Data: svr})
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

func HandleBatchImport(st *Store, w http.ResponseWriter, r *http.Request) {
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
		if svr.Port == 0 {
			svr.Port = 22
		}
		if svr.User == "" {
			svr.User = "root"
		}
		if svr.ID == "" {
			svr.ID = "" // will be set by frontend
		}
		if err := st.CreateServer(context.Background(), svr); err != nil {
			jsonResp(w, ServerResponse{Success: false, Error: "import failed: " + err.Error()})
			return
		}
		imported++
	}

	jsonResp(w, ServerResponse{Success: true, Data: map[string]int{"imported": imported}})
}
