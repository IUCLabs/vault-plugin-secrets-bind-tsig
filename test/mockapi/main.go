// Command mockapi is an in-memory stand-in for the bind-operator companion API,
// used by the e2e tests. It implements the /v1/keys contract the plugin expects
// (create/read/rotate/delete), generating random TSIG material — no Kubernetes
// required. Not for production use.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

type key struct {
	Name       string `json:"name"`
	Algorithm  string `json:"algorithm"`
	Secret     string `json:"secret"`
	KeyName    string `json:"key_name"`
	ClusterRef string `json:"cluster_ref,omitempty"`
}

type store struct {
	mu    sync.Mutex
	keys  map[string]*key
	token string
}

func genSecret() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func (s *store) authOK(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	return r.Header.Get("Authorization") == "Bearer "+s.token
}

func (s *store) handle(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// /v1/keys  or  /v1/keys/<name>[/rotate]
	rest := strings.TrimPrefix(r.URL.Path, "/v1/keys")
	name := strings.Trim(rest, "/")
	rotate := strings.HasSuffix(name, "/rotate")
	name = strings.TrimSuffix(name, "/rotate")

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && name == "": // create
		var req key
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if req.Algorithm == "" {
			req.Algorithm = "hmac-sha256"
		}
		k := &key{Name: req.Name, Algorithm: req.Algorithm, Secret: genSecret(), KeyName: req.Name, ClusterRef: req.ClusterRef}
		s.keys[req.Name] = k
		writeJSON(w, k)
	case r.Method == http.MethodPost && rotate: // rotate
		k, ok := s.keys[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		k.Secret = genSecret()
		writeJSON(w, k)
	case r.Method == http.MethodGet && name != "": // read
		k, ok := s.keys[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, k)
	case r.Method == http.MethodDelete && name != "": // delete
		if _, ok := s.keys[name]; !ok {
			http.NotFound(w, r)
			return
		}
		delete(s.keys, name)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	addr := os.Getenv("MOCKAPI_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	s := &store{keys: map[string]*key{}, token: os.Getenv("MOCKAPI_TOKEN")}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys", s.handle)
	mux.HandleFunc("/v1/keys/", s.handle)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("mock companion API listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux)) //nolint:gosec // test-only mock
}
