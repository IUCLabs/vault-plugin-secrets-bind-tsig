package bindtsig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func getTestBackend(t *testing.T) (*bindTSIGBackend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("creating backend: %v", err)
	}
	return b.(*bindTSIGBackend), config.StorageView
}

// mockAPI is an in-memory companion API implementing the /v1/keys contract.
type mockAPI struct {
	server *httptest.Server
	mu     sync.Mutex
	keys   map[string]*tsigKey
}

func newMockAPI(t *testing.T) *mockAPI {
	t.Helper()
	m := &mockAPI{keys: map[string]*tsigKey{}}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockAPI) handle(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/keys"), "/")
	rotate := strings.HasSuffix(name, "/rotate")
	name = strings.TrimSuffix(name, "/rotate")

	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && name == "":
		var req tsigKey
		_ = json.NewDecoder(r.Body).Decode(&req)
		k := &tsigKey{Name: req.Name, Algorithm: "hmac-sha256", Secret: "s3cr3t-" + req.Name, KeyName: req.Name, ClusterRef: req.ClusterRef}
		m.keys[req.Name] = k
		_ = json.NewEncoder(w).Encode(k)
	case r.Method == http.MethodPost && rotate:
		k := m.keys[name]
		if k == nil {
			http.NotFound(w, r)
			return
		}
		k.Secret = k.Secret + "-rot"
		_ = json.NewEncoder(w).Encode(k)
	case r.Method == http.MethodGet:
		k := m.keys[name]
		if k == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(k)
	case r.Method == http.MethodDelete:
		delete(m.keys, name)
		w.WriteHeader(http.StatusNoContent)
	}
}

func TestDynamicCredentialLifecycle(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	m := newMockAPI(t)

	// config
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"api_url": m.server.URL, "default_cluster_ref": "bind-authoritative"},
	}); err != nil {
		t.Fatalf("config: %v", err)
	}

	// role
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/ephemeral", Storage: s,
		Data: map[string]interface{}{"ttl": "1h", "max_ttl": "24h"},
	}); err != nil {
		t.Fatalf("role: %v", err)
	}

	// mint
	resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "creds/ephemeral", Storage: s})
	if err != nil || resp == nil || resp.Secret == nil {
		t.Fatalf("creds: err=%v resp=%v", err, resp)
	}
	name := resp.Data["name"].(string)
	if !strings.HasPrefix(name, "dyn-ephemeral-") {
		t.Fatalf("unexpected dynamic name %q", name)
	}
	if _, ok := m.keys[name]; !ok {
		t.Fatalf("key %q not created in companion API", name)
	}
	if resp.Data["secret"].(string) == "" {
		t.Fatal("empty secret returned")
	}

	// revoke -> deleted
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/ephemeral", Storage: s, Secret: resp.Secret,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := m.keys[name]; ok {
		t.Fatalf("key %q still present after revoke", name)
	}
}

func TestStaticRoleProvisionAndRead(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	m := newMockAPI(t)

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"api_url": m.server.URL},
	}); err != nil {
		t.Fatalf("config: %v", err)
	}
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "static-roles/client-update", Storage: s,
		Data: map[string]interface{}{"rotation_period": "720h"},
	}); err != nil {
		t.Fatalf("static-role: %v", err)
	}
	if _, ok := m.keys["client-update"]; !ok {
		t.Fatal("static key not provisioned in companion API")
	}
	resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "static-creds/client-update", Storage: s})
	if err != nil || resp == nil {
		t.Fatalf("static-creds: err=%v resp=%v", err, resp)
	}
	if resp.Data["secret"].(string) == "" {
		t.Fatal("static-creds returned empty secret")
	}
	if resp.Data["key_name"].(string) != "client-update" {
		t.Fatalf("unexpected key_name %v", resp.Data["key_name"])
	}
}
