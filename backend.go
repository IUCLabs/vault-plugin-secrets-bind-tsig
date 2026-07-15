// Package bindtsig implements a Vault / OpenBao secrets engine that manages
// BIND TSIG keys through the bind-operator's companion API. Static roles expose
// a named key with managed rotation; dynamic roles mint unique, lease-bound
// keys. The companion API owns the BindTSIGKey CRs; the operator reconciles
// them into the actual key material.
package bindtsig

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// errBackendNotConfigured is returned when a credential is requested before the
// companion API connection has been configured.
var errBackendNotConfigured = errors.New("bind-tsig backend not configured; write config first")

type bindTSIGBackend struct {
	*framework.Backend

	lock   sync.RWMutex
	client *apiClient
}

// Factory returns a configured bind-tsig secrets backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *bindTSIGBackend {
	b := &bindTSIGBackend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathRole(b),
				pathRolesList(b),
				pathCredentials(b),
				pathStaticRole(b),
				pathStaticRolesList(b),
				pathStaticCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.tsigKeySecret(),
		},
		Invalidate:  b.invalidate,
		WALRollback: nil,
	}

	return b
}

// reset drops the cached API client so it is rebuilt from storage on the next
// request. Called when the config changes.
func (b *bindTSIGBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears the cached client when the config is written from another
// cluster node.
func (b *bindTSIGBackend) invalidate(_ context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

// getClient returns a cached companion-API client, building one from stored
// config if necessary.
func (b *bindTSIGBackend) getClient(ctx context.Context, s logical.Storage) (*apiClient, error) {
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}
	b.client = client
	return b.client, nil
}

const backendHelp = `
The bind-tsig secrets engine manages BIND TSIG keys via the bind-operator
companion API.

Static roles expose a stable, named key whose material Vault rotates on a
schedule (the key name never changes, so zone allow-update clauses stay valid).
Dynamic roles mint a unique key per request, bound to a Vault lease and deleted
on revocation.
`
