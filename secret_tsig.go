package bindtsig

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const tsigKeyType = "tsig_key"

func (b *bindTSIGBackend) tsigKeySecret() *framework.Secret {
	return &framework.Secret{
		Type: tsigKeyType,
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The BindTSIGKey resource name.",
			},
			"key_name": {
				Type:        framework.TypeString,
				Description: "The TSIG key name used in named.conf.",
			},
			"secret": {
				Type:        framework.TypeString,
				Description: "The base64-encoded TSIG key material.",
			},
		},
		Revoke: b.secretRevoke,
		Renew:  b.secretRenew,
	}
}

// secretRevoke deletes the dynamic key (and its BindTSIGKey CR) via the API.
func (b *bindTSIGBackend) secretRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	rawName, ok := req.Secret.InternalData["name"]
	if !ok {
		return nil, errors.New("secret is missing internal name data")
	}
	name, ok := rawName.(string)
	if !ok {
		return nil, errors.New("secret internal name data is not a string")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if err := client.DeleteKey(ctx, name); err != nil {
		return nil, fmt.Errorf("revoking tsig key %q: %w", name, err)
	}
	return nil, nil
}

// secretRenew extends the Vault lease. The key material is unchanged; the
// authoritative lifetime is the Vault lease.
func (b *bindTSIGBackend) secretRenew(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{Secret: req.Secret}, nil
}
