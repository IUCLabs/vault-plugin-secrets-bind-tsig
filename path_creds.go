package bindtsig

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *bindTSIGBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "bind-tsig",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the dynamic role to mint a key for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    "Mint a dynamic TSIG key from a role.",
		HelpDescription: "Reading this path provisions a new, lease-bound TSIG key via the companion API; the key is deleted when the lease is revoked.",
	}
}

func (b *bindTSIGBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	ttl, maxTTL := b.resolveTTLs(role.TTL, role.MaxTTL)

	suffix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("generating key name suffix: %w", err)
	}

	key, err := client.CreateKey(ctx, createKeyRequest{
		Name:       fmt.Sprintf("dyn-%s-%s", roleName, suffix[:8]),
		Algorithm:  firstNonEmpty(role.Algorithm, config.DefaultAlgorithm),
		ClusterRef: firstNonEmpty(role.ClusterRef, config.DefaultClusterRef),
	})
	if err != nil {
		return nil, fmt.Errorf("minting tsig key: %w", err)
	}

	internal := map[string]interface{}{"name": key.Name}
	external := map[string]interface{}{
		"name":        key.Name,
		"key_name":    key.KeyName,
		"algorithm":   key.Algorithm,
		"secret":      key.Secret,
		"cluster_ref": key.ClusterRef,
	}

	resp := b.Secret(tsigKeyType).Response(external, internal)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	resp.Secret.Renewable = true
	return resp, nil
}

// resolveTTLs clamps a role's TTL/MaxTTL against the mount and system limits.
func (b *bindTSIGBackend) resolveTTLs(roleTTL, roleMaxTTL time.Duration) (ttl, maxTTL time.Duration) {
	sysMaxTTL := b.System().MaxLeaseTTL()
	maxTTL = roleMaxTTL
	if maxTTL <= 0 || maxTTL > sysMaxTTL {
		maxTTL = sysMaxTTL
	}
	ttl = roleTTL
	if ttl <= 0 {
		ttl = b.System().DefaultLeaseTTL()
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl, maxTTL
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
