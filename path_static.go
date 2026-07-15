package bindtsig

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const staticRoleStoragePrefix = "static-role/"

// bindTSIGStaticRole is a stable, named key whose material Vault rotates on a
// schedule. The key name never changes, so zone allow-update clauses stay valid
// across rotations.
type bindTSIGStaticRole struct {
	KeyName        string        `json:"key_name"`
	Algorithm      string        `json:"algorithm"`
	ClusterRef     string        `json:"cluster_ref"`
	RotationPeriod time.Duration `json:"rotation_period"`
	LastRotation   time.Time     `json:"last_rotation"`
}

func pathStaticRole(b *bindTSIGBackend) *framework.Path {
	return &framework.Path{
		Pattern: "static-roles/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "bind-tsig",
			OperationSuffix: "static-role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the static role.",
				Required:    true,
			},
			"key_name": {
				Type:        framework.TypeString,
				Description: "TSIG key name to manage (defaults to the role name). Zone allow-update clauses reference this.",
			},
			"algorithm": {
				Type:        framework.TypeString,
				Description: "TSIG algorithm (defaults to the config default).",
			},
			"cluster_ref": {
				Type:        framework.TypeString,
				Description: "BindCluster the key is scoped to (defaults to the config default).",
			},
			"rotation_period": {
				Type:        framework.TypeDurationSecond,
				Description: "How often the key material is rotated. 0 disables automatic rotation.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathStaticRoleRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathStaticRoleWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathStaticRoleDelete},
		},
		ExistenceCheck:  b.pathStaticRoleExistenceCheck,
		HelpSynopsis:    "Manage static (rotated) TSIG-key roles.",
		HelpDescription: "Static roles expose a stable, named key whose material is rotated on a schedule; read static-creds/<name> for the current value.",
	}
}

func pathStaticRolesList(b *bindTSIGBackend) *framework.Path {
	return &framework.Path{
		Pattern: "static-roles/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "bind-tsig",
			OperationSuffix: "static-roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathStaticRolesList},
		},
		HelpSynopsis: "List static roles.",
	}
}

func pathStaticCredentials(b *bindTSIGBackend) *framework.Path {
	return &framework.Path{
		Pattern: "static-creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "bind-tsig",
			OperationSuffix: "static-credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the static role.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathStaticCredentialsRead},
		},
		HelpSynopsis:    "Read the current material for a static TSIG key.",
		HelpDescription: "Returns the current key material, rotating it first if the rotation period has elapsed.",
	}
}

func (b *bindTSIGBackend) pathStaticRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getStaticRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *bindTSIGBackend) pathStaticRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getStaticRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"key_name":        role.KeyName,
			"algorithm":       role.Algorithm,
			"cluster_ref":     role.ClusterRef,
			"rotation_period": int64(role.RotationPeriod.Seconds()),
			"last_rotation":   role.LastRotation.Format(time.RFC3339),
		},
	}, nil
}

func (b *bindTSIGBackend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	created := role == nil
	if created {
		role = &bindTSIGStaticRole{KeyName: name}
	}

	if v, ok := data.GetOk("key_name"); ok {
		role.KeyName = v.(string)
	}
	if v, ok := data.GetOk("algorithm"); ok {
		role.Algorithm = v.(string)
	}
	if v, ok := data.GetOk("cluster_ref"); ok {
		role.ClusterRef = v.(string)
	}
	if v, ok := data.GetOk("rotation_period"); ok {
		role.RotationPeriod = time.Duration(v.(int)) * time.Second
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	// Provision the key on creation so it exists immediately.
	if created {
		client, cerr := b.getClient(ctx, req.Storage)
		if cerr != nil {
			return nil, cerr
		}
		if _, cerr := client.CreateKey(ctx, createKeyRequest{
			Name:       role.KeyName,
			Algorithm:  firstNonEmpty(role.Algorithm, config.DefaultAlgorithm),
			ClusterRef: firstNonEmpty(role.ClusterRef, config.DefaultClusterRef),
			Static:     true,
		}); cerr != nil {
			return nil, fmt.Errorf("provisioning static tsig key: %w", cerr)
		}
		role.LastRotation = time.Now().UTC()
	}

	return nil, setJSON(ctx, req.Storage, staticRoleStoragePrefix+name, role)
}

func (b *bindTSIGBackend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role != nil {
		if client, cerr := b.getClient(ctx, req.Storage); cerr == nil {
			_ = client.DeleteKey(ctx, role.KeyName)
		}
	}
	return nil, req.Storage.Delete(ctx, staticRoleStoragePrefix+name)
}

func (b *bindTSIGBackend) pathStaticRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, staticRoleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *bindTSIGBackend) pathStaticCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("static role %q does not exist", name), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Rotate first if the rotation period has elapsed.
	rotated := false
	if role.RotationPeriod > 0 && time.Since(role.LastRotation) >= role.RotationPeriod {
		if _, rerr := client.RotateKey(ctx, role.KeyName); rerr != nil {
			return nil, fmt.Errorf("rotating static tsig key: %w", rerr)
		}
		role.LastRotation = time.Now().UTC()
		rotated = true
	}

	key, err := client.GetKey(ctx, role.KeyName)
	if err != nil {
		return nil, fmt.Errorf("reading static tsig key: %w", err)
	}
	if rotated {
		if serr := setJSON(ctx, req.Storage, staticRoleStoragePrefix+name, role); serr != nil {
			return nil, serr
		}
	}

	ttl := role.RotationPeriod - time.Since(role.LastRotation)
	if ttl < 0 {
		ttl = 0
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"key_name":        key.KeyName,
			"algorithm":       key.Algorithm,
			"secret":          key.Secret,
			"cluster_ref":     key.ClusterRef,
			"last_rotation":   role.LastRotation.Format(time.RFC3339),
			"ttl":             int64(ttl.Seconds()),
			"rotation_period": int64(role.RotationPeriod.Seconds()),
		},
	}, nil
}

func (b *bindTSIGBackend) getStaticRole(ctx context.Context, s logical.Storage, name string) (*bindTSIGStaticRole, error) {
	if name == "" {
		return nil, fmt.Errorf("missing static role name")
	}
	entry, err := s.Get(ctx, staticRoleStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &bindTSIGStaticRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}
