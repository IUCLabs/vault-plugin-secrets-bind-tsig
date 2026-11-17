package bindtsig

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleStoragePrefix = "role/"

// bindTSIGRole is a dynamic role: each read of creds/<name> mints a unique,
// lease-bound TSIG key.
type bindTSIGRole struct {
	Algorithm  string        `json:"algorithm"`
	ClusterRef string        `json:"cluster_ref"`
	TTL        time.Duration `json:"ttl"`
	MaxTTL     time.Duration `json:"max_ttl"`
}

func pathRole(b *bindTSIGBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "bind-tsig",
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the dynamic role.",
				Required:    true,
			},
			"algorithm": {
				Type:        framework.TypeString,
				Description: "TSIG algorithm for generated keys (defaults to the config default).",
			},
			"cluster_ref": {
				Type:        framework.TypeString,
				Description: "BIND cluster the generated keys are scoped to (defaults to the config default).",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL for keys generated from this role.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL for keys generated from this role.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
		ExistenceCheck:  b.pathRoleExistenceCheck,
		HelpSynopsis:    "Manage dynamic TSIG-key roles.",
		HelpDescription: "Dynamic roles mint a unique, lease-bound TSIG key per read of creds/<name>.",
	}
}

func pathRolesList(b *bindTSIGBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "bind-tsig",
			OperationSuffix: "roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
		},
		HelpSynopsis:    "List dynamic roles.",
		HelpDescription: "List the dynamic TSIG-key roles configured on this backend.",
	}
}

func (b *bindTSIGBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *bindTSIGBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"algorithm":   role.Algorithm,
			"cluster_ref": role.ClusterRef,
			"ttl":         int64(role.TTL.Seconds()),
			"max_ttl":     int64(role.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *bindTSIGBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &bindTSIGRole{}
	}

	if v, ok := data.GetOk("algorithm"); ok {
		role.Algorithm = v.(string)
	}
	if v, ok := data.GetOk("cluster_ref"); ok {
		role.ClusterRef = v.(string)
	}
	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl must not exceed max_ttl"), nil
	}

	return nil, setJSON(ctx, req.Storage, roleStoragePrefix+name, role)
}

func (b *bindTSIGBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, roleStoragePrefix+data.Get("name").(string))
}

func (b *bindTSIGBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *bindTSIGBackend) getRole(ctx context.Context, s logical.Storage, name string) (*bindTSIGRole, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}
	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &bindTSIGRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

// setJSON stores a value as a JSON storage entry.
func setJSON(ctx context.Context, s logical.Storage, key string, value interface{}) error {
	entry, err := logical.StorageEntryJSON(key, value)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}
