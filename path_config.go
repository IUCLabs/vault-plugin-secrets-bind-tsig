package bindtsig

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// bindTSIGConfig is the connection to the bind-operator companion API.
type bindTSIGConfig struct {
	APIURL                string `json:"api_url"`
	Token                 string `json:"token"`
	CACert                string `json:"ca_cert"`
	TLSSkipVerify         bool   `json:"tls_skip_verify"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
	DefaultAlgorithm      string `json:"default_algorithm"`
	DefaultClusterRef     string `json:"default_cluster_ref"`
}

func pathConfig(b *bindTSIGBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "bind-tsig",
			OperationSuffix: "config",
		},
		Fields: map[string]*framework.FieldSchema{
			"api_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the bind-operator companion API, e.g. https://bind-tsig-api.bind-system.svc:8443.",
				Required:    true,
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Bearer token used to authenticate to the companion API.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "API Token",
					Sensitive: true,
				},
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM CA certificate that signed the companion API's TLS certificate.",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS verification of the companion API (not recommended).",
				Default:     false,
			},
			"request_timeout_seconds": {
				Type:        framework.TypeInt,
				Description: "HTTP timeout in seconds for calls to the companion API (default 30).",
				Default:     30,
			},
			"default_algorithm": {
				Type:        framework.TypeString,
				Description: "Default TSIG algorithm for keys when a role does not set one.",
				Default:     "hmac-sha256",
			},
			"default_cluster_ref": {
				Type:        framework.TypeString,
				Description: "Default BindCluster a key is scoped to when a role does not set one.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    "Configure the connection to the bind-operator companion API.",
		HelpDescription: "Configure the URL and token the backend uses to manage BIND TSIG keys.",
	}
}

func (b *bindTSIGBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *bindTSIGBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	// The token is deliberately not returned.
	return &logical.Response{
		Data: map[string]interface{}{
			"api_url":                 config.APIURL,
			"tls_skip_verify":         config.TLSSkipVerify,
			"request_timeout_seconds": config.RequestTimeoutSeconds,
			"default_algorithm":       config.DefaultAlgorithm,
			"default_cluster_ref":     config.DefaultClusterRef,
		},
	}, nil
}

func (b *bindTSIGBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = &bindTSIGConfig{}
	}

	if v, ok := data.GetOk("api_url"); ok {
		config.APIURL = v.(string)
	}
	if v, ok := data.GetOk("token"); ok {
		config.Token = v.(string)
	}
	if v, ok := data.GetOk("ca_cert"); ok {
		config.CACert = v.(string)
	}
	if v, ok := data.GetOk("tls_skip_verify"); ok {
		config.TLSSkipVerify = v.(bool)
	}
	if v, ok := data.GetOk("request_timeout_seconds"); ok {
		config.RequestTimeoutSeconds = v.(int)
	} else if req.Operation == logical.CreateOperation {
		config.RequestTimeoutSeconds = data.Get("request_timeout_seconds").(int)
	}
	if v, ok := data.GetOk("default_algorithm"); ok {
		config.DefaultAlgorithm = v.(string)
	} else if req.Operation == logical.CreateOperation {
		config.DefaultAlgorithm = data.Get("default_algorithm").(string)
	}
	if v, ok := data.GetOk("default_cluster_ref"); ok {
		config.DefaultClusterRef = v.(string)
	}

	if config.APIURL == "" {
		return logical.ErrorResponse("api_url is required"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()
	return nil, nil
}

func (b *bindTSIGBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*bindTSIGConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	config := &bindTSIGConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}
