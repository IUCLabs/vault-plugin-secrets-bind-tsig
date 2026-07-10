package bindtsig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// apiClient talks to the bind-operator companion API, which manages BindTSIGKey
// CRs and their rotation. The operator reconciles the CRs into key material.
type apiClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// tsigKey is the companion API's representation of a TSIG key.
type tsigKey struct {
	Name       string `json:"name"`
	Algorithm  string `json:"algorithm"`
	Secret     string `json:"secret"`
	KeyName    string `json:"key_name"`
	ClusterRef string `json:"cluster_ref,omitempty"`
}

// createKeyRequest is the payload for POST /v1/keys.
type createKeyRequest struct {
	Name       string `json:"name,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
	ClusterRef string `json:"cluster_ref,omitempty"`
	// Static, when true, marks the key for managed rotation rather than
	// lease-bound (dynamic) lifetime.
	Static bool `json:"static,omitempty"`
}

func newClient(config *bindTSIGConfig) (*apiClient, error) {
	if config == nil {
		return nil, errors.New("bind-tsig client configuration is nil")
	}
	if config.APIURL == "" {
		return nil, errors.New("api_url is required")
	}

	timeout := defaultHTTPTimeout
	if config.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(config.RequestTimeoutSeconds) * time.Second
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: config.TLSSkipVerify} //nolint:gosec // opt-in via config
	if config.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(config.CACert)) {
			return nil, errors.New("ca_cert is not a valid PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}

	return &apiClient{
		baseURL: strings.TrimRight(config.APIURL, "/"),
		token:   config.Token,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

// CreateKey asks the companion API to provision a TSIG key. The API creates a
// BindTSIGKey CR and returns the reconciled material.
func (c *apiClient) CreateKey(ctx context.Context, req createKeyRequest) (*tsigKey, error) {
	var out tsigKey
	if err := c.do(ctx, http.MethodPost, "/v1/keys", req, &out); err != nil {
		return nil, err
	}
	if out.Secret == "" {
		return nil, errors.New("companion API returned an empty key secret")
	}
	return &out, nil
}

// GetKey reads the current material for a named key.
func (c *apiClient) GetKey(ctx context.Context, name string) (*tsigKey, error) {
	var out tsigKey
	if err := c.do(ctx, http.MethodGet, "/v1/keys/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateKey asks the API to rotate a key's material, returning the new value.
func (c *apiClient) RotateKey(ctx context.Context, name string) (*tsigKey, error) {
	var out tsigKey
	if err := c.do(ctx, http.MethodPost, "/v1/keys/"+url.PathEscape(name)+"/rotate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteKey removes a key (and its BindTSIGKey CR). A missing key is success.
func (c *apiClient) DeleteKey(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/keys/"+url.PathEscape(name), nil, nil)
}

func (c *apiClient) do(ctx context.Context, method, path string, payload, out interface{}) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling companion API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if method == http.MethodDelete && resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("companion API %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decoding companion API response: %w", err)
	}
	return nil
}
