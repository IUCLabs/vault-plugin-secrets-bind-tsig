# Configuration

## `config`

Connection to the companion API plus defaults applied when a role does not set
its own. The `token` is stored seal-wrapped and is never returned on read.

| Method   | Path |
|----------|------|
| `GET`    | `/bind-tsig/config` |
| `POST`   | `/bind-tsig/config` |
| `DELETE` | `/bind-tsig/config` |

### Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `api_url` | string | — (required) | Base URL of the companion API, e.g. `https://tsig-api.example.com:8443`. |
| `token` | string | — | Bearer token sent as `Authorization: Bearer <token>`. |
| `ca_cert` | string | system roots | PEM CA certificate that signed the companion API's TLS certificate. |
| `tls_skip_verify` | bool | `false` | Skip TLS verification (not recommended). |
| `request_timeout_seconds` | int | `30` | HTTP timeout for calls to the companion API. |
| `default_algorithm` | string | `hmac-sha256` | TSIG algorithm used when a role does not set one. |
| `default_cluster_ref` | string | — | BIND cluster a key is scoped to when a role does not set one. |

### Examples

```sh
vault write bind-tsig/config \
  api_url=https://tsig-api.example.com:8443 \
  token=@api-token.txt \
  ca_cert=@ca.pem \
  default_algorithm=hmac-sha256 \
  default_cluster_ref=authoritative

vault read bind-tsig/config
vault delete bind-tsig/config
```

```text
Key                        Value
---                        -----
api_url                    https://tsig-api.example.com:8443
default_algorithm          hmac-sha256
default_cluster_ref        authoritative
request_timeout_seconds    30
tls_skip_verify            false
```
