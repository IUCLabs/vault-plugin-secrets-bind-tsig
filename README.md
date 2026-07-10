# vault-plugin-secrets-bind-tsig

A HashiCorp Vault / OpenBao secrets engine that manages **BIND TSIG keys** via
the [bind-operator](https://git.unkin.net/unkin/bind-operator) companion API.

Vault never talks to Kubernetes directly: it calls the operator's companion API
(deployed by the operator, boolean-gated), which creates/rotates/deletes
`BindTSIGKey` custom resources. The operator reconciles those into the actual
key material and wires them into `named.conf`.

```
Vault plugin ──HTTP──> companion API ──creates/rotates──> BindTSIGKey CR
                                                              │ operator reconciles
                                                              ▼
                                                    Secret (key material) + named.conf
```

## Paths

| Path | Purpose |
|------|---------|
| `<mount>/config` | companion API URL + token + TLS + defaults |
| `<mount>/static-roles/<role>` | a stable, named key with **managed rotation** (the key name never changes, so zone `allow-update` clauses stay valid) |
| `<mount>/static-creds/<role>` | read the current material for a static key (rotates first if the period elapsed) |
| `<mount>/roles/<role>` | a **dynamic** role |
| `<mount>/creds/<role>` | mint a unique, **lease-bound** key; deleted on revoke |

## Companion API contract

The plugin expects the bind-operator companion API to expose:

- `POST /v1/keys` — `{name, algorithm, cluster_ref, static}` → creates a `BindTSIGKey`, returns `{name, algorithm, secret, key_name, cluster_ref}`
- `GET /v1/keys/{name}` — current material
- `POST /v1/keys/{name}/rotate` — rotate material, returns the new value
- `DELETE /v1/keys/{name}` — delete the key + its CR

## Usage

```sh
# register + enable (Vault plugin_directory must contain the binary)
sha=$(sha256sum /opt/vault-plugins/vault-plugin-secrets-bind-tsig | cut -d' ' -f1)
vault plugin register -sha256=$sha secret vault-plugin-secrets-bind-tsig
vault secrets enable -path=bind-tsig vault-plugin-secrets-bind-tsig

# configure the companion API connection
vault write bind-tsig/config \
  api_url=https://bind-tsig-api.bind-system.svc:8443 \
  token=@token default_cluster_ref=bind-authoritative

# a static, rotated key (e.g. the puppet client-update key)
vault write bind-tsig/static-roles/client-update rotation_period=720h
vault read  bind-tsig/static-creds/client-update

# a dynamic, lease-bound key
vault write bind-tsig/roles/ephemeral cluster_ref=bind-authoritative ttl=1h max_ttl=24h
vault read  bind-tsig/creds/ephemeral
```

## Build

```sh
make build      # -> dist/vault-plugin-secrets-bind-tsig
make test lint  # go test -race / go vet
make rpm        # vault + openbao RPM flavours
```

CI (Woodpecker) runs pre-commit/build/lint/test on PRs and builds+publishes the
RPMs on a `v*` tag.
