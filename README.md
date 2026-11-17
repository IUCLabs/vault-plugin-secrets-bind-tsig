# vault-plugin-secrets-bind-tsig

A HashiCorp Vault / OpenBao secrets engine that manages BIND TSIG keys.

Static roles give you a stable, named key whose material Vault rotates on a
schedule; dynamic roles mint a unique, lease-bound key per request and delete it
when the lease is revoked. Vault never touches BIND directly: it calls a small
HTTP "companion API" (any service implementing the companion API contract, see
[docs/companion-api.md](docs/companion-api.md)) that provisions the keys and
wires them into `named.conf`.

```
Vault/OpenBao ──HTTP──▶ companion API ──▶ TSIG key material + named.conf
```

## Why use this plugin?

TSIG keys for dynamic DNS updates tend to be generated once, pasted into config
management and never rotated. This engine puts them behind Vault policy and
audit: clients that need to update a zone read their key from Vault, static keys
rotate without changing the key name (so `allow-update` clauses stay valid), and
short-lived jobs get a throwaway key that disappears with their lease.

## Requirements

- HashiCorp Vault or OpenBao with a `plugin_directory` configured (tested
  end-to-end against Vault 1.18 and the latest OpenBao release)
- A companion API reachable from the Vault servers
- Go 1.25+ to build from source

## Installation

Download a binary from the [releases page](https://github.com/IUCLabs/vault-plugin-secrets-bind-tsig/releases), or build one:

```sh
git clone https://github.com/IUCLabs/vault-plugin-secrets-bind-tsig
cd vault-plugin-secrets-bind-tsig
make build   # -> dist/vault-plugin-secrets-bind-tsig
```

Copy the binary into the directory set by `plugin_directory` in the server
config (Vault or OpenBao), then register and enable it. The commands are
identical for OpenBao — use `bao` instead of `vault`.

```sh
PLUGIN_DIR=/etc/vault/plugins   # must match plugin_directory in the server config
SHA256=$(sha256sum "$PLUGIN_DIR/vault-plugin-secrets-bind-tsig" | cut -d' ' -f1)

vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-bind-tsig
vault secrets enable -path=bind-tsig vault-plugin-secrets-bind-tsig
```

## Quick start

```sh
# Point the engine at the companion API.
vault write bind-tsig/config \
  api_url=https://tsig-api.example.com:8443 \
  token=@api-token.txt \
  ca_cert=@ca.pem \
  default_cluster_ref=authoritative

# A static key, rotated every 30 days.
vault write bind-tsig/static-roles/ddns-client rotation_period=720h
vault read  bind-tsig/static-creds/ddns-client

# A dynamic, lease-bound key.
vault write bind-tsig/roles/ephemeral ttl=1h max_ttl=24h
vault read  bind-tsig/creds/ephemeral
```

Use the returned `key_name`, `algorithm` and `secret` with any TSIG client, e.g.
`nsupdate -y "hmac-sha256:<key_name>:<secret>"`.

## Documentation

Full path and parameter reference lives in [`docs/`](docs/):

- [Configuration](docs/config.md)
- [Static roles and credentials](docs/static-roles.md)
- [Dynamic roles and credentials](docs/roles.md)
- [Companion API contract](docs/companion-api.md)

## Development

```sh
make test   # unit tests (go test -race)
make lint   # go vet
make e2e    # Docker: mock companion API + Vault + OpenBao, full lifecycle
```

## License

[MIT](LICENSE)
