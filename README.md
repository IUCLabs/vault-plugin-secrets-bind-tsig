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

Release assets download through artifactapi's GitHub proxy, which serves
`https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-bind-tsig/releases/download/<tag>/<file>`.
Each method below ends with `SHA256` set for [registration](#register-and-enable).
With OpenBao, use `bao` in place of `vault`.

```sh
TAG=vX.Y.Z  # the release to install
V=${TAG#v}
BASE=https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-bind-tsig/releases/download/$TAG
```

### RPM

Install the Vault RPM or the OpenBao RPM, not both. Set the server's
`plugin_directory` to the directory the RPM installs into.

Vault: installs `/usr/libexec/vault-plugins/vault-plugin-secrets-bind-tsig`.

```sh
dnf install vault-plugin-secrets-bind-tsig  # from a yum repo carrying it, or from the release:
dnf install "$BASE/vault-plugin-secrets-bind-tsig-$V-1.x86_64.rpm"

SHA256=$(sha256sum /usr/libexec/vault-plugins/vault-plugin-secrets-bind-tsig | cut -d' ' -f1)
```

OpenBao: installs `/usr/libexec/openbao-plugins/vault-plugin-secrets-bind-tsig`.

```sh
dnf install openbao-plugin-secrets-bind-tsig  # from a yum repo carrying it, or from the release:
dnf install "$BASE/openbao-plugin-secrets-bind-tsig-$V-1.x86_64.rpm"

SHA256=$(sha256sum /usr/libexec/openbao-plugins/vault-plugin-secrets-bind-tsig | cut -d' ' -f1)
```

### Released binary

`vault-plugin-secrets-bind-tsig_<version>_SHA256SUMS` lists the binary and the RPMs.

```sh
curl -fLO "$BASE/vault-plugin-secrets-bind-tsig_${V}_linux_amd64"
curl -fLO "$BASE/vault-plugin-secrets-bind-tsig_${V}_SHA256SUMS"
sha256sum --check --ignore-missing "vault-plugin-secrets-bind-tsig_${V}_SHA256SUMS"

install -m 0755 "vault-plugin-secrets-bind-tsig_${V}_linux_amd64" <plugin_directory>/vault-plugin-secrets-bind-tsig
SHA256=$(sha256sum <plugin_directory>/vault-plugin-secrets-bind-tsig | cut -d' ' -f1)
```

### Kubernetes image volume

`ghcr.io/iuclabs/vault-plugin-secrets-bind-tsig:<tag>` is a `FROM scratch` image holding only
`/vault-plugin-secrets-bind-tsig`. Mount it read-only into the Vault/OpenBao container with an
[image volume](https://kubernetes.io/docs/concepts/storage/volumes/#image):
Image volumes are beta from Kubernetes 1.33 but off by default (enable the
`ImageVolume` feature gate), on by default from 1.35, and GA in 1.36. Vault and OpenBao only run a binary that sits directly in
`plugin_directory`, not in a subdirectory, so mount the file itself with
`subPath`, which on image volumes needs 1.33+.

```yaml
spec:
  containers:
    - name: vault
      volumeMounts:
        - name: plugin-bind-tsig
          mountPath: /vault/plugins/vault-plugin-secrets-bind-tsig  # <plugin_directory>/vault-plugin-secrets-bind-tsig
          subPath: vault-plugin-secrets-bind-tsig
          readOnly: true
  volumes:
    - name: plugin-bind-tsig
      image:
        reference: ghcr.io/iuclabs/vault-plugin-secrets-bind-tsig:vX.Y.Z
        pullPolicy: IfNotPresent
```

The image holds the released binary, so its sha256 is the `linux_amd64` line
of `SHA256SUMS`:

```sh
SHA256=$(curl -fsSL "$BASE/vault-plugin-secrets-bind-tsig_${V}_SHA256SUMS" | awk '/_linux_amd64$/ {print $1}')
```

### From source

```sh
make build  # writes ./dist/vault-plugin-secrets-bind-tsig
```

Copy it into `plugin_directory` and take `SHA256` from `sha256sum` as above.

### Register and enable

```sh
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-bind-tsig
vault secrets enable -path=bind-tsig vault-plugin-secrets-bind-tsig
```

After replacing the binary, register the new sha256 and reload the plugin:

```sh
vault write sys/plugins/reload/backend plugin=vault-plugin-secrets-bind-tsig
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
