# Dynamic roles and credentials

A dynamic role mints a unique TSIG key on every read of `creds/<name>`. Each key
is tied to a Vault lease and deleted from the companion API when the lease is
revoked or expires.

## `roles/<name>`

| Method   | Path |
|----------|------|
| `GET`    | `/bind-tsig/roles/:name` |
| `POST`   | `/bind-tsig/roles/:name` |
| `DELETE` | `/bind-tsig/roles/:name` |

### Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string (path) | — | Role name, lower-cased. |
| `algorithm` | string | config `default_algorithm` | TSIG algorithm for generated keys. |
| `cluster_ref` | string | config `default_cluster_ref` | BIND cluster generated keys are scoped to. |
| `ttl` | duration | mount default lease TTL | Default lease TTL. |
| `max_ttl` | duration | mount max lease TTL | Maximum lease TTL. `ttl` must not exceed it. |

### Examples

```sh
vault write bind-tsig/roles/ephemeral \
  algorithm=hmac-sha256 cluster_ref=authoritative \
  ttl=1h max_ttl=24h

vault read bind-tsig/roles/ephemeral
vault delete bind-tsig/roles/ephemeral
```

## `roles/`

| Method | Path |
|--------|------|
| `LIST` | `/bind-tsig/roles` |

```sh
vault list bind-tsig/roles
```

## `creds/<name>`

Mints a new key named `dyn-<role>-<8 random hex chars>`. `POST` behaves the same
as `GET`.

| Method | Path |
|--------|------|
| `GET`  | `/bind-tsig/creds/:name` |
| `POST` | `/bind-tsig/creds/:name` |

```sh
vault read bind-tsig/creds/ephemeral
```

```text
Key                Value
---                -----
lease_id           bind-tsig/creds/ephemeral/AbCd...
lease_duration     1h
lease_renewable    true
algorithm          hmac-sha256
cluster_ref        authoritative
key_name           dyn-ephemeral-1a2b3c4d
name               dyn-ephemeral-1a2b3c4d
secret             c2VjcmV0...
```

Renewing the lease extends it (up to `max_ttl`) without changing the key.
Revoking it deletes the key:

```sh
vault lease renew  bind-tsig/creds/ephemeral/AbCd...
vault lease revoke bind-tsig/creds/ephemeral/AbCd...
```
