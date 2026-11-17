# Static roles and credentials

A static role manages one stable, named TSIG key. Vault rotates the key material
on a schedule, but the key name never changes, so zone `allow-update` clauses
that reference it stay valid.

## `static-roles/<name>`

Creating a static role provisions the key on the companion API immediately, so
`config` must be written first. Deleting the role also deletes the key.

| Method   | Path |
|----------|------|
| `GET`    | `/bind-tsig/static-roles/:name` |
| `POST`   | `/bind-tsig/static-roles/:name` |
| `DELETE` | `/bind-tsig/static-roles/:name` |

### Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string (path) | — | Role name, lower-cased. |
| `key_name` | string | role name | TSIG key name to manage; this is what zone `allow-update` clauses reference. |
| `algorithm` | string | config `default_algorithm` | TSIG algorithm. |
| `cluster_ref` | string | config `default_cluster_ref` | BIND cluster the key is scoped to. |
| `rotation_period` | duration | `0` | How often the material is rotated. `0` disables automatic rotation. |

### Examples

```sh
vault write bind-tsig/static-roles/ddns-client \
  key_name=ddns-client.example.com \
  algorithm=hmac-sha512 \
  rotation_period=720h

vault read bind-tsig/static-roles/ddns-client
vault delete bind-tsig/static-roles/ddns-client
```

Read returns `key_name`, `algorithm`, `cluster_ref`, `rotation_period` (seconds)
and `last_rotation`.

## `static-roles/`

| Method | Path |
|--------|------|
| `LIST` | `/bind-tsig/static-roles` |

```sh
vault list bind-tsig/static-roles
```

## `static-creds/<name>`

Returns the current key material. Rotation is lazy: if `rotation_period` has
elapsed since `last_rotation`, the key is rotated before it is returned.

| Method | Path |
|--------|------|
| `GET`  | `/bind-tsig/static-creds/:name` |

```sh
vault read bind-tsig/static-creds/ddns-client
```

```text
Key                Value
---                -----
algorithm          hmac-sha512
cluster_ref        authoritative
key_name           ddns-client.example.com
last_rotation      2026-01-01T00:00:00Z
rotation_period    2592000
secret             c2VjcmV0...
ttl                2591000
```

`ttl` is the number of seconds until the next rotation is due.
