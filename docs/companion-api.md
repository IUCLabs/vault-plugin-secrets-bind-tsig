# Companion API contract

The engine does not manage BIND itself. It calls an HTTP API that owns the key
material and its distribution to the name servers. Any service implementing
the endpoints below works. `test/mockapi` is a minimal
in-memory reference implementation.

All requests carry `Accept: application/json`, plus `Authorization: Bearer
<token>` when a token is configured in `config`; request bodies are JSON.

A key is represented as:

```json
{
  "name": "ddns-client",
  "algorithm": "hmac-sha256",
  "secret": "<base64 key material>",
  "key_name": "ddns-client",
  "cluster_ref": "authoritative"
}
```

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `POST /v1/keys` | Create a key. Body: `{name, algorithm, cluster_ref, static}`; `static` is `true` for static roles. | the key (`secret` must be non-empty) |
| `GET /v1/keys/{name}` | Read the current material. | the key |
| `POST /v1/keys/{name}/rotate` | Rotate the material. | the key with the new `secret` |
| `DELETE /v1/keys/{name}` | Delete the key. | any 2xx; `404` is treated as success |

Any other non-2xx status is surfaced to the Vault caller as an error.

Example against the mock API:

```sh
curl -s -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"test","algorithm":"hmac-sha256"}' \
  http://127.0.0.1:8443/v1/keys
```
