#!/usr/bin/env bash
#
# End-to-end test for vault-plugin-secrets-bind-tsig.
#
# Builds the plugin, brings up a mock companion API plus both Vault and OpenBao,
# then drives the identical lifecycle against each engine to prove the same
# binary works on both:
#   configure -> static role -> static creds -> dynamic role -> creds -> revoke.
#
# Select engines with ENGINES (default "vault openbao"), e.g. ENGINES=openbao.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/test/docker-compose.yml"
COMPOSE="docker compose -f ${COMPOSE_FILE}"
BINARY="vault-plugin-secrets-bind-tsig"

API_TOKEN="e2e-token"
API_ADDR="http://127.0.0.1:8443"   # companion API, from the host
MOUNT="bind-tsig"
ENGINES="${ENGINES:-vault openbao}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m==> %s\033[0m\n' "$*"; }

cleanup() { blue "Tearing down containers"; ${COMPOSE} down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { red "FAIL: $*"; exit 1; }

wait_for() {
  local desc="$1"; shift
  local i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "${WAIT_RETRIES:-90}" ] && fail "timed out waiting for ${desc}"
    sleep 2
  done
  green "ready: ${desc}"
}

# api_key_status NAME -> HTTP status of GET /v1/keys/NAME on the companion API.
api_key_status() {
  curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${API_TOKEN}" "${API_ADDR}/v1/keys/$1"
}

jq_field() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

run_engine() {
  local engine="$1" container="$2" cli="$3"
  blue "[${engine}] exercising the plugin"
  ex() { ${COMPOSE} exec -T "${container}" "${cli}" "$@"; }

  local sha; sha="$(sha256sum "${ROOT_DIR}/dist/${BINARY}" | awk '{print $1}')"
  ex plugin register -sha256="${sha}" secret "${BINARY}" >/dev/null || true
  ex secrets disable "${MOUNT}" >/dev/null 2>&1 || true
  ex secrets enable -path="${MOUNT}" "${BINARY}" >/dev/null
  green "[${engine}] plugin registered and mounted"

  # The plugin runs inside the engine container, so it reaches the API by name.
  ex write "${MOUNT}/config" api_url="http://companion-api:8443" token="${API_TOKEN}" \
    default_cluster_ref="bind-authoritative" >/dev/null
  green "[${engine}] configured"

  # --- static role: stable name, managed rotation ---
  local skey="client-update-${engine}"
  ex write "${MOUNT}/static-roles/${skey}" rotation_period=1h >/dev/null
  [ "$(api_key_status "${skey}")" = "200" ] || fail "[${engine}] static key not created in companion API"
  local sc; sc="$(ex read -format=json "${MOUNT}/static-creds/${skey}")"
  local ssecret; ssecret="$(printf '%s' "${sc}" | jq_field '["data"]["secret"]')"
  [ -n "${ssecret}" ] || fail "[${engine}] static-creds returned no secret"
  green "[${engine}] static role: key present, secret ${ssecret:0:8}..."

  # --- dynamic role: unique, lease-bound ---
  ex write "${MOUNT}/roles/ephemeral" cluster_ref="bind-authoritative" ttl=1h max_ttl=24h >/dev/null
  local json name lease
  json="$(ex read -format=json "${MOUNT}/creds/ephemeral")"
  name="$(printf '%s' "${json}" | jq_field '["data"]["name"]')"
  lease="$(printf '%s' "${json}" | jq_field '["lease_id"]')"
  [ -n "${name}" ] || fail "[${engine}] no dynamic key returned"
  [ "$(api_key_status "${name}")" = "200" ] || fail "[${engine}] dynamic key ${name} not in companion API"
  green "[${engine}] dynamic key ${name} issued (lease ${lease})"

  # revoke -> key deleted from the companion API
  ex lease revoke "${lease}" >/dev/null
  sleep 2
  [ "$(api_key_status "${name}")" = "404" ] || fail "[${engine}] revoked key still present in companion API"
  green "[${engine}] revoked key removed from companion API"

  green "[${engine}] PASSED"
}

blue "Building plugin for linux/amd64"
OS=linux ARCH=amd64 PLUGIN_DIR="${ROOT_DIR}/dist" make -C "${ROOT_DIR}" build

blue "Starting Docker stack (companion-api + vault + openbao)"
${COMPOSE} up -d --build

wait_for "companion-api" curl -fsS "${API_ADDR}/healthz"

for engine in ${ENGINES}; do
  case "${engine}" in
    vault)   wait_for "vault"   ${COMPOSE} exec -T vault   vault status -address=http://127.0.0.1:8200; run_engine vault vault vault ;;
    openbao) wait_for "openbao" ${COMPOSE} exec -T openbao bao   status -address=http://127.0.0.1:8200; run_engine openbao openbao bao ;;
    *) fail "unknown engine: ${engine}" ;;
  esac
done

green "ALL END-TO-END CHECKS PASSED (${ENGINES})"
