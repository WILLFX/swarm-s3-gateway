#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf '\n=== %s ===\n' "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

hash_hex() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

wait_port() {
  local port="$1"
  local label="$2"

  for _ in $(seq 1 40); do
    if ss -ltnp 2>/dev/null | grep -q ":${port}"; then
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for ${label} on port ${port}" >&2
  exit 1
}

assert_header() {
  local headers="$1"
  local name="$2"
  local expected="$3"

  if ! tr -d '\r' < "$headers" | grep -F "${name}: ${expected}" >/dev/null; then
    echo "FAILED: missing header ${name}: ${expected}" >&2
    echo "headers:" >&2
    cat "$headers" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd curl
require_cmd openssl
require_cmd sha256sum
require_cmd ss
require_cmd xxd

LATEST_ENV="${TRUSTLESS_DEV_STACK_ENV:-$(ls -td /tmp/s3w-dev-stack-*/dev-stack.env 2>/dev/null | head -1)}"

if [ -z "${LATEST_ENV}" ] || [ ! -f "$LATEST_ENV" ]; then
  echo "missing dev stack env file; run scripts/trustless_dev_stack_bootstrap.sh first" >&2
  exit 1
fi

log "loading dev stack env"
echo "$LATEST_ENV"
# shellcheck disable=SC1090
source "$LATEST_ENV"

LOCAL_PROXY_HOST="${LOCAL_PROXY_HOST:-127.0.0.1}"
LOCAL_PROXY_PORT="${LOCAL_PROXY_PORT:-9090}"
LOCAL_PROXY_ENDPOINT="http://${LOCAL_PROXY_HOST}:${LOCAL_PROXY_PORT}"

RUN_ID="$(date +%s)-$$"
RUN_DIR="${RUN_DIR:-/tmp/s3w-live-local-proxy-demo-${RUN_ID}}"
mkdir -p "$RUN_DIR"

LOCAL_ACCOUNT="${TRUSTLESS_PROXY_DEMO_ACCOUNT:-0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d}"
LOCAL_KEY_TYPE="aws-esdk-rust-recipient-key"
UNLOCK_KEY_HEX="$(openssl rand -hex 32)"

KEY_MATERIAL_DIR="$RUN_DIR/key-material"
mkdir -p "$KEY_MATERIAL_DIR"

log "checking live gateway auth"
curl -fsS \
  --aws-sigv4 "aws:amz:us-east-1:s3" \
  --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
  -H "x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  "$GATEWAY_ENDPOINT/" >/dev/null

log "generating local proxy RSA key material"
TRUSTLESS_PROXY_DEV_KEY_OUTPUT_DIR="$KEY_MATERIAL_DIR" \
TRUSTLESS_PROXY_DEV_KEY_ACCOUNT="$LOCAL_ACCOUNT" \
TRUSTLESS_PROXY_DEV_KEY_UNLOCK_KEY_HEX="$UNLOCK_KEY_HEX" \
  cargo run -q -p trustless-proxy --bin trustless_proxy_dev_key_material \
  | tee "$RUN_DIR/key-material.log"

# shellcheck disable=SC1090
source "$KEY_MATERIAL_DIR/local-proxy-key-material.env"

BUCKET="trustless-local-proxy-demo-${RUN_ID}"
OBJECT_KEY="docs/plaintext.txt"
BUCKET_ID="$(hash_hex "$BUCKET")"
POLICY_VERSION="1"

log "seeding empty encrypted manifest"
EMPTY_MANIFEST_HEX="$(
  TRUSTLESS_PROXY_DEV_MANIFEST_KEYSTORE_PATH="$TRUSTLESS_PROXY_KEYSTORE_PATH" \
  TRUSTLESS_PROXY_DEV_MANIFEST_RECIPIENT_KEYS_PATH="$TRUSTLESS_PROXY_RECIPIENT_KEYS_PATH" \
  TRUSTLESS_PROXY_DEV_MANIFEST_UNLOCK_KEY_HEX="$TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX" \
  TRUSTLESS_PROXY_DEV_MANIFEST_ACCOUNT="$S3W_LOCAL_PROXY_ACCOUNT" \
  TRUSTLESS_PROXY_DEV_MANIFEST_KEY_TYPE="$S3W_LOCAL_PROXY_KEY_TYPE" \
  TRUSTLESS_PROXY_DEV_MANIFEST_BUCKET_ID="$BUCKET_ID" \
  TRUSTLESS_PROXY_DEV_MANIFEST_OBJECT_KEY_ID="$BUCKET_ID" \
  TRUSTLESS_PROXY_DEV_MANIFEST_POLICY_VERSION="$POLICY_VERSION" \
    cargo run -q -p trustless-proxy --bin trustless_proxy_dev_encrypt_empty_manifest
)"

SEED_MANIFEST_JSON="$RUN_DIR/seed-empty-manifest.json"
cat > "$SEED_MANIFEST_JSON" <<EOFSEED
{"version":1,"action":"put_encrypted_manifest","bucket":"${BUCKET}","ciphertext_hex":null,"encrypted_manifest_hex":"${EMPTY_MANIFEST_HEX}","gateway_plaintext_access":false}
EOFSEED

SEED_MANIFEST_HASH="$(sha256sum "$SEED_MANIFEST_JSON" | awk '{print $1}')"

curl -fsS \
  --aws-sigv4 "aws:amz:us-east-1:s3" \
  --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
  -H "content-type: application/json" \
  -H "x-amz-content-sha256: ${SEED_MANIFEST_HASH}" \
  --data-binary "@${SEED_MANIFEST_JSON}" \
  "${GATEWAY_ENDPOINT}/trustless/v1/ciphertext-gateway" \
  | tee "$RUN_DIR/seed-empty-manifest.out"

grep -F '"metadata_only":true' "$RUN_DIR/seed-empty-manifest.out" >/dev/null
grep -F '"gateway_plaintext_access":false' "$RUN_DIR/seed-empty-manifest.out" >/dev/null

log "starting local trustless proxy"
pkill -f 'target/debug/trustless-proxy.*local-proxy' 2>/dev/null || true
pkill -f 'cargo run.*trustless-proxy.*local-proxy' 2>/dev/null || true
sleep 1

if ss -ltnp 2>/dev/null | grep -q ":${LOCAL_PROXY_PORT}"; then
  echo "local proxy port ${LOCAL_PROXY_PORT} is already in use" >&2
  ss -ltnp 2>/dev/null | grep ":${LOCAL_PROXY_PORT}" >&2 || true
  exit 1
fi

TRUSTLESS_PROXY_LISTEN_HOST="$LOCAL_PROXY_HOST" \
TRUSTLESS_PROXY_LISTEN_PORT="$LOCAL_PROXY_PORT" \
TRUSTLESS_PROXY_REMOTE_GATEWAY_URL="$GATEWAY_ENDPOINT" \
TRUSTLESS_PROXY_REMOTE_GATEWAY_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
TRUSTLESS_PROXY_REMOTE_GATEWAY_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
TRUSTLESS_PROXY_REMOTE_GATEWAY_REGION="us-east-1" \
TRUSTLESS_PROXY_REMOTE_GATEWAY_SERVICE="s3" \
TRUSTLESS_PROXY_CHAIN_RPC_URL="$CHAIN_RPC_WS" \
TRUSTLESS_PROXY_LOCAL_ACCOUNT="$S3W_LOCAL_PROXY_ACCOUNT" \
TRUSTLESS_PROXY_KEYSTORE_PATH="$TRUSTLESS_PROXY_KEYSTORE_PATH" \
TRUSTLESS_PROXY_RECIPIENT_KEYS_PATH="$TRUSTLESS_PROXY_RECIPIENT_KEYS_PATH" \
TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX="$TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX" \
RUST_LOG=trustless_proxy=debug \
  cargo run -q -p trustless-proxy --bin trustless-proxy -- local-proxy \
  >"$RUN_DIR/local-proxy.log" 2>&1 &

LOCAL_PROXY_PID="$!"
echo "$LOCAL_PROXY_PID" > "$RUN_DIR/local-proxy.pid"
wait_port "$LOCAL_PROXY_PORT" "local proxy"

PAYLOAD_FILE="$RUN_DIR/plaintext-put.txt"
GET_FILE="$RUN_DIR/plaintext-get.txt"
PUT_HEADERS="$RUN_DIR/put.headers"
GET_HEADERS="$RUN_DIR/get.headers"

printf 'hello from local trustless proxy plaintext %s\n' "$RUN_ID" > "$PAYLOAD_FILE"

COMMON_HEADERS=(
  -H "x-s3w-bucket-id: ${BUCKET_ID}"
  -H "x-s3w-policy-version: ${POLICY_VERSION}"
  -H "x-s3w-local-account: ${S3W_LOCAL_PROXY_ACCOUNT}"
  -H "x-s3w-local-key-type: ${S3W_LOCAL_PROXY_KEY_TYPE}"
  -H "x-s3w-recipients: ${S3W_LOCAL_PROXY_ACCOUNT}"
  -H "x-s3w-recipient-keys: ${S3W_RECIPIENT_KEY_HEADER}"
)

log "PUT plaintext through local proxy"
curl -fsS \
  -X PUT \
  --dump-header "$PUT_HEADERS" \
  "${COMMON_HEADERS[@]}" \
  --data-binary "@${PAYLOAD_FILE}" \
  "${LOCAL_PROXY_ENDPOINT}/${BUCKET}/${OBJECT_KEY}" \
  -o "$RUN_DIR/put.body"

assert_header "$PUT_HEADERS" "x-s3w-gateway-plaintext-access" "false"

log "GET plaintext back through local proxy"
curl -fsS \
  --dump-header "$GET_HEADERS" \
  "${COMMON_HEADERS[@]}" \
  "${LOCAL_PROXY_ENDPOINT}/${BUCKET}/${OBJECT_KEY}" \
  --output "$GET_FILE"

assert_header "$GET_HEADERS" "x-s3w-gateway-plaintext-access" "false"

if ! cmp -s "$PAYLOAD_FILE" "$GET_FILE"; then
  echo "FAILED: local proxy GET plaintext did not match PUT plaintext" >&2
  echo "expected:" >&2
  cat "$PAYLOAD_FILE" >&2
  echo "got:" >&2
  cat "$GET_FILE" >&2
  exit 1
fi

log "live local proxy demo passed"
echo "run_dir=$RUN_DIR"
echo "local_proxy_log=$RUN_DIR/local-proxy.log"
