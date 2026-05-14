#!/usr/bin/env bash
set -euo pipefail

# Private S3 gateway lifecycle smoke test.
#
# Requires these services to already be running:
#   1. local Substrate node / contracts chain
#   2. Bee node
#   3. gateway HTTP server
#
# Required env:
#   RPC_URL or S3GW_CHAIN_RPC_URL
#   MASTER_SERVICE_KEY_HEX or S3GW_MASTER_SERVICE_KEY_HEX
#   AWS_ACCESS_KEY_ID
#   AWS_SECRET_ACCESS_KEY
#
# Optional env:
#   S3GW_ENDPOINT          default: http://127.0.0.1:3000
#   S3GW_AWS_REGION       default: us-east-1
#   OWNER_HEX             default: Alice, inside helper binaries
#   OWNER_SURI            default: //Alice, inside sign_bucket_op
#   BUCKET                default: private-smoke-<timestamp>
#   OBJECT_KEY            default: secret.txt

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENDPOINT="${S3GW_ENDPOINT:-http://127.0.0.1:3000}"
REGION="${S3GW_AWS_REGION:-us-east-1}"
SERVICE="${S3GW_AWS_SERVICE:-s3}"
BUCKET="${BUCKET:-private-smoke-$(date +%s)}"
OBJECT_KEY="${OBJECT_KEY:-secret.txt}"
PAYLOAD_FILE="$(mktemp)"
GET_FILE="$(mktemp)"
HEAD_HEADERS="$(mktemp)"
GET_HEADERS="$(mktemp)"
LIST_HEADERS="$(mktemp)"
PUT_HEADERS="$(mktemp)"
LIST_BODY="$(mktemp)"
EMPTY_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

cleanup() {
  rm -f "$PAYLOAD_FILE" "$GET_FILE" "$HEAD_HEADERS" "$GET_HEADERS" "$LIST_HEADERS" "$PUT_HEADERS" "$LIST_BODY"
}
trap cleanup EXIT

need_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required env: $name" >&2
    exit 1
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

sign_bucket_op() {
  local op="$1"
  local bucket="$2"
  local visibility="${3:-private}"

  RPC_URL="${RPC_URL:-${S3GW_CHAIN_RPC_URL:-}}" \
    cargo run -q -p gateway --bin sign_bucket_op -- "$op" "$bucket" "$visibility" \
    | awk -F= '/^x-s3gw-owner-signature=/{print $2}'
}

curl_s3() {
  curl --silent --show-error --fail-with-body \
    --aws-sigv4 "aws:amz:${REGION}:${SERVICE}" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    "$@"
}

assert_header_absent() {
  local headers_file="$1"
  local header_name="$2"

  if grep -i "^${header_name}:" "$headers_file" >/dev/null; then
    echo "FAILED: unexpected private response header found: ${header_name}" >&2
    echo "headers were:" >&2
    cat "$headers_file" >&2
    exit 1
  fi
}

assert_contains() {
  local file="$1"
  local needle="$2"

  if ! grep -F "$needle" "$file" >/dev/null; then
    echo "FAILED: expected to find '${needle}' in ${file}" >&2
    echo "file contents:" >&2
    cat "$file" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd sha256sum
need_cmd cargo
need_env AWS_ACCESS_KEY_ID
need_env AWS_SECRET_ACCESS_KEY

export RPC_URL="${RPC_URL:-${S3GW_CHAIN_RPC_URL:-}}"
export MASTER_SERVICE_KEY_HEX="${MASTER_SERVICE_KEY_HEX:-${S3GW_MASTER_SERVICE_KEY_HEX:-}}"

need_env RPC_URL
need_env MASTER_SERVICE_KEY_HEX

echo "== preflight: gateway reachable =="
if ! curl --silent --show-error --output /dev/null --max-time 3 "${ENDPOINT}/"; then
  echo "gateway is not reachable at ${ENDPOINT}" >&2
  echo "start it first, for example:" >&2
  echo "  export S3GW_BIND_ADDR=127.0.0.1:3000" >&2
  echo "  cargo run -p gateway --bin gateway" >&2
  exit 1
fi
echo "gateway reachable"
echo

echo "== private lifecycle smoke =="
echo "endpoint=${ENDPOINT}"
echo "bucket=${BUCKET}"
echo "object=${OBJECT_KEY}"
echo

echo "== 1. Register identity =="
RPC_URL="$RPC_URL" \
MASTER_SERVICE_KEY_HEX="$MASTER_SERVICE_KEY_HEX" \
AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
cargo run -q -p gateway --bin register_identity || {
  echo "identity registration failed" >&2
  exit 1
}

echo
echo "== 2. Create private bucket =="
CREATE_SIG="$(sign_bucket_op create "$BUCKET" private)"
if [[ -z "$CREATE_SIG" ]]; then
  echo "failed to create owner signature for private bucket create" >&2
  exit 1
fi

curl_s3 \
  --request PUT \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  --header "x-s3gw-owner-signature: ${CREATE_SIG}" \
  --header "x-s3gw-bucket-visibility: private" \
  "${ENDPOINT}/${BUCKET}" >/dev/null

echo "created private bucket"

echo
echo "== 3. PUT private object =="
cat > "$PAYLOAD_FILE" <<'EOF'
private smoke payload
EOF

PAYLOAD_SHA256="$(sha256_file "$PAYLOAD_FILE")"

curl_s3 \
  --request PUT \
  --dump-header "$PUT_HEADERS" \
  --header "content-type: text/plain" \
  --header "x-amz-content-sha256: ${PAYLOAD_SHA256}" \
  --data-binary "@${PAYLOAD_FILE}" \
  "${ENDPOINT}/${BUCKET}/${OBJECT_KEY}" >/dev/null

assert_header_absent "$PUT_HEADERS" "x-amz-meta-swarm-ref"
echo "put private object and confirmed PUT response hides x-amz-meta-swarm-ref"

echo
echo "== 4. HEAD private object =="
curl_s3 \
  --head \
  --dump-header "$HEAD_HEADERS" \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  "${ENDPOINT}/${BUCKET}/${OBJECT_KEY}" >/dev/null

assert_header_absent "$HEAD_HEADERS" "x-amz-meta-swarm-ref"
echo "HEAD private object hides x-amz-meta-swarm-ref"

echo
echo "== 5. GET private object =="
curl_s3 \
  --dump-header "$GET_HEADERS" \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  "${ENDPOINT}/${BUCKET}/${OBJECT_KEY}" \
  --output "$GET_FILE"

assert_header_absent "$GET_HEADERS" "x-amz-meta-swarm-ref"

if ! cmp -s "$PAYLOAD_FILE" "$GET_FILE"; then
  echo "FAILED: GET payload does not match uploaded payload" >&2
  echo "expected:" >&2
  cat "$PAYLOAD_FILE" >&2
  echo "got:" >&2
  cat "$GET_FILE" >&2
  exit 1
fi

echo "GET private object decrypted correctly and hides x-amz-meta-swarm-ref"

echo
echo "== 6. LIST private bucket =="
curl_s3 \
  --dump-header "$LIST_HEADERS" \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  "${ENDPOINT}/${BUCKET}?list-type=2" \
  --output "$LIST_BODY"

assert_header_absent "$LIST_HEADERS" "x-amz-meta-swarm-ref"
assert_contains "$LIST_BODY" "<Key>${OBJECT_KEY}</Key>"
echo "LIST private bucket shows object metadata and hides x-amz-meta-swarm-ref"

echo
echo "== 7. DELETE private object =="
curl_s3 \
  --request DELETE \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  "${ENDPOINT}/${BUCKET}/${OBJECT_KEY}" >/dev/null

echo "deleted private object"

echo
echo "== 8. Confirm object is gone =="
LIST_AFTER_DELETE="$(mktemp)"
trap 'cleanup; rm -f "$LIST_AFTER_DELETE"' EXIT

curl_s3 \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  "${ENDPOINT}/${BUCKET}?list-type=2" \
  --output "$LIST_AFTER_DELETE"

if grep -F "<Key>${OBJECT_KEY}</Key>" "$LIST_AFTER_DELETE" >/dev/null; then
  echo "FAILED: deleted object still appears in private bucket listing" >&2
  cat "$LIST_AFTER_DELETE" >&2
  exit 1
fi

echo "confirmed private object removed from listing"

echo
echo "== 9. DELETE private bucket =="
DELETE_SIG="$(sign_bucket_op delete "$BUCKET" private)"
if [[ -z "$DELETE_SIG" ]]; then
  echo "failed to create owner signature for private bucket delete" >&2
  exit 1
fi

curl_s3 \
  --request DELETE \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  --header "x-s3gw-owner-signature: ${DELETE_SIG}" \
  "${ENDPOINT}/${BUCKET}" >/dev/null

echo "deleted private bucket"

echo
echo "PRIVATE LIFECYCLE SMOKE PASSED"
