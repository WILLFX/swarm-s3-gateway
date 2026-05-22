#!/usr/bin/env bash
set -euo pipefail

# Gateway delegation scope smoke test.
#
# Required running services:
#   1. local chain
#   2. Bee
#   3. gateway running with delegated anchor signer, for example:
#        export S3GW_ANCHOR_SIGNER_SURI='//Bob'
#
# This script proves:
#   - owner can grant gateway anchor signer CREATE_BUCKET + PUT_OBJECT
#   - delegated gateway signer can create private bucket and PUT private object
#   - delegated gateway signer cannot DELETE private object without DELETE_OBJECT
#   - after owner grants DELETE_OBJECT + DELETE_BUCKET, cleanup succeeds

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENDPOINT="${S3GW_ENDPOINT:-http://127.0.0.1:3000}"
REGION="${S3GW_AWS_REGION:-us-east-1}"
SERVICE="${S3GW_AWS_SERVICE:-s3}"
BUCKET="${BUCKET:-delegation-smoke-$(date +%s)}"
OBJECT_KEY="${OBJECT_KEY:-delegated-secret.txt}"

ALICE_OWNER_HEX="d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
BOB_DELEGATE_HEX="8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"

OWNER_HEX="${OWNER_HEX:-$ALICE_OWNER_HEX}"
DELEGATE_HEX="${DELEGATE_HEX:-$BOB_DELEGATE_HEX}"

OP_PUT_OBJECT=1
OP_DELETE_OBJECT=4
OP_CREATE_BUCKET=32
OP_DELETE_BUCKET=64

CREATE_AND_PUT_SCOPE=$((OP_CREATE_BUCKET | OP_PUT_OBJECT))
DELETE_CLEANUP_SCOPE=$((OP_DELETE_OBJECT | OP_DELETE_BUCKET))
EXPIRES_AT="${EXPIRES_AT:-9999999999999}"

EMPTY_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

PAYLOAD_FILE="$(mktemp)"
GET_FILE="$(mktemp)"
PUT_HEADERS="$(mktemp)"
DELETE_FAIL_BODY="$(mktemp)"
DELETE_FAIL_HEADERS="$(mktemp)"

cleanup() {
  rm -f "$PAYLOAD_FILE" "$GET_FILE" "$PUT_HEADERS" "$DELETE_FAIL_BODY" "$DELETE_FAIL_HEADERS"
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

curl_s3() {
  curl --silent --show-error --fail-with-body \
    --aws-sigv4 "aws:amz:${REGION}:${SERVICE}" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    "$@"
}

sign_bucket_op() {
  local op="$1"
  local bucket="$2"
  local visibility="${3:-private}"

  RPC_URL="${RPC_URL:-${S3GW_CHAIN_RPC_URL:-}}" \
    S3GW_BUCKET_OWNER_SIGNER_SURI="${S3GW_BUCKET_OWNER_SIGNER_SURI}" \
    cargo run -q -p gateway --bin sign_bucket_op -- "$op" "$bucket" "$visibility" \
    | awk -F= '/^x-s3gw-owner-signature=/{print $2}'
}

grant_delegation() {
  local scope="$1"

  RPC_URL="${RPC_URL}" \
    OWNER_HEX="${OWNER_HEX}" \
    S3GW_DELEGATION_OWNER_SIGNER_SURI="${S3GW_DELEGATION_OWNER_SIGNER_SURI}" \
    cargo run -q -p gateway --bin grant_delegation -- \
      "$DELEGATE_HEX" "$scope" "$EXPIRES_AT"
}

assert_header_absent() {
  local headers_file="$1"
  local header_name="$2"

  if grep -i "^${header_name}:" "$headers_file" >/dev/null; then
    echo "FAILED: unexpected private response header found: ${header_name}" >&2
    cat "$headers_file" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd sha256sum
need_cmd cargo

export RPC_URL="${RPC_URL:-${S3GW_CHAIN_RPC_URL:-}}"
export MASTER_SERVICE_KEY_HEX="${MASTER_SERVICE_KEY_HEX:-${S3GW_MASTER_SERVICE_KEY_HEX:-}}"

need_env RPC_URL
need_env MASTER_SERVICE_KEY_HEX
need_env AWS_ACCESS_KEY_ID
need_env AWS_SECRET_ACCESS_KEY
need_env S3GW_IDENTITY_REGISTRAR_SIGNER_SURI
need_env S3GW_BUCKET_OWNER_SIGNER_SURI
need_env S3GW_DELEGATION_OWNER_SIGNER_SURI

echo "== preflight: gateway reachable =="
if ! curl --silent --show-error --output /dev/null --max-time 3 "${ENDPOINT}/"; then
  echo "gateway is not reachable at ${ENDPOINT}" >&2
  echo "Start gateway with delegated anchor signer first, for example:" >&2
  echo "  export S3GW_ANCHOR_SIGNER_SURI='//Bob'" >&2
  echo "  RUST_LOG=gateway=debug cargo run -p gateway --bin gateway" >&2
  exit 1
fi
echo "gateway reachable"
echo

echo "== delegation scope smoke =="
echo "endpoint=${ENDPOINT}"
echo "bucket=${BUCKET}"
echo "object=${OBJECT_KEY}"
echo "owner=0x${OWNER_HEX}"
echo "delegate=0x${DELEGATE_HEX}"
echo

echo "== 1. Register owner identity =="
RPC_URL="$RPC_URL" \
MASTER_SERVICE_KEY_HEX="$MASTER_SERVICE_KEY_HEX" \
AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
OWNER_HEX="$OWNER_HEX" \
cargo run -q -p gateway --bin register_identity

echo
echo "== 2. Grant delegate CREATE_BUCKET + PUT_OBJECT =="
grant_delegation "$CREATE_AND_PUT_SCOPE"

echo
echo "== 3. Create private bucket through delegated gateway signer =="
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

echo "created private bucket via delegated anchor signer"

echo
echo "== 4. PUT private object succeeds with PUT_OBJECT scope =="
cat > "$PAYLOAD_FILE" <<'EOF'
delegation smoke payload
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
echo "delegated PUT succeeded and private response hid x-amz-meta-swarm-ref"

echo
echo "== 5. DELETE private object must fail without DELETE_OBJECT scope =="
set +e
curl_s3 \
  --request DELETE \
  --dump-header "$DELETE_FAIL_HEADERS" \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  "${ENDPOINT}/${BUCKET}/${OBJECT_KEY}" \
  --output "$DELETE_FAIL_BODY"
DELETE_STATUS=$?
set -e

if [[ "$DELETE_STATUS" -eq 0 ]]; then
  echo "FAILED: DELETE private object unexpectedly succeeded without DELETE_OBJECT scope" >&2
  exit 1
fi

if ! grep -q "Error6" "$DELETE_FAIL_BODY"; then
  echo "FAILED: DELETE failed, but not with expected InsufficientScope bucket error Error6" >&2
  echo "== response headers ==" >&2
  cat "$DELETE_FAIL_HEADERS" >&2
  echo >&2
  echo "== response body ==" >&2
  cat "$DELETE_FAIL_BODY" >&2
  echo >&2
  exit 1
fi

echo "delete failed as expected without DELETE_OBJECT scope"

echo
echo "== 6. Grant delegate DELETE_OBJECT + DELETE_BUCKET for cleanup =="
grant_delegation "$DELETE_CLEANUP_SCOPE"

echo
echo "== 7. DELETE private object succeeds after DELETE_OBJECT scope =="
curl_s3 \
  --request DELETE \
  --header "x-amz-content-sha256: ${EMPTY_SHA256}" \
  "${ENDPOINT}/${BUCKET}/${OBJECT_KEY}" >/dev/null

echo "deleted private object after delete scope grant"

echo
echo "== 8. DELETE private bucket succeeds after DELETE_BUCKET scope =="
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

echo "deleted private bucket after delete bucket scope grant"
echo
echo "DELEGATION SCOPE SMOKE PASSED"
