#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CHAIN_RPC_HTTP="${CHAIN_RPC_HTTP:-http://127.0.0.1:9944}"
CHAIN_RPC_WS="${CHAIN_RPC_WS:-ws://127.0.0.1:9944}"

BEE_API_URL="${BEE_API_URL:-http://127.0.0.1:1633}"
BEE_API_ADDR="${BEE_API_ADDR:-127.0.0.1:1633}"
BEE_HOME="${BEE_HOME:-/tmp/s3w-bee-dev/home}"
BEE_STAMP_AMOUNT="${BEE_STAMP_AMOUNT:-10000000}"
BEE_STAMP_DEPTH="${BEE_STAMP_DEPTH:-20}"
BEE_STAMP_LABEL="${BEE_STAMP_LABEL:-s3w-demo}"

GATEWAY_BIND_ADDR="${GATEWAY_BIND_ADDR:-127.0.0.1:3000}"
GATEWAY_ENDPOINT="${GATEWAY_ENDPOINT:-http://127.0.0.1:3000}"

CONTRACT_DEPLOYER_SURI="${CONTRACT_DEPLOYER_SURI:-//Alice}"
S3GW_SUDO_SIGNER_SURI="${S3GW_SUDO_SIGNER_SURI:-//Alice}"
S3GW_IDENTITY_REGISTRAR_SIGNER_SURI="${S3GW_IDENTITY_REGISTRAR_SIGNER_SURI:-//Alice}"
S3GW_BUCKET_OWNER_SIGNER_SURI="${S3GW_BUCKET_OWNER_SIGNER_SURI:-//Alice}"
S3GW_ANCHOR_SIGNER_SURI="${S3GW_ANCHOR_SIGNER_SURI:-//Alice}"

ALICE_ACCOUNT_HEX="${ALICE_ACCOUNT_HEX:-0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d}"

AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-s3w-dev-access-key}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-s3w-dev-secret-key}"
S3GW_MASTER_SERVICE_KEY_HEX="${S3GW_MASTER_SERVICE_KEY_HEX:-0000000000000000000000000000000000000000000000000000000000000001}"

S3GW_GAS_TANK_SEED="${S3GW_GAS_TANK_SEED:-s3w-local-dev-gas-tank}"
S3GW_ENABLE_DEV_DEFAULTS="${S3GW_ENABLE_DEV_DEFAULTS:-true}"
S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK="${S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK:-true}"

IDENTITY_CONTRACT_ARTIFACT="${IDENTITY_CONTRACT_ARTIFACT:-target/ink/s3_identity_contract/s3_identity_contract.contract}"
BUCKET_CONTRACT_ARTIFACT="${BUCKET_CONTRACT_ARTIFACT:-target/ink/s3_bucket_contract/s3_bucket_contract.contract}"

RUN_DIR="${RUN_DIR:-/tmp/s3w-dev-stack}"
LOG_DIR="$RUN_DIR/logs"
ENV_FILE="$RUN_DIR/dev-stack.env"

mkdir -p "$LOG_DIR"

log() {
  printf '\n=== %s ===\n' "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

wait_http_ok() {
  local url="$1"
  local label="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for $label at $url" >&2
  exit 1
}

http_endpoint_reachable() {
  local url="$1"
  curl -sS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null | grep -Eq '^[1-5][0-9][0-9]$'
}

wait_http_reachable() {
  local url="$1"
  local label="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "$attempts"); do
    if http_endpoint_reachable "$url"; then
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for $label at $url" >&2
  exit 1
}

json_field() {
  local field="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$field"
}

ss58_to_account_hex() {
  python3 - "$1" <<'PYSS58'
import hashlib
import sys

address = sys.argv[1]
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

num = 0
for char in address:
    num *= 58
    num += alphabet.index(char)

raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
leading_zeroes = len(address) - len(address.lstrip("1"))
raw = b"\x00" * leading_zeroes + raw

if len(raw) < 35:
    raise SystemExit(f"SS58 address too short: {address}")

if raw[0] & 0b0100_0000 == 0:
    prefix_len = 1
elif raw[0] & 0b1000_0000 == 0:
    prefix_len = 2
else:
    raise SystemExit(f"unsupported SS58 prefix encoding: {address}")

account_len = 32
checksum_len = len(raw) - prefix_len - account_len
if checksum_len <= 0:
    raise SystemExit(f"missing SS58 checksum: {address}")

body = raw[:prefix_len + account_len]
checksum = raw[prefix_len + account_len:]
expected = hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:checksum_len]

if checksum != expected:
    raise SystemExit(f"bad SS58 checksum: {address}")

print("0x" + body[prefix_len:].hex())
PYSS58
}

extract_usable_stamp() {
  python3 -c 'import json,sys
data=json.loads(sys.argv[1] or "{}")
for stamp in data.get("stamps", []):
    if stamp.get("usable") and stamp.get("batchID"):
        print(stamp["batchID"])
        break
' "$1"
}

signed_post_json() {
  local label="$1"
  local file="$2"
  local out="$3"
  local hash

  hash="$(sha256sum "$file" | awk '{print $1}')"

  log "$label"
  echo "payload_sha256=$hash"

  curl -fsS \
    --aws-sigv4 "aws:amz:us-east-1:s3" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    -H "content-type: application/json" \
    -H "x-amz-content-sha256: ${hash}" \
    --data-binary "@${file}" \
    "${GATEWAY_ENDPOINT}/trustless/v1/ciphertext-gateway" \
    | tee "$out"
  echo
}

require_cmd curl
require_cmd python3
require_cmd cargo
require_cmd bee
require_cmd sha256sum
require_cmd xxd

log "checking chain RPC"
curl -fsS \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' \
  "$CHAIN_RPC_HTTP" \
  | tee "$LOG_DIR/chain-health.json"
echo

if ! curl -fsS "$BEE_API_URL/readiness" >/dev/null 2>&1; then
  log "starting Bee dev"
  mkdir -p "$BEE_HOME"

  HOME="$BEE_HOME" \
  bee dev \
    --api-addr "$BEE_API_ADDR" \
    --verbosity debug \
    >"$LOG_DIR/bee.log" 2>&1 &

  echo $! > "$RUN_DIR/bee.pid"
fi

log "waiting for Bee readiness"
wait_http_ok "$BEE_API_URL/readiness" "Bee"
curl -fsS "$BEE_API_URL/readiness" | tee "$LOG_DIR/bee-readiness.json"
echo

log "resolving Bee postage stamp"
STAMPS_JSON="$(curl -fsS "$BEE_API_URL/stamps")"
BEE_STAMP_BATCH_ID="$(extract_usable_stamp "$STAMPS_JSON")"

if [ -z "$BEE_STAMP_BATCH_ID" ]; then
  log "creating Bee dev postage stamp"
  BEE_STAMP_BATCH_ID="$(
    curl -fsS -X POST \
      "${BEE_API_URL}/stamps/${BEE_STAMP_AMOUNT}/${BEE_STAMP_DEPTH}?label=${BEE_STAMP_LABEL}" \
      | json_field batchID
  )"
fi

echo "BEE_STAMP_BATCH_ID=$BEE_STAMP_BATCH_ID" | tee "$LOG_DIR/bee-stamp.txt"

log "checking gateway port is free"
if http_endpoint_reachable "$GATEWAY_ENDPOINT/"; then
  echo "gateway endpoint is already reachable at $GATEWAY_ENDPOINT" >&2
  echo "stop the existing gateway before running this bootstrap script so fresh contract addresses are loaded" >&2
  exit 1
fi

log "checking contract artifacts"
test -f "$IDENTITY_CONTRACT_ARTIFACT"
test -f "$BUCKET_CONTRACT_ARTIFACT"

CONTRACT_SALT_SUFFIX="${CONTRACT_SALT_SUFFIX:-$(date +%s)-$$}"
IDENTITY_CONTRACT_SALT_HEX="$(printf 's3w-identity-%s' "$CONTRACT_SALT_SUFFIX" | xxd -p -c 256)"
BUCKET_CONTRACT_SALT_HEX="$(printf 's3w-bucket-%s' "$CONTRACT_SALT_SUFFIX" | xxd -p -c 256)"

echo "identity_contract_salt_hex=$IDENTITY_CONTRACT_SALT_HEX" | tee "$LOG_DIR/identity-contract-salt.txt"
echo "bucket_contract_salt_hex=$BUCKET_CONTRACT_SALT_HEX" | tee "$LOG_DIR/bucket-contract-salt.txt"

log "instantiating identity contract"
IDENTITY_JSON="$LOG_DIR/instantiate-identity.json"
cargo contract instantiate \
  "$IDENTITY_CONTRACT_ARTIFACT" \
  --constructor new \
  --args "$ALICE_ACCOUNT_HEX" \
  --salt "$IDENTITY_CONTRACT_SALT_HEX" \
  --suri "$CONTRACT_DEPLOYER_SURI" \
  --url "$CHAIN_RPC_WS" \
  --execute \
  --skip-confirm \
  --output-json \
  | tee "$IDENTITY_JSON"

IDENTITY_CONTRACT_SS58="$(json_field contract < "$IDENTITY_JSON")"
IDENTITY_CONTRACT_ADDRESS_HEX="$(ss58_to_account_hex "$IDENTITY_CONTRACT_SS58")"

log "instantiating bucket contract"
BUCKET_JSON="$LOG_DIR/instantiate-bucket.json"
cargo contract instantiate \
  "$BUCKET_CONTRACT_ARTIFACT" \
  --constructor new \
  --args "$ALICE_ACCOUNT_HEX" "$IDENTITY_CONTRACT_SS58" \
  --salt "$BUCKET_CONTRACT_SALT_HEX" \
  --suri "$CONTRACT_DEPLOYER_SURI" \
  --url "$CHAIN_RPC_WS" \
  --execute \
  --skip-confirm \
  --output-json \
  | tee "$BUCKET_JSON"

BUCKET_CONTRACT_SS58="$(json_field contract < "$BUCKET_JSON")"
BUCKET_CONTRACT_ADDRESS_HEX="$(ss58_to_account_hex "$BUCKET_CONTRACT_SS58")"

log "registering contract addresses in S3Contracts pallet"
SET_CONTRACT_ADDRESSES_ATTEMPT=1

while true; do
  set +e
  RPC_URL="$CHAIN_RPC_WS" \
  S3GW_SUDO_SIGNER_SURI="$S3GW_SUDO_SIGNER_SURI" \
  IDENTITY_CONTRACT_ADDRESS_HEX="$IDENTITY_CONTRACT_ADDRESS_HEX" \
  BUCKET_CONTRACT_ADDRESS_HEX="$BUCKET_CONTRACT_ADDRESS_HEX" \
    cargo run -q -p gateway --bin set_contract_addresses \
    2>&1 | tee "$LOG_DIR/set-contract-addresses-attempt-${SET_CONTRACT_ADDRESSES_ATTEMPT}.log"
  status="${PIPESTATUS[0]}"
  set -e

  if [ "$status" -eq 0 ]; then
    cp "$LOG_DIR/set-contract-addresses-attempt-${SET_CONTRACT_ADDRESSES_ATTEMPT}.log" \
      "$LOG_DIR/set-contract-addresses.log"
    break
  fi

  if [ "$SET_CONTRACT_ADDRESSES_ATTEMPT" -ge 3 ]; then
    echo "set_contract_addresses failed after ${SET_CONTRACT_ADDRESSES_ATTEMPT} attempts" >&2
    exit "$status"
  fi

  if grep -qi "transaction is outdated" \
    "$LOG_DIR/set-contract-addresses-attempt-${SET_CONTRACT_ADDRESSES_ATTEMPT}.log"; then
    echo "set_contract_addresses hit outdated nonce; retrying after finality wait"
    SET_CONTRACT_ADDRESSES_ATTEMPT=$((SET_CONTRACT_ADDRESSES_ATTEMPT + 1))
    sleep 6
    continue
  fi

  exit "$status"
done

log "bucket registry sanity check"
RPC_URL="$CHAIN_RPC_WS" \
S3GW_BUCKET_OWNER_SIGNER_SURI="$S3GW_BUCKET_OWNER_SIGNER_SURI" \
  cargo run -q -p gateway --bin sign_bucket_op -- create-trustless trustless-demo-bucket private \
  | tee "$LOG_DIR/sign-bucket-op.log"

log "registering dev identity"
RPC_URL="$CHAIN_RPC_WS" \
MASTER_SERVICE_KEY_HEX="$S3GW_MASTER_SERVICE_KEY_HEX" \
AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
S3GW_IDENTITY_REGISTRAR_SIGNER_SURI="$S3GW_IDENTITY_REGISTRAR_SIGNER_SURI" \
  cargo run -q -p gateway --bin register_identity \
  | tee "$LOG_DIR/register-identity.log"

cat > "$ENV_FILE" <<EOFENV
export CHAIN_RPC_HTTP="$CHAIN_RPC_HTTP"
export CHAIN_RPC_WS="$CHAIN_RPC_WS"
export BEE_API_URL="$BEE_API_URL"
export S3GW_BEE_STAMP_BATCH_ID="$BEE_STAMP_BATCH_ID"
export IDENTITY_CONTRACT_SS58="$IDENTITY_CONTRACT_SS58"
export IDENTITY_CONTRACT_ADDRESS_HEX="$IDENTITY_CONTRACT_ADDRESS_HEX"
export BUCKET_CONTRACT_SS58="$BUCKET_CONTRACT_SS58"
export BUCKET_CONTRACT_ADDRESS_HEX="$BUCKET_CONTRACT_ADDRESS_HEX"
export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
export S3GW_MASTER_SERVICE_KEY_HEX="$S3GW_MASTER_SERVICE_KEY_HEX"
export GATEWAY_ENDPOINT="$GATEWAY_ENDPOINT"
EOFENV

log "dev stack env"
cat "$ENV_FILE"

log "starting gateway"
S3GW_BIND_ADDR="$GATEWAY_BIND_ADDR" \
S3GW_CHAIN_RPC_URL="$CHAIN_RPC_WS" \
S3GW_BEE_API_URL="$BEE_API_URL" \
S3GW_BEE_STAMP_BATCH_ID="$BEE_STAMP_BATCH_ID" \
S3GW_MASTER_SERVICE_KEY_HEX="$S3GW_MASTER_SERVICE_KEY_HEX" \
S3GW_ENABLE_DEV_DEFAULTS="$S3GW_ENABLE_DEV_DEFAULTS" \
S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK="$S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK" \
S3GW_GAS_TANK_SEED="$S3GW_GAS_TANK_SEED" \
S3GW_ANCHOR_SIGNER_SURI="$S3GW_ANCHOR_SIGNER_SURI" \
RUST_LOG=gateway=debug,tower_http=debug \
  cargo run -q -p gateway --bin gateway \
  >"$LOG_DIR/gateway.log" 2>&1 &

echo $! > "$RUN_DIR/gateway.pid"
wait_http_reachable "$GATEWAY_ENDPOINT/" "gateway"

log "checking signed gateway root"
EMPTY_HASH="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

curl -fsS \
  --aws-sigv4 "aws:amz:us-east-1:s3" \
  --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
  -H "x-amz-content-sha256: ${EMPTY_HASH}" \
  "$GATEWAY_ENDPOINT/" \
  | tee "$LOG_DIR/signed-root.xml"
echo

log "running live trustless gateway smoke"
SMOKE_DIR="$RUN_DIR/live-trustless-smoke"
mkdir -p "$SMOKE_DIR"

SMOKE_BUCKET="trustless-bootstrap-smoke"
SMOKE_OBJECT_KEY="docs/a.txt"
CIPHERTEXT_HEX="$(printf 'remote gateway ciphertext only' | xxd -p -c 256)"
MANIFEST_HEX="$(printf 'encrypted manifest only' | xxd -p -c 256)"

cat > "$SMOKE_DIR/put-object.json" <<EOFPUT
{"version":1,"action":"put_ciphertext_object","bucket":"${SMOKE_BUCKET}","key":"${SMOKE_OBJECT_KEY}","ciphertext_hex":"${CIPHERTEXT_HEX}","encrypted_manifest_hex":null,"plaintext_payload_present":false,"gateway_plaintext_access":false}
EOFPUT

cat > "$SMOKE_DIR/get-object.json" <<EOFGET
{"version":1,"action":"get_ciphertext_object","bucket":"${SMOKE_BUCKET}","key":"${SMOKE_OBJECT_KEY}","ciphertext_hex":null,"encrypted_manifest_hex":null,"plaintext_payload_present":false,"gateway_plaintext_access":false}
EOFGET

cat > "$SMOKE_DIR/put-manifest.json" <<EOFMANPUT
{"version":1,"action":"put_encrypted_manifest","bucket":"${SMOKE_BUCKET}","key":null,"ciphertext_hex":null,"encrypted_manifest_hex":"${MANIFEST_HEX}","plaintext_payload_present":false,"gateway_plaintext_access":false}
EOFMANPUT

cat > "$SMOKE_DIR/list-manifest.json" <<EOFMANGET
{"version":1,"action":"list_ciphertext_manifest","bucket":"${SMOKE_BUCKET}","key":null,"ciphertext_hex":null,"encrypted_manifest_hex":null,"plaintext_payload_present":false,"gateway_plaintext_access":false}
EOFMANGET

signed_post_json "put ciphertext object" "$SMOKE_DIR/put-object.json" "$SMOKE_DIR/put-object.out"
signed_post_json "get ciphertext object" "$SMOKE_DIR/get-object.json" "$SMOKE_DIR/get-object.out"
signed_post_json "put encrypted manifest" "$SMOKE_DIR/put-manifest.json" "$SMOKE_DIR/put-manifest.out"
signed_post_json "list encrypted manifest" "$SMOKE_DIR/list-manifest.json" "$SMOKE_DIR/list-manifest.out"

grep -F "\"metadata_only\":true" "$SMOKE_DIR/put-object.out" >/dev/null
grep -F "\"gateway_plaintext_access\":false" "$SMOKE_DIR/put-object.out" >/dev/null
grep -F "\"ciphertext_hex\":\"${CIPHERTEXT_HEX}\"" "$SMOKE_DIR/get-object.out" >/dev/null
grep -F "\"gateway_plaintext_access\":false" "$SMOKE_DIR/get-object.out" >/dev/null
grep -F "\"metadata_only\":true" "$SMOKE_DIR/put-manifest.out" >/dev/null
grep -F "\"gateway_plaintext_access\":false" "$SMOKE_DIR/put-manifest.out" >/dev/null
grep -F "\"encrypted_manifest_hex\":\"${MANIFEST_HEX}\"" "$SMOKE_DIR/list-manifest.out" >/dev/null
grep -F "\"gateway_plaintext_access\":false" "$SMOKE_DIR/list-manifest.out" >/dev/null

log "dev stack bootstrap passed"
echo "env file: $ENV_FILE"
echo "logs: $LOG_DIR"
