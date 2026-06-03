# Trustless Local Dev Runbook

This runbook explains how to start the local trustless stack and run the live local proxy demo.

Target proof:

    S3-style client
      -> local trustless proxy
      -> local encryption/decryption
      -> signed remote gateway
      -> Bee ciphertext/encrypted manifest storage
      -> local plaintext returned on GET

## Prerequisites

Required commands:

    cargo --version
    curl --version
    bee version
    openssl version
    sha256sum --version
    xxd -h
    ss -h

The local Substrate dev chain should be running on:

    127.0.0.1:9944

Check:

    ss -ltnp | grep ':9944'

## 1. Bootstrap the dev stack

    ./scripts/trustless_dev_stack_bootstrap.sh

This script checks chain RPC, verifies or starts Bee, resolves or creates a Bee postage stamp, instantiates contracts, registers contract addresses, registers a dev identity, starts the gateway, verifies signed auth, and runs a ciphertext gateway smoke test.

Expected ending:

    === dev stack bootstrap passed ===
    env file: /tmp/s3w-dev-stack-.../dev-stack.env
    logs: /tmp/s3w-dev-stack-.../logs

## 2. Verify the generated env

    LATEST_ENV="$(ls -td /tmp/s3w-dev-stack-*/dev-stack.env | head -1)"
    cat "$LATEST_ENV"

## 3. Restart the gateway if needed

    LATEST_ENV="$(ls -td /tmp/s3w-dev-stack-*/dev-stack.env | head -1)"
    source "$LATEST_ENV"

    S3GW_BIND_ADDR="127.0.0.1:3000" \
    S3GW_CHAIN_RPC_URL="$CHAIN_RPC_WS" \
    S3GW_BEE_API_URL="$BEE_API_URL" \
    S3GW_BEE_STAMP_BATCH_ID="$S3GW_BEE_STAMP_BATCH_ID" \
    S3GW_MASTER_SERVICE_KEY_HEX="$S3GW_MASTER_SERVICE_KEY_HEX" \
    S3GW_ENABLE_DEV_DEFAULTS="true" \
    S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK="true" \
    S3GW_GAS_TANK_SEED="s3w-local-dev-gas-tank" \
    S3GW_ANCHOR_SIGNER_SURI="//Alice" \
    RUST_LOG=gateway=debug,tower_http=debug \
      cargo run -q -p gateway --bin gateway

Verify signed gateway auth in another terminal:

    LATEST_ENV="$(ls -td /tmp/s3w-dev-stack-*/dev-stack.env | head -1)"
    source "$LATEST_ENV"

    curl -fsS \
      --aws-sigv4 "aws:amz:us-east-1:s3" \
      --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
      -H "x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
      "$GATEWAY_ENDPOINT/" >/dev/null

    echo "gateway signed auth works"

## 4. Run the live local proxy demo

    ./scripts/trustless_live_local_proxy_demo.sh

Expected ending:

    === live local proxy demo passed ===
    run_dir=/tmp/s3w-live-local-proxy-demo-...
    local_proxy_log=/tmp/s3w-live-local-proxy-demo-.../local-proxy.log

## 5. Expected ports

    127.0.0.1:9944   Substrate dev chain
    127.0.0.1:1633   Bee dev API
    127.0.0.1:3000   remote gateway
    127.0.0.1:9090   trustless local proxy

Check:

    ss -ltnp | grep -E ':3000|:1633|:9944|:9090'

## 6. Logs

Bootstrap logs:

    ls -td /tmp/s3w-dev-stack-*/logs | head -1

Live demo run dir:

    ls -td /tmp/s3w-live-local-proxy-demo-* | head -1

Latest local proxy log:

    RUN_DIR="$(ls -td /tmp/s3w-live-local-proxy-demo-* | head -1)"
    cat "$RUN_DIR/local-proxy.log"

## 7. Common failures

### Gateway is not running

Restart the gateway from the latest bootstrap env using section 3.

### Local proxy port already in use

    pkill -f 'target/debug/trustless-proxy.*local-proxy' || true
    pkill -f 'cargo run.*trustless-proxy.*local-proxy' || true

### Missing encrypted manifest on first PUT

The local proxy fails closed when the encrypted manifest is missing. The live demo handles first-object bootstrap by encrypting and seeding an empty manifest before the first PUT.

### Outdated transaction during contract address registration

The bootstrap script retries `set_contract_addresses` when the local chain reports:

    Invalid transaction: Transaction is outdated

## 8. Safety rule

Dev scripts and helper binaries are local-development only.

Do not use generated demo keys, dev signers, placeholder keys, or dev fallback flags in production.
