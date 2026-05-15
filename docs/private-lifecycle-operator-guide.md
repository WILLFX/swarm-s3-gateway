# Private S3 Lifecycle Operator Guide

This guide documents the local operator setup for running the S3 gateway private bucket lifecycle against:

- local Substrate/contracts chain
- Bee/Swarm node
- S3 gateway HTTP server
- deployed identity and bucket ink! contracts registered in the S3Contracts pallet

The private lifecycle smoke script is:

```bash
./scripts/private_lifecycle_smoke.sh
```

It covers:

- identity registration
- private bucket creation
- private object PUT
- private object HEAD
- private object GET
- private bucket ListObjectsV2
- private object DELETE
- private bucket DELETE
- decrypted payload verification
- verification that private responses do not expose `x-amz-meta-swarm-ref`

## Important port note

The gateway binary defaults to:

```text
127.0.0.1:8000
```

The smoke script defaults to:

```text
http://127.0.0.1:3000
```

So for the smoke script, start the gateway with:

```bash
export S3GW_BIND_ADDR="127.0.0.1:3000"
```

Alternatively, leave the gateway on `8000` and run the smoke script with:

```bash
S3GW_ENDPOINT="http://127.0.0.1:8000" ./scripts/private_lifecycle_smoke.sh
```

## Required running services

Before running the smoke script, make sure these are running:

1. Local chain RPC, usually:

```bash
ws://127.0.0.1:9944
```

2. Bee API, usually:

```bash
http://127.0.0.1:1633
```

3. Gateway HTTP server.

## Required environment variables for gateway

Start the gateway in its own terminal.

```bash
cd ~/projects/s3-blockchain/swarm-s3-gateway

export S3GW_BIND_ADDR="127.0.0.1:3000"

export S3GW_CHAIN_RPC_URL="ws://127.0.0.1:9944"
export S3GW_BEE_API_URL="http://127.0.0.1:1633"

export S3GW_MASTER_SERVICE_KEY_HEX="PASTE_64_HEX_MASTER_SERVICE_KEY"
export S3GW_BEE_STAMP_BATCH_ID="PASTE_64_HEX_BEE_POSTAGE_BATCH_ID"
export S3GW_GAS_TANK_SEED="dev-gas-tank-seed"

export S3GW_EXPECTED_REGION="us-east-1"
export S3GW_EXPECTED_SERVICE="s3"
export S3GW_ALLOW_UNSIGNED_PAYLOAD="false"

cargo run -p gateway --bin gateway
```

Leave this terminal running.

## Verify gateway is reachable

In a second terminal:

```bash
ss -ltnp | grep ':3000'
curl -v http://127.0.0.1:3000/
```

The `curl` request does not need to return a successful S3 response. It only needs to connect to the gateway.

If you see:

```text
Connection refused
```

then the gateway is not listening on that port.

## Required environment variables for smoke script

The smoke script requires:

```bash
RPC_URL="ws://127.0.0.1:9944"
MASTER_SERVICE_KEY_HEX="PASTE_64_HEX_MASTER_SERVICE_KEY"
AWS_ACCESS_KEY_ID="some-unique-access-key"
AWS_SECRET_ACCESS_KEY="some-unique-secret"
```

The master key must be exactly 64 hex characters because it decodes to 32 bytes.

Do not commit real secrets into the repository.

## Run the private lifecycle smoke

Use a fresh access key and bucket name each run to avoid identity/bucket collisions:

```bash
RUN_ID="$(date +%s)"

S3GW_ENDPOINT="http://127.0.0.1:3000" \
RPC_URL="ws://127.0.0.1:9944" \
BUCKET="private-smoke-${RUN_ID}" \
AWS_ACCESS_KEY_ID="contract-access-${RUN_ID}" \
AWS_SECRET_ACCESS_KEY="contract-secret-${RUN_ID}" \
./scripts/private_lifecycle_smoke.sh
```

Expected final output:

```text
PRIVATE LIFECYCLE SMOKE PASSED
```

## Common failures

### `missing required env: MASTER_SERVICE_KEY_HEX`

The shell running the smoke script does not have the master key.

Fix:

```bash
export MASTER_SERVICE_KEY_HEX="PASTE_64_HEX_MASTER_SERVICE_KEY"
```

or:

```bash
export S3GW_MASTER_SERVICE_KEY_HEX="PASTE_64_HEX_MASTER_SERVICE_KEY"
```

### `Contracts::ContractReverted` with decoded `Error0` during identity registration

This usually means the access key is already registered.

Use a fresh key:

```bash
RUN_ID="$(date +%s)"
AWS_ACCESS_KEY_ID="contract-access-${RUN_ID}"
AWS_SECRET_ACCESS_KEY="contract-secret-${RUN_ID}"
```

### `Failed to connect to 127.0.0.1 port 3000`

The gateway is not running on `3000`.

Fix by starting the gateway with:

```bash
export S3GW_BIND_ADDR="127.0.0.1:3000"
cargo run -p gateway --bin gateway
```

Or run the smoke against the gateway's actual port:

```bash
S3GW_ENDPOINT="http://127.0.0.1:8000" ./scripts/private_lifecycle_smoke.sh
```

### `cargo run could not determine which binary to run`

The gateway crate has multiple binaries.

Use:

```bash
cargo run -p gateway --bin gateway
```

not:

```bash
cargo run -p gateway
```

## Security notes

Private object payloads are encrypted before being written to Bee/Swarm.

Private object responses must not expose:

```text
x-amz-meta-swarm-ref
```

The smoke script checks this for:

- private PUT
- private HEAD
- private GET
- private LIST

Public bucket responses may still expose the Swarm reference header.
