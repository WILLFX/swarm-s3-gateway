# Swarm S3 Gateway

Swarm S3 Gateway is an S3-compatible storage system that uses Swarm/Bee for content storage and a Substrate chain/contracts layer for identity, bucket state, and anchoring.

The current main architecture is the trustless private storage path:

    S3-style client
      -> local trustless proxy
      -> local encryption/decryption
      -> signed remote gateway
      -> Bee ciphertext/encrypted manifest storage
      -> chain/contracts anchoring

The remote gateway must never receive private plaintext object bytes.

Plaintext exists only at the local client/local proxy boundary. The remote gateway stores and returns ciphertext, encrypted manifests, metadata, and chain anchors.

## Current status

The trustless local proxy path has been implemented and live-proven locally.

The live demo proves:

    PUT plaintext locally
    local proxy encrypts locally
    remote gateway receives ciphertext/encrypted manifest only
    Bee stores ciphertext/encrypted manifest only
    GET fetches ciphertext
    local proxy decrypts locally
    GET returns original plaintext
    x-s3w-gateway-plaintext-access remains false

## Main components

### Trustless local proxy

Package:

    trustless-proxy/

The local proxy is the client-side trust boundary.

It is responsible for local plaintext handling, local encryption/decryption, local private-key custody, recipient envelopes, encrypted manifests, and ciphertext-only forwarding to the remote gateway.

### Remote gateway

Package:

    gateway/

The remote gateway is responsible for SigV4 authentication, authorization checks, Bee storage/retrieval, contract/pallet reads, and chain anchoring.

For trustless private buckets, the remote gateway must not perform plaintext encryption or plaintext decryption.

It should only see:

    ciphertext object bytes
    encrypted manifest bytes
    encrypted metadata/envelopes
    chain anchor data

### Chain and contracts

The chain/contracts layer anchors identity and bucket state. It is not the privacy layer. Privacy comes from client-side encryption and from keeping plaintext away from the remote gateway.

### Bee/Swarm

Bee/Swarm stores content-addressed bytes. In the trustless path, Bee stores ciphertext and encrypted manifests.

## Trustless private flow

### PUT

    1. S3 client sends PUT plaintext to local trustless proxy.
    2. Local proxy encrypts object bytes locally.
    3. Local proxy updates/encrypts manifests locally.
    4. Local proxy sends ciphertext/encrypted manifest bytes to the remote gateway.
    5. Remote gateway stores ciphertext/encrypted manifest through Bee.
    6. Local proxy returns an S3-style success response.

### GET

    1. S3 client sends GET to local trustless proxy.
    2. Local proxy requests ciphertext/encrypted manifest from the remote gateway.
    3. Remote gateway returns ciphertext only.
    4. Local proxy decrypts locally.
    5. Local proxy returns plaintext to the local S3 client.

## Local development quick start

Start or verify the local Substrate dev chain first.

Expected chain RPC:

    127.0.0.1:9944

Bootstrap the trustless dev stack:

    ./scripts/trustless_dev_stack_bootstrap.sh

Expected ending:

    === dev stack bootstrap passed ===
    env file: /tmp/s3w-dev-stack-.../dev-stack.env
    logs: /tmp/s3w-dev-stack-.../logs

Run the live local proxy demo:

    ./scripts/trustless_live_local_proxy_demo.sh

Expected ending:

    === live local proxy demo passed ===
    run_dir=/tmp/s3w-live-local-proxy-demo-...
    local_proxy_log=/tmp/s3w-live-local-proxy-demo-.../local-proxy.log

Full runbook:

    docs/runbooks/trustless-local-dev.md

## Expected local ports

    127.0.0.1:9944   local Substrate dev chain
    127.0.0.1:1633   Bee dev API
    127.0.0.1:3000   remote gateway
    127.0.0.1:9090   trustless local proxy

## Validation

    cargo test -p trustless-proxy -- --nocapture
    cargo test -p gateway -- --nocapture

    cargo check -p trustless-proxy
    cargo check -p gateway

    ./scripts/check_trustless_live_local_proxy_demo_surface.py
    ./scripts/check_trustless_local_proxy_cli_surface.py
    ./scripts/check_trustless_local_proxy_scaffold.py
    ./scripts/check_trustless_local_proxy_aws_esdk_keyring_surface.py
    ./scripts/check_trustless_remote_gateway_http_client_surface.py
    ./scripts/check_gateway_trustless_ciphertext_endpoint_surface.py
    ./scripts/check_docs_secret_safety.py
    ./scripts/check_no_silent_dev_signers.sh

## Documentation map

- `docs/runbooks/trustless-local-dev.md` — startup commands and live demo runbook.
- `docs/security/trustless-private-access-model.md` — trustless security model.
- `docs/security/chain-privacy-surface.md` — chain metadata/privacy surface.
- `docs/security/private-encryption-version-rotation.md` — private encryption rotation limitations.
- `docs/private-lifecycle-operator-guide.md` — older trusted-gateway private lifecycle guide.

## Production warning

The local scripts and helper binaries are for local development proof only.

Do not use dev signers, dev fallback flags, generated demo key material, local demo unlock keys, or placeholder master keys in production.
