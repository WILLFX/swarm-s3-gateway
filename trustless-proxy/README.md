# Trustless Local Proxy

This package contains the Rust local S3-compatible proxy for TrustlessPrivate buckets, referred to in user-facing docs as trustless private buckets.

The trustless proxy must not introduce a TypeScript or Node.js runtime.

The local proxy is the client-side trust boundary. It handles local plaintext, local encryption/decryption, local private-key custody, recipient envelope creation, encrypted manifest handling, and ciphertext-only forwarding to the remote gateway.

## Trust boundary

Plaintext is allowed here:

    S3 client <-> local trustless proxy

Plaintext is not allowed here:

    local trustless proxy <-> remote gateway
    remote gateway <-> Bee
    remote gateway <-> chain/contracts

The remote gateway must receive only ciphertext object bytes, encrypted manifest bytes, and metadata.

The remote gateway must never receive plaintext object bytes, plaintext data keys, private encryption keys, decrypted owner catalogs, decrypted bucket manifests, or decrypted object manifests for trustless private buckets.

Payload and manifest encryption use the AWS Encryption SDK for Rust with local recipient key material.


## Main command

    cargo run -p trustless-proxy --bin trustless-proxy -- local-proxy

## Required runtime environment

    TRUSTLESS_PROXY_REMOTE_GATEWAY_URL
    TRUSTLESS_PROXY_REMOTE_GATEWAY_ACCESS_KEY_ID
    TRUSTLESS_PROXY_REMOTE_GATEWAY_SECRET_ACCESS_KEY
    TRUSTLESS_PROXY_CHAIN_RPC_URL
    TRUSTLESS_PROXY_LOCAL_ACCOUNT
    TRUSTLESS_PROXY_KEYSTORE_PATH
    TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX
    TRUSTLESS_PROXY_RECIPIENT_KEYS_PATH

Optional:

    TRUSTLESS_PROXY_REMOTE_GATEWAY_REGION
    TRUSTLESS_PROXY_REMOTE_GATEWAY_SERVICE
    TRUSTLESS_PROXY_AWS_ESDK_KEY_NAMESPACE
    TRUSTLESS_PROXY_LISTEN_HOST
    TRUSTLESS_PROXY_LISTEN_PORT

Default local listener:

    127.0.0.1:9090

## Live local demo

From the repository root:

    ./scripts/trustless_live_local_proxy_demo.sh

Expected ending:

    === live local proxy demo passed ===

The demo generates local dev RSA key material, seals the private key into a local keystore, writes recipient key JSON, seeds an empty encrypted manifest, starts the local proxy, PUTs plaintext locally, GETs plaintext locally, and verifies `x-s3w-gateway-plaintext-access=false`.

## Dev helper binaries

    cargo run -p trustless-proxy --bin trustless_proxy_dev_key_material
    cargo run -p trustless-proxy --bin trustless_proxy_dev_encrypt_empty_manifest

These are local-development helpers only.

## Validation

    cargo test -p trustless-proxy -- --nocapture
    cargo check -p trustless-proxy

    ./scripts/check_trustless_live_local_proxy_demo_surface.py
    ./scripts/check_trustless_local_proxy_cli_surface.py
    ./scripts/check_trustless_local_proxy_scaffold.py
    ./scripts/check_trustless_local_proxy_aws_esdk_keyring_surface.py
    ./scripts/check_trustless_remote_gateway_http_client_surface.py
    ./scripts/check_docs_secret_safety.py
    ./scripts/check_no_silent_dev_signers.sh

## Security invariant

The proxy may handle plaintext locally.

The remote gateway must not receive plaintext.

The live demo checks:

    x-s3w-gateway-plaintext-access: false

## Production warning

Do not use generated demo private keys, unlock keys, placeholder credentials, dev signers, or dev fallback flags in production.
