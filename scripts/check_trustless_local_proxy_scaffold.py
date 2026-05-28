#!/usr/bin/env python3
from pathlib import Path

required_files = [
    "trustless-proxy/README.md",
    "trustless-proxy/Cargo.toml",
    "trustless-proxy/src/lib.rs",
    "trustless-proxy/src/main.rs",
    "trustless-proxy/src/aws_esdk.rs",
    "trustless-proxy/src/config.rs",
    "trustless-proxy/src/cli.rs",
    "trustless-proxy/src/encryption.rs",
    "trustless-proxy/src/execution_coordinator.rs",
    "trustless-proxy/src/gateway_boundary.rs",
    "trustless-proxy/src/handler.rs",
    "trustless-proxy/src/http_handler.rs",
    "trustless-proxy/src/http_mapping.rs",
    "trustless-proxy/src/keyring.rs",
    "trustless-proxy/src/local_keystore.rs",
    "trustless-proxy/src/local_keystore_file.rs",
    "trustless-proxy/src/manifest.rs",
    "trustless-proxy/src/manifest_codec.rs",
    "trustless-proxy/src/operations.rs",
    "trustless-proxy/src/pipeline.rs",
    "trustless-proxy/src/planner.rs",
    "trustless-proxy/src/preflight.rs",
    "trustless-proxy/src/recipient_keys.rs",
    "trustless-proxy/src/references.rs",
    "trustless-proxy/src/remote_gateway.rs",
    "trustless-proxy/src/request_adapter.rs",
    "trustless-proxy/src/request_context.rs",
    "trustless-proxy/src/response_adapter.rs",
    "trustless-proxy/src/router.rs",
    "trustless-proxy/src/runtime.rs",
    "trustless-proxy/src/s3_surface.rs",
    "trustless-proxy/src/server.rs",
    "trustless-proxy/src/service.rs",
    "trustless-proxy/src/types.rs",
]

for file in required_files:
    if not Path(file).exists():
        raise SystemExit(f"FAILED: missing trustless Rust proxy scaffold file: {file}")

forbidden_files = [
    "trustless-proxy/package.json",
    "trustless-proxy/package-lock.json",
    "trustless-proxy/tsconfig.json",
    "trustless-proxy/src/config.ts",
    "trustless-proxy/src/index.ts",
    "trustless-proxy/src/keyring.ts",
    "trustless-proxy/src/types.ts",
]

for file in forbidden_files:
    if Path(file).exists():
        raise SystemExit(f"FAILED: TypeScript/Node proxy artifact must not exist: {file}")

readme = Path("trustless-proxy/README.md").read_text()
cargo = Path("trustless-proxy/Cargo.toml").read_text()

workspace = Path("Cargo.toml").read_text()
if '"trustless-proxy",' not in workspace:
    raise SystemExit("FAILED: trustless-proxy must be a root workspace member")

keyring = Path("trustless-proxy/src/keyring.rs").read_text()
types = Path("trustless-proxy/src/types.rs").read_text()
config = Path("trustless-proxy/src/config.rs").read_text()
local_env = Path(".env.local.example").read_text()
prod_env = Path(".env.production.example").read_text()

required_readme = [
    "Rust local S3-compatible proxy",
    "TrustlessPrivate buckets",
    "remote gateway must never receive plaintext object bytes",
    "AWS Encryption SDK for Rust",
    "must not introduce a TypeScript or Node.js runtime",
]

required_cargo = [
    "name = \"trustless-proxy\"",
    "edition = \"2024\"",
    "publish = false",
]

required_keyring = [
    "TrustlessRecipientKeyring",
    "trustless-recipient-keyring",
    "AWS Encryption SDK for Rust",
    "must never send",
    "EncryptNotImplemented",
    "DecryptNotImplemented",
]

required_types = [
    "TrustlessProxyConfig",
    "RecipientEncryptionKey",
    "RecipientEnvelopeContext",
    "TrustlessPutPlan",
    "TrustlessGetPlan",
    "ciphertext_only",
    "decrypt_locally",
]

required_config = [
    "TRUSTLESS_PROXY_REMOTE_GATEWAY_URL",
    "TRUSTLESS_PROXY_CHAIN_RPC_URL",
    "TRUSTLESS_PROXY_LOCAL_ACCOUNT",
    "TRUSTLESS_PROXY_KEYSTORE_PATH",
    "ConfigError",
]

required_env = [
    "TRUSTLESS_PROXY_REMOTE_GATEWAY_URL",
    "TRUSTLESS_PROXY_CHAIN_RPC_URL",
    "TRUSTLESS_PROXY_LOCAL_ACCOUNT",
    "TRUSTLESS_PROXY_KEYSTORE_PATH",
]

for token in required_readme:
    if token not in readme:
        raise SystemExit(f"FAILED: missing trustless Rust proxy README token: {token}")

for token in required_cargo:
    if token not in cargo:
        raise SystemExit(f"FAILED: missing trustless Rust proxy Cargo token: {token}")

for token in required_keyring:
    if token not in keyring:
        raise SystemExit(f"FAILED: missing trustless Rust proxy keyring token: {token}")

for token in required_types:
    if token not in types and token not in config:
        raise SystemExit(f"FAILED: missing trustless Rust proxy type/config token: {token}")

for token in required_config:
    if token not in config:
        raise SystemExit(f"FAILED: missing trustless Rust proxy config token: {token}")

for token in required_env:
    if token not in local_env:
        raise SystemExit(f"FAILED: missing local env trustless proxy token: {token}")
    if token not in prod_env:
        raise SystemExit(f"FAILED: missing production env trustless proxy token: {token}")

print("Trustless Rust local proxy scaffold guard passed.")
