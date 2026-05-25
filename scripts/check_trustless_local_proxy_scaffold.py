#!/usr/bin/env python3
from pathlib import Path

required_files = [
    "trustless-proxy/README.md",
    "trustless-proxy/package.json",
    "trustless-proxy/tsconfig.json",
    "trustless-proxy/src/types.ts",
    "trustless-proxy/src/config.ts",
    "trustless-proxy/src/keyring.ts",
    "trustless-proxy/src/index.ts",
]

for file in required_files:
    if not Path(file).exists():
        raise SystemExit(f"FAILED: missing trustless local proxy scaffold file: {file}")

readme = Path("trustless-proxy/README.md").read_text()
package = Path("trustless-proxy/package.json").read_text()
keyring = Path("trustless-proxy/src/keyring.ts").read_text()
types = Path("trustless-proxy/src/types.ts").read_text()
local_env = Path(".env.local.example").read_text()
prod_env = Path(".env.production.example").read_text()

required_readme = [
    "local S3-compatible proxy",
    "TrustlessPrivate buckets",
    "remote gateway must never receive plaintext object bytes",
    "custom `aws-esdk` keyring",
]

required_package = [
    "@aws-crypto/client-node",
    "@aws-crypto/material-management-node",
    "typescript",
    "\"check\": \"tsc --noEmit\"",
]

required_keyring = [
    "TrustlessRecipientKeyring",
    "trustless-recipient-keyring",
    "aws-esdk",
    "must never send plaintext data keys",
]

required_types = [
    "TrustlessProxyConfig",
    "RecipientEncryptionKey",
    "RecipientEnvelopeContext",
    "TrustlessPutPlan",
    "TrustlessGetPlan",
    "ciphertextOnly: true",
    "decryptLocally: true",
]

required_env = [
    "TRUSTLESS_PROXY_REMOTE_GATEWAY_URL",
    "TRUSTLESS_PROXY_CHAIN_RPC_URL",
    "TRUSTLESS_PROXY_LOCAL_ACCOUNT",
    "TRUSTLESS_PROXY_KEYSTORE_PATH",
]

for token in required_readme:
    if token not in readme:
        raise SystemExit(f"FAILED: missing trustless proxy README token: {token}")

for token in required_package:
    if token not in package:
        raise SystemExit(f"FAILED: missing trustless proxy package token: {token}")

for token in required_keyring:
    if token not in keyring:
        raise SystemExit(f"FAILED: missing trustless proxy keyring token: {token}")

for token in required_types:
    if token not in types:
        raise SystemExit(f"FAILED: missing trustless proxy type token: {token}")

for token in required_env:
    if token not in local_env:
        raise SystemExit(f"FAILED: missing local env trustless proxy token: {token}")
    if token not in prod_env:
        raise SystemExit(f"FAILED: missing production env trustless proxy token: {token}")

print("Trustless local proxy scaffold guard passed.")
