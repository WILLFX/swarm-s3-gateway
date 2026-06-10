#!/usr/bin/env python3
from pathlib import Path

script = Path("scripts/trustless_live_local_proxy_demo.sh").read_text()
key_helper = Path("trustless-proxy/src/bin/trustless_proxy_dev_key_material.rs").read_text()
manifest_helper = Path("trustless-proxy/src/bin/trustless_proxy_dev_encrypt_empty_manifest.rs").read_text()

required_script_tokens = [
    "TRUSTLESS_PROXY_REMOTE_GATEWAY_ACCESS_KEY_ID",
    "TRUSTLESS_PROXY_REMOTE_GATEWAY_SECRET_ACCESS_KEY",
    "TRUSTLESS_PROXY_KEYSTORE_PATH",
    "TRUSTLESS_PROXY_RECIPIENT_KEYS_PATH",
    "TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX",
    "cargo run -q -p trustless-proxy --bin trustless-proxy -- local-proxy",
    "cargo run -q -p trustless-proxy --bin trustless_proxy_dev_key_material",
    "cargo run -q -p trustless-proxy --bin trustless_proxy_dev_encrypt_empty_manifest",
    '"action":"put_encrypted_manifest"',
    "x-s3w-bucket-id",
    "x-s3w-policy-version",
    "x-s3w-local-account",
    "x-s3w-local-key-type",
    "x-s3w-recipients",
    "x-s3w-recipient-keys",
    "x-s3w-gateway-plaintext-access",
    "cmp -s",
    "live local proxy demo passed",
]

required_key_helper_tokens = [
    "AesGcmLocalPrivateKeyUnlocker",
    "seal_private_key_for_storage",
    "LocalKeystoreFile::write_records",
    "RecipientKeyFileDocument",
    "refuses to overwrite existing files",
    "genpkey",
    "rsa_keygen_bits:2048",
    "pkey",
    "-pubout",
    "local-private-key.pem",
    "local-public-key.pem",
]

required_manifest_helper_tokens = [
    "AwsEsdkTrustlessManifestCipher",
    "TrustlessManifestBoundary",
    "encrypt_manifest_locally",
    "TrustlessManifest",
    "RecipientEnvelopeContext",
    "LocalRecipientKeyFile::read_records",
]

for token in required_script_tokens:
    if token not in script:
        raise SystemExit(f"FAILED: live local proxy demo script missing token: {token}")

for token in required_key_helper_tokens:
    if token not in key_helper:
        raise SystemExit(f"FAILED: dev key material helper missing token: {token}")

for token in required_manifest_helper_tokens:
    if token not in manifest_helper:
        raise SystemExit(f"FAILED: empty manifest helper missing token: {token}")

for forbidden in [
    "gateway_plaintext_access=true",
    "x-s3w-gateway-plaintext-access: true",
    "x-s3w-object-key-id",
    "x-s3w-manifest-ciphertext-ref",
    "x-s3w-manifest-ciphertext-size",
    "x-s3w-manifest-content-type",
    "x-s3w-manifest-etag",
]:
    if forbidden in script:
        raise SystemExit(f"FAILED: forbidden plaintext gateway access token found: {forbidden}")

print("Trustless live local proxy demo surface guard passed.")
