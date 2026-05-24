#!/usr/bin/env python3
from pathlib import Path

doc_path = Path("docs/security/trustless-private-access-model.md")
if not doc_path.exists():
    raise SystemExit("FAILED: trustless private access model doc is missing")

doc_raw = doc_path.read_text()
doc = doc_raw.lower()

required = [
    "trustless private buckets are a new bucket type",
    "local s3-compatible proxy",
    "`aws-esdk`",
    "custom `aws-esdk` keyring",
    "identity contract",
    "public encryption key registry",
    "encrypted data-key envelopes",
    "the client's private encryption key lives client-side",
    "local proxy's local keystore",
    "the remote gateway never receives the client's private encryption key",
    "the project-specific logic lives in a custom keyring",
    "the upload path for a trustless private bucket",
    "the download path for a trustless private bucket",
    "local proxy mvp scope",
    "trusted-gateway private buckets and trustless private buckets are separate bucket types",
    "must not be able to derive or recover plaintext private data",
]

for token in required:
    if token not in doc:
        raise SystemExit(f"FAILED: missing trustless model token: {token}")

for forbidden in [
    "X25519",
    "ChaCha20-Poly1305",
    "MPC network is the first implementation",
    "hardware wallet is the first implementation",
]:
    if forbidden in doc_raw:
        raise SystemExit(
            f"FAILED: trustless model still contains unresolved/manual primitive token: {forbidden}"
        )

print("Trustless private access model guard passed.")
