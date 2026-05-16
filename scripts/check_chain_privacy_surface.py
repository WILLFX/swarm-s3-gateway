#!/usr/bin/env python3
from pathlib import Path
import re

CONTRACT_PATHS = [
    Path("contracts/s3_bucket_contract"),
    Path("contracts/common"),
]

FORBIDDEN_CONTRACT_TOKENS = [
    "object_key",
    "content_type",
    "last_modified",
    "encrypted_swarm_reference",
    "swarm_reference",
]

REQUIRED_CONTRACT_TOKENS = [
    "bucket_name_hash",
    "bucket_manifest_root",
    "owner_catalog_root",
    "is_private",
    "encryption_version",
]

def fail(message: str) -> None:
    raise SystemExit(f"FAILED: {message}")

contract_text = ""
for root in CONTRACT_PATHS:
    for path in root.rglob("*.rs"):
        contract_text += f"\n// FILE: {path}\n"
        contract_text += path.read_text()

for token in FORBIDDEN_CONTRACT_TOKENS:
    if token in contract_text:
        fail(f"contract surface contains private metadata token: {token}")

for token in REQUIRED_CONTRACT_TOKENS:
    if token not in contract_text:
        fail(f"contract surface missing expected root/hash token: {token}")

manifest = Path("gateway/src/manifest.rs").read_text()

def require_function_contains(fn_name: str, required_tokens: list[str]) -> None:
    pattern = rf"pub async fn {fn_name}\b.*?\n}}\n"
    match = re.search(pattern, manifest, flags=re.S)
    if not match:
        fail(f"function not found: {fn_name}")

    body = match.group(0)
    for token in required_tokens:
        if token not in body:
            fail(f"{fn_name} missing token: {token}")

require_function_contains("write_owner_catalog_manifest", [
    "serde_json::to_vec",
    "derive_owner_catalog_encryption_key",
    "encrypt_blob_random",
    "put_bytes",
])

require_function_contains("write_private_bucket_manifest_v2", [
    "serde_json::to_vec",
    "derive_private_bucket_manifest_key",
    "encrypt_blob_random",
    "put_bytes",
])

require_function_contains("read_private_bucket_manifest_v2", [
    "get_bytes",
    "derive_private_bucket_manifest_key",
    "decrypt_blob",
    "serde_json::from_slice",
])

require_function_contains("write_private_object_manifest_v2", [
    "serde_json::to_vec",
    "derive_private_object_manifest_key",
    "encrypt_blob_random",
    "put_bytes",
])

require_function_contains("read_private_object_manifest_v2", [
    "get_bytes",
    "derive_private_object_manifest_key",
    "decrypt_blob",
    "serde_json::from_slice",
])

anchor = Path("gateway/src/chain/anchor_client.rs").read_text()

for token in [
    "_object_key_id: [u8; 32]",
    "_swarm_ref: String",
    "_size: u64",
    "_etag: [u8; 32]",
    "decode_swarm_reference(&bucket_manifest_root)",
]:
    if token not in anchor:
        fail(f"anchor client missing expected privacy-preserving token: {token}")

crypto = Path("gateway/src/crypto.rs").read_text()
bucket_hash_match = re.search(
    r"pub fn bucket_name_hash\b.*?\n}\n",
    crypto,
    flags=re.S,
)
if not bucket_hash_match:
    fail("bucket_name_hash function not found")

bucket_hash_body = bucket_hash_match.group(0)
for token in ["hasher.update(owner)", "to_ascii_lowercase", "hasher.update(normalized.as_bytes())"]:
    if token not in bucket_hash_body:
        fail(f"bucket_name_hash no longer appears owner-scoped/lowercase-normalized: {token}")

print("Chain privacy surface guard passed.")
