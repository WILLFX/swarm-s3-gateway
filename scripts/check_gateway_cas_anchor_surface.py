#!/usr/bin/env python3
from pathlib import Path

def fail(msg: str) -> None:
    raise SystemExit(f"FAILED: {msg}")

traits = Path("gateway/src/traits.rs").read_text()
anchor = Path("gateway/src/chain/anchor_client.rs").read_text()
put = Path("gateway/src/routes/put_object.rs").read_text()
delete = Path("gateway/src/routes/delete_object.rs").read_text()
abi = Path("gateway/src/contracts_abi.rs").read_text()

required = [
    (traits, "expected_bucket_manifest_root"),
    (anchor, "encode_bucket_update_bucket_manifest_root_for_put_cas"),
    (anchor, "encode_bucket_update_bucket_manifest_root_for_delete_cas"),
    (anchor, "bucket::update_bucket_manifest_root_for_put_cas"),
    (anchor, "bucket::update_bucket_manifest_root_for_delete_cas"),
    (abi, "BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_PUT_CAS_SELECTOR"),
    (abi, "BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_DELETE_CAS_SELECTOR"),
    (abi, "encode_bucket_update_bucket_manifest_root_for_put_cas"),
    (abi, "encode_bucket_update_bucket_manifest_root_for_delete_cas"),
    (put, "hex::encode(&chain_bucket.bucket_manifest_root)"),
    (delete, "hex::encode(&chain_bucket.bucket_manifest_root)"),
]

for text, token in required:
    if token not in text:
        fail(f"missing CAS token: {token}")

legacy_forbidden = [
    "encode_bucket_update_bucket_manifest_root_for_put(",
    "encode_bucket_update_bucket_manifest_root_for_delete(",
    '"bucket::update_bucket_manifest_root_for_put"',
    '"bucket::update_bucket_manifest_root_for_delete"',
]

for token in legacy_forbidden:
    if token in anchor:
        fail(f"anchor client still uses legacy non-CAS token: {token}")

print("Gateway CAS anchor surface guard passed.")
