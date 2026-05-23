#!/usr/bin/env python3
from pathlib import Path

def fail(msg: str) -> None:
    raise SystemExit(f"FAILED: {msg}")

traits = Path("gateway/src/traits.rs").read_text()
anchor = Path("gateway/src/chain/anchor_client.rs").read_text()
create_route = Path("gateway/src/routes/create_bucket.rs").read_text()
delete_route = Path("gateway/src/routes/delete_bucket.rs").read_text()
abi = Path("gateway/src/contracts_abi.rs").read_text()
tests = Path("gateway/tests/private_bucket_catalog_behavior.rs").read_text()

required = [
    (traits, "expected_owner_catalog_root"),
    (anchor, "encode_bucket_create_bucket_cas"),
    (anchor, "encode_bucket_delete_bucket_cas"),
    (anchor, "bucket::create_bucket_cas"),
    (anchor, "bucket::delete_bucket_cas"),
    (abi, "BUCKET_CREATE_BUCKET_CAS_SELECTOR"),
    (abi, "BUCKET_DELETE_BUCKET_CAS_SELECTOR"),
    (abi, "encode_bucket_create_bucket_cas"),
    (abi, "encode_bucket_delete_bucket_cas"),
    (create_route, "expected_owner_catalog_root"),
    (delete_route, "expected_owner_catalog_root"),
    (tests, "private bucket create must CAS against the owner catalog root it read"),
    (tests, "private bucket delete must CAS against the owner catalog root it read"),
]

for text, token in required:
    if token not in text:
        fail(f"missing owner-catalog CAS token: {token}")

legacy_forbidden = [
    "encode_bucket_create_bucket(",
    "encode_bucket_delete_bucket(",
    '"bucket::create_bucket"',
    '"bucket::delete_bucket"',
]

for token in legacy_forbidden:
    if token in anchor:
        fail(f"anchor client still uses legacy non-CAS owner-catalog token: {token}")

print("Gateway owner catalog CAS surface guard passed.")
