#!/usr/bin/env python3
from pathlib import Path

abi = Path("gateway/src/contracts_abi.rs").read_text()
traits = Path("gateway/src/traits.rs").read_text()
anchor = Path("gateway/src/chain/anchor_client.rs").read_text()
signer = Path("gateway/src/bin/sign_bucket_op.rs").read_text()

required_abi = [
    "BUCKET_CREATE_TRUSTLESS_BUCKET_CAS_SELECTOR",
    "[0x0e, 0xe0, 0x6e, 0x35]",
    "encode_bucket_create_trustless_bucket_cas",
    "encode_bucket_create_trustless_bucket_cas_uses_metadata_selector",
]

required_trait = [
    "create_trustless_bucket_anchor",
]

required_anchor = [
    "encode_bucket_create_trustless_bucket_cas",
    "bucket::create_trustless_bucket_cas",
    "async fn create_trustless_bucket_anchor",
]

required_signer = [
    "create-trustless",
    "s3gw/v1/create_trustless_bucket",
    "bucket_type=trustless-private",
]

for token in required_abi:
    if token not in abi:
        raise SystemExit(f"FAILED: missing trustless bucket create ABI token: {token}")

for token in required_trait:
    if token not in traits:
        raise SystemExit(f"FAILED: missing trustless bucket create trait token: {token}")

for token in required_anchor:
    if token not in anchor:
        raise SystemExit(f"FAILED: missing trustless bucket create anchor token: {token}")

for token in required_signer:
    if token not in signer:
        raise SystemExit(f"FAILED: missing trustless bucket create signer token: {token}")

print("Gateway trustless bucket create surface guard passed.")
