#!/usr/bin/env python3
from pathlib import Path

common = Path("common/src/types.rs").read_text()
abi = Path("gateway/src/contracts_abi.rs").read_text()
registry = Path("gateway/src/chain/registry.rs").read_text()

required_common = [
    "pub enum ChainBucketType",
    "Public",
    "TrustedGatewayPrivate",
    "TrustlessPrivate",
]

required_abi = [
    "pub enum BucketType",
    "BUCKET_GET_BUCKET_TYPE_SELECTOR",
    "[0x82, 0xc3, 0xd9, 0x39]",
    "pub fn encode_bucket_get_bucket_type",
    "encode_bucket_get_bucket_type_uses_metadata_selector",
    "bucket_type_scale_discriminants_match_contract",
]

required_registry = [
    "ChainBucketType",
    "ContractBucketType",
    "encode_bucket_get_bucket_type",
    "pub async fn get_bucket_type",
    "bucket::get_bucket_type",
    "chain_bucket_type_from_contract",
]

for token in required_common:
    if token not in common:
        raise SystemExit(f"FAILED: missing common gateway bucket type token: {token}")

for token in required_abi:
    if token not in abi:
        raise SystemExit(f"FAILED: missing ABI gateway bucket type token: {token}")

for token in required_registry:
    if token not in registry:
        raise SystemExit(f"FAILED: missing registry gateway bucket type token: {token}")

print("Gateway bucket type surface guard passed.")
