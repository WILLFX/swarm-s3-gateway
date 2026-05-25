#!/usr/bin/env python3
from pathlib import Path

common = Path("contracts/common/src/lib.rs").read_text()
bucket = Path("contracts/s3_bucket_contract/src/lib.rs").read_text()

required_common = [
    "pub enum BucketType",
    "Public",
    "TrustedGatewayPrivate",
    "TrustlessPrivate",
]

required_bucket = [
    "bucket_type_map: Mapping<[u8; 32], BucketType>",
    "pub fn create_trustless_bucket_cas",
    "pub fn get_bucket_type",
    "bucket_type_from_legacy_privacy",
    "s3gw/v1/create_trustless_bucket",
    "verify_create_trustless_signature",
    "create_trustless_bucket_cas_records_trustless_type",
    "trustless_create_rejects_legacy_create_signature",
    "legacy_private_create_bucket_records_trusted_gateway_private_type",
    "delete_bucket_removes_bucket_type",
]

for token in required_common:
    if token not in common:
        raise SystemExit(f"FAILED: missing common bucket type token: {token}")

for token in required_bucket:
    if token not in bucket:
        raise SystemExit(f"FAILED: missing bucket contract type token: {token}")

print("Bucket type contract surface guard passed.")
