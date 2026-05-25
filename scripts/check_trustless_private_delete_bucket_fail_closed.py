#!/usr/bin/env python3
from pathlib import Path

route = Path("gateway/src/routes/delete_bucket.rs").read_text()
test = Path("gateway/tests/private_bucket_catalog_behavior.rs").read_text()

required_route = [
    "ChainBucketType",
    "fetch_bucket_type",
    "ChainBucketType::TrustlessPrivate",
    "trustless private buckets cannot be deleted by the gateway",
    "ChainBucketType::TrustedGatewayPrivate",
    "ensure_bucket_manifest_empty",
    "write_owner_catalog_without_bucket",
]

required_test = [
    "trustless_private_delete_bucket_fails_before_gateway_manifest_or_catalog_writes",
    "bucket_type: Some(ChainBucketType::TrustlessPrivate)",
    "trustless private bucket DELETE must fail before gateway reads encrypted bucket or owner catalog manifests",
    "trustless private bucket DELETE must fail before gateway writes owner catalog manifests",
    "trustless private bucket DELETE must fail before gateway anchors bucket deletion",
]

for token in required_route:
    if token not in route:
        raise SystemExit(f"FAILED: missing trustless delete-bucket fail-closed route token: {token}")

for token in required_test:
    if token not in test:
        raise SystemExit(f"FAILED: missing trustless delete-bucket fail-closed test token: {token}")

print("Trustless private delete-bucket fail-closed guard passed.")
