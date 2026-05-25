#!/usr/bin/env python3
from pathlib import Path

route = Path("gateway/src/routes/get_object.rs").read_text()
test = Path("gateway/tests/private_route_behavior.rs").read_text()

required_route = [
    "ChainBucketType",
    "fetch_bucket_type",
    "ChainBucketType::TrustlessPrivate",
    "trustless private buckets cannot be decrypted by the gateway",
    "ChainBucketType::TrustedGatewayPrivate",
]

required_test = [
    "trustless_private_get_fails_before_gateway_manifest_or_payload_reads",
    "bucket_type: Some(ChainBucketType::TrustlessPrivate)",
    "trustless private GET must fail before gateway reads encrypted manifests or payloads",
]

for token in required_route:
    if token not in route:
        raise SystemExit(f"FAILED: missing trustless GET fail-closed route token: {token}")

for token in required_test:
    if token not in test:
        raise SystemExit(f"FAILED: missing trustless GET fail-closed test token: {token}")

print("Trustless private GET fail-closed guard passed.")
