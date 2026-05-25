#!/usr/bin/env python3
from pathlib import Path

head = Path("gateway/src/routes/head_object.rs").read_text()
listing = Path("gateway/src/routes/list_objects_v2.rs").read_text()
test = Path("gateway/tests/private_route_behavior.rs").read_text()

required_head = [
    "ChainBucketType",
    "fetch_bucket_type",
    "ChainBucketType::TrustlessPrivate",
    "trustless private buckets cannot be decrypted by the gateway",
    "ChainBucketType::TrustedGatewayPrivate",
]

required_list = [
    "ChainBucketType",
    "fetch_bucket_type",
    "ChainBucketType::TrustlessPrivate",
    "trustless private buckets cannot be listed by the gateway",
    "ChainBucketType::TrustedGatewayPrivate",
]

required_test = [
    "trustless_private_head_fails_before_gateway_manifest_or_payload_reads",
    "trustless private HEAD must fail before gateway reads encrypted manifests or payloads",
    "trustless_private_list_fails_before_gateway_manifest_reads",
    "trustless private LIST must fail before gateway reads encrypted bucket manifests",
    "bucket_type: Some(ChainBucketType::TrustlessPrivate)",
]

for token in required_head:
    if token not in head:
        raise SystemExit(f"FAILED: missing trustless HEAD fail-closed token: {token}")

for token in required_list:
    if token not in listing:
        raise SystemExit(f"FAILED: missing trustless LIST fail-closed token: {token}")

for token in required_test:
    if token not in test:
        raise SystemExit(f"FAILED: missing trustless HEAD/LIST fail-closed test token: {token}")

print("Trustless private HEAD/LIST fail-closed guard passed.")
