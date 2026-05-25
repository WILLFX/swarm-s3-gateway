#!/usr/bin/env python3
from pathlib import Path

put = Path("gateway/src/routes/put_object.rs").read_text()
delete = Path("gateway/src/routes/delete_object.rs").read_text()
put_test = Path("gateway/tests/private_put_behavior.rs").read_text()
delete_test = Path("gateway/tests/private_delete_behavior.rs").read_text()

required_put = [
    "ChainBucketType",
    "fetch_bucket_type",
    "ChainBucketType::TrustlessPrivate",
    "trustless private buckets cannot be written by the gateway",
    "ChainBucketType::TrustedGatewayPrivate",
]

required_delete = [
    "ChainBucketType",
    "fetch_bucket_type",
    "ChainBucketType::TrustlessPrivate",
    "trustless private buckets cannot be deleted by the gateway",
    "ChainBucketType::TrustedGatewayPrivate",
]

required_put_test = [
    "trustless_private_put_fails_before_gateway_payload_manifest_or_anchor_writes",
    "bucket_type: Some(ChainBucketType::TrustlessPrivate)",
    "trustless private PUT must fail before gateway writes encrypted payloads or manifests",
    "trustless private PUT must fail before gateway anchors object state",
]

required_delete_test = [
    "trustless_private_delete_fails_before_gateway_manifest_or_anchor_writes",
    "bucket_type: Some(ChainBucketType::TrustlessPrivate)",
    "trustless private DELETE must fail before gateway reads encrypted bucket manifests",
    "trustless private DELETE must fail before gateway writes replacement bucket manifests",
    "trustless private DELETE must fail before gateway anchors delete state",
]

for token in required_put:
    if token not in put:
        raise SystemExit(f"FAILED: missing trustless PUT fail-closed token: {token}")

for token in required_delete:
    if token not in delete:
        raise SystemExit(f"FAILED: missing trustless DELETE fail-closed token: {token}")

for token in required_put_test:
    if token not in put_test:
        raise SystemExit(f"FAILED: missing trustless PUT fail-closed test token: {token}")

for token in required_delete_test:
    if token not in delete_test:
        raise SystemExit(f"FAILED: missing trustless DELETE fail-closed test token: {token}")

print("Trustless private PUT/DELETE fail-closed guard passed.")
