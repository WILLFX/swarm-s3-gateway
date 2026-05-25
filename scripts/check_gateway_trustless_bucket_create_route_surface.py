#!/usr/bin/env python3
from pathlib import Path

route = Path("gateway/src/routes/create_bucket.rs").read_text()
test = Path("gateway/tests/private_bucket_catalog_behavior.rs").read_text()

required_route = [
    "x-s3gw-bucket-type",
    "x-s3gw-expected-owner-catalog-root",
    "x-s3gw-owner-catalog-root",
    "CreateBucketMode::TrustlessPrivate",
    "parse_trustless_owner_catalog_roots",
    "create_trustless_bucket_anchor",
    "write_owner_catalog_with_bucket",
]

required_test = [
    "trustless_create_bucket_uses_client_supplied_catalog_roots_without_bee_writes",
    "trustless_create_headers",
    "trustless_create_call",
    "create_trustless_bucket_anchor",
    "trustless create must not read/decrypt an owner catalog through the gateway",
    "trustless create must not write/encrypt an owner catalog through the gateway",
]

for token in required_route:
    if token not in route:
        raise SystemExit(f"FAILED: missing trustless bucket create route token: {token}")

for token in required_test:
    if token not in test:
        raise SystemExit(f"FAILED: missing trustless bucket create route test token: {token}")

print("Gateway trustless bucket create route surface guard passed.")
