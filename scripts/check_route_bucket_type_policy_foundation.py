#!/usr/bin/env python3
from pathlib import Path

traits = Path("gateway/src/traits.rs").read_text()
registry = Path("gateway/src/chain/registry.rs").read_text()

required_traits = [
    "ChainBucketType",
    "async fn fetch_bucket_type",
]

required_registry = [
    "async fn fetch_bucket_type",
    "self.get_bucket_type(bucket_name_hash).await",
]

for token in required_traits:
    if token not in traits:
        raise SystemExit(f"FAILED: missing route bucket-type trait token: {token}")

for token in required_registry:
    if token not in registry:
        raise SystemExit(f"FAILED: missing route bucket-type registry token: {token}")

print("Route bucket type policy foundation guard passed.")
