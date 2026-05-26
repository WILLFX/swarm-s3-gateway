#!/usr/bin/env python3
from pathlib import Path

surface = Path("trustless-proxy/src/s3_surface.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalS3Operation",
    "LocalS3Request",
    "LocalS3Response",
    "LocalS3RouteIntent",
    "LocalS3Surface",
    "LocalS3SurfaceError",
    "PutObject",
    "GetObject",
    "HeadObject",
    "ListObjectsV2",
    "DeleteObject",
    "CreateTrustlessBucket",
    "plaintext_body_allowed_locally",
    "gateway_plaintext_access: false",
    "classify_request",
    "local_plaintext_response",
    "metadata_only_response",
]

required_tests = [
    "put_request_accepts_plaintext_only_at_local_boundary",
    "get_head_delete_requests_reject_plaintext_bodies",
    "list_request_uses_prefix_without_plaintext_body",
    "create_trustless_bucket_has_no_object_key_or_plaintext_body",
    "surface_rejects_missing_bucket_key_or_put_body",
    "get_response_returns_plaintext_locally_only",
    "metadata_response_never_contains_plaintext_body",
    "surface_rejects_gateway_plaintext_response_flag",
]

required_lib = [
    "pub mod s3_surface",
    "LocalS3Surface",
    "LocalS3Operation",
]

required_workflow = [
    "Check trustless local proxy S3 surface",
    "./scripts/check_trustless_local_proxy_s3_surface.py",
]

for token in required_source:
    if token not in surface:
        raise SystemExit(f"FAILED: missing trustless S3 surface token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in surface:
        raise SystemExit(f"FAILED: forbidden trustless S3 surface token: {forbidden}")

for token in required_tests:
    if token not in surface:
        raise SystemExit(f"FAILED: missing trustless S3 surface test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless S3 surface lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless S3 surface workflow token: {token}")

print("Trustless local proxy S3 surface guard passed.")
