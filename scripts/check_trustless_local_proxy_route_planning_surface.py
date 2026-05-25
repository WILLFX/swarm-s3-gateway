#!/usr/bin/env python3
from pathlib import Path

planner = Path("trustless-proxy/src/planner.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_planner = [
    "TrustlessRoutePlanner",
    "TrustlessRoutePlan",
    "TrustlessProxyOperation",
    "LocalTrustlessStep",
    "RemoteGatewayAction",
    "plan_put_object",
    "plan_get_object",
    "plan_head_object",
    "plan_list_objects_v2",
    "plan_delete_object",
    "EncryptPayloadLocally",
    "DecryptPayloadLocally",
    "ReadEncryptedBucketManifest",
    "DecryptBucketManifestLocally",
    "UpdateBucketManifestLocally",
    "EncryptBucketManifestLocally",
    "ValidateCiphertextOnlyForwarding",
    "ciphertext_only_remote: true",
    "gateway_plaintext_access: false",
]

required_tests = [
    "put_plan_encrypts_locally_and_forwards_ciphertext_only",
    "get_plan_fetches_ciphertext_and_decrypts_locally",
    "head_plan_returns_metadata_without_local_decrypt_step",
    "list_plan_decrypts_encrypted_manifest_locally",
    "delete_plan_updates_manifest_locally_and_forwards_ciphertext_only",
    "planner_rejects_empty_bucket_or_key",
]

required_lib = [
    "pub mod planner",
    "TrustlessRoutePlanner",
    "TrustlessRoutePlan",
]

required_workflow = [
    "Check trustless local proxy route planning surface",
    "./scripts/check_trustless_local_proxy_route_planning_surface.py",
]

for token in required_planner:
    if token not in planner:
        raise SystemExit(f"FAILED: missing trustless proxy planner token: {token}")

for token in required_tests:
    if token not in planner:
        raise SystemExit(f"FAILED: missing trustless proxy planner test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless proxy planner lib export token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless proxy route planning workflow token: {token}")

print("Trustless local proxy route planning surface guard passed.")
