#!/usr/bin/env python3
from pathlib import Path

router = Path("trustless-proxy/src/router.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessLocalOperationRouter",
    "TrustlessLocalOperationRoute",
    "TrustlessExecutionStage",
    "TrustlessRouterError",
    "route_request",
    "route_intent",
    "ClassifyLocalS3Request",
    "BuildTrustlessRequestContext",
    "EncryptObjectLocally",
    "DecryptObjectLocally",
    "DecryptManifestLocally",
    "EncryptManifestLocally",
    "SendCiphertextOnlyGatewayRequest",
    "ReturnLocalPlaintext",
    "ReturnMetadataOnly",
    "CreateTrustlessBucketAnchor",
    "gateway_plaintext_access: false",
]

required_tests = [
    "put_route_keeps_plaintext_at_local_boundary_then_encrypts_and_forwards_ciphertext",
    "get_route_fetches_ciphertext_and_returns_plaintext_locally",
    "head_route_returns_metadata_only_without_local_decrypt_stage",
    "list_route_fetches_encrypted_manifest_and_lists_metadata_locally",
    "delete_route_updates_manifest_locally_and_forwards_ciphertext_only",
    "create_trustless_bucket_route_anchors_without_remote_plaintext",
    "router_rejects_plaintext_outside_put_via_local_surface",
]

required_lib = [
    "pub mod router",
    "TrustlessLocalOperationRouter",
    "TrustlessExecutionStage",
]

required_workflow = [
    "Check trustless local proxy operation router surface",
    "./scripts/check_trustless_local_proxy_operation_router_surface.py",
]

for token in required_source:
    if token not in router:
        raise SystemExit(f"FAILED: missing trustless operation router token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in router:
        raise SystemExit(f"FAILED: forbidden trustless operation router token: {forbidden}")

for token in required_tests:
    if token not in router:
        raise SystemExit(f"FAILED: missing trustless operation router test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless operation router lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless operation router workflow token: {token}")

print("Trustless local proxy operation router surface guard passed.")
