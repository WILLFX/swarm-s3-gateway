#!/usr/bin/env python3
from pathlib import Path

preflight = Path("trustless-proxy/src/preflight.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessPreflightRequest",
    "TrustlessPutPreflight",
    "TrustlessLocalDecryptPreflight",
    "TrustlessOperationPreflightBuilder",
    "PreflightError",
    "preflight_put_object",
    "preflight_get_object",
    "preflight_list_objects_v2",
    "preflight_delete_object",
    "RecipientEnvelopeBuilder",
    "LocalPrivateKeySelector",
    "ciphertext_only_remote",
    "gateway_plaintext_access",
]

required_tests = [
    "put_preflight_combines_route_plan_recipient_envelopes_and_local_key",
    "put_preflight_fails_closed_when_recipient_key_is_missing",
    "get_preflight_selects_local_key_and_keeps_gateway_ciphertext_only",
    "list_preflight_selects_local_key_for_manifest_decryption",
    "delete_preflight_selects_local_key_and_updates_manifest_locally",
    "preflight_fails_closed_when_local_private_key_is_missing",
    "preflight_rejects_missing_object_key_or_object_key_id",
]

required_lib = [
    "pub mod preflight",
    "TrustlessOperationPreflightBuilder",
    "TrustlessPreflightRequest",
]

required_workflow = [
    "Check trustless local proxy preflight surface",
    "./scripts/check_trustless_local_proxy_preflight_surface.py",
]

for token in required_source:
    if token not in preflight:
        raise SystemExit(f"FAILED: missing trustless preflight source token: {token}")

for token in required_tests:
    if token not in preflight:
        raise SystemExit(f"FAILED: missing trustless preflight test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless preflight lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless preflight workflow token: {token}")

print("Trustless local proxy preflight surface guard passed.")
