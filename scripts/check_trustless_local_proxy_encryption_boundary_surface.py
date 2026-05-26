#!/usr/bin/env python3
from pathlib import Path

encryption = Path("trustless-proxy/src/encryption.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessEncryptionBoundary",
    "TrustlessEncryptRequest",
    "TrustlessEncryptResult",
    "TrustlessDecryptRequest",
    "TrustlessDecryptResult",
    "TrustlessEncryptionError",
    "encrypt_for_put",
    "decrypt_locally",
    "TrustlessRecipientKeyring",
    "RecipientEnvelopeContext",
    "remote_payload_is_ciphertext_only",
    "gateway_plaintext_access",
    "RouteAllowsNonCiphertextRemotePayload",
    "RouteAllowsGatewayPlaintextAccess",
]

required_tests = [
    "encrypt_for_put_returns_ciphertext_only_remote_payload",
    "decrypt_locally_returns_plaintext_without_gateway_plaintext_access",
    "encryption_rejects_empty_plaintext_or_ciphertext",
    "encryption_rejects_route_that_is_not_ciphertext_only",
    "encryption_rejects_route_that_allows_gateway_plaintext_access",
]

required_lib = [
    "pub mod encryption",
    "TrustlessEncryptionBoundary",
    "TrustlessEncryptRequest",
    "TrustlessDecryptRequest",
]

required_workflow = [
    "Check trustless local proxy encryption boundary surface",
    "./scripts/check_trustless_local_proxy_encryption_boundary_surface.py",
]

for token in required_source:
    if token not in encryption:
        raise SystemExit(f"FAILED: missing trustless encryption boundary source token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_decrypt",
    "plaintext_remote_payload",
]:
    if forbidden in encryption:
        raise SystemExit(f"FAILED: trustless encryption boundary must not expose token: {forbidden}")

for token in required_tests:
    if token not in encryption:
        raise SystemExit(f"FAILED: missing trustless encryption boundary test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless encryption boundary lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless encryption boundary workflow token: {token}")

print("Trustless local proxy encryption boundary surface guard passed.")
