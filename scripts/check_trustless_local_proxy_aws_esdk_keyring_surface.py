#!/usr/bin/env python3
from pathlib import Path

aws_esdk = Path("trustless-proxy/src/aws_esdk.rs").read_text()
keyring = Path("trustless-proxy/src/keyring.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "AwsEsdkTrustlessRecipientKeyring",
    "AwsEsdkKeyringConfig",
    "AwsEsdkRecipientEnvelopeDescriptor",
    "AwsEsdkRecipientEnvelopePlan",
    "recipient_envelope_plan",
    "uses_official_aws_encryption_sdk: true",
    "manual_algorithm_selection: false",
    "TrustlessRecipientKeyring",
    "AwsEsdkAdapterNotWired",
    "require-encrypt-require-decrypt",
]

required_keyring = [
    "AwsEsdkAdapterNotWired",
    "MissingPlaintextPayload",
    "MissingCiphertextPayload",
    "MissingRecipientEnvelopes",
    "DisabledRecipientEnvelope",
    "EmptyRecipientPublicKey",
    "EmptyRecipientKeyType",
]

required_tests = [
    "aws_esdk_keyring_builds_recipient_envelope_plan_from_context",
    "aws_esdk_keyring_rejects_empty_context_fields",
    "aws_esdk_keyring_rejects_missing_or_disabled_recipients",
    "aws_esdk_keyring_rejects_malformed_recipient_records",
    "aws_esdk_keyring_fails_closed_until_sdk_wiring_exists",
    "aws_esdk_keyring_rejects_empty_payloads_before_sdk_wiring",
]

required_lib = [
    "pub mod aws_esdk",
    "AwsEsdkTrustlessRecipientKeyring",
    "AwsEsdkRecipientEnvelopePlan",
]

required_workflow = [
    "Check trustless local proxy AWS ESDK keyring surface",
    "./scripts/check_trustless_local_proxy_aws_esdk_keyring_surface.py",
]

for token in required_source:
    if token not in aws_esdk:
        raise SystemExit(f"FAILED: missing AWS ESDK keyring source token: {token}")

for forbidden in [
    "X25519",
    "ChaCha20",
    "ChaCha20Poly1305",
    "AES-GCM",
    "AesGcm",
    "RSA-OAEP",
    "manual primitive",
]:
    if forbidden in aws_esdk or forbidden in keyring:
        raise SystemExit(f"FAILED: forbidden manual primitive token in AWS ESDK boundary: {forbidden}")

for token in required_keyring:
    if token not in keyring:
        raise SystemExit(f"FAILED: missing keyring error token: {token}")

for token in required_tests:
    if token not in aws_esdk:
        raise SystemExit(f"FAILED: missing AWS ESDK keyring test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing AWS ESDK keyring lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing AWS ESDK keyring workflow token: {token}")

print("Trustless local proxy AWS ESDK keyring surface guard passed.")
