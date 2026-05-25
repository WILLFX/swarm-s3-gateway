#!/usr/bin/env python3
from pathlib import Path

recipient_keys = Path("trustless-proxy/src/recipient_keys.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "RecipientKeyRequest",
    "RecipientKeyRecord",
    "RecipientKeyResolver",
    "RecipientEnvelopeBuilder",
    "RecipientKeyError",
    "MissingEnabledRecipientKey",
    "EmptyRecipientPublicKey",
    "EmptyRecipientKeyType",
    "RecipientEnvelopeContext",
    "normalize_recipients",
    "BTreeSet",
]

required_tests = [
    "builder_creates_envelope_context_for_enabled_recipient_keys",
    "builder_deduplicates_and_sorts_recipients",
    "builder_fails_closed_when_recipient_key_is_missing",
    "builder_fails_closed_when_recipient_key_is_disabled",
    "builder_rejects_empty_public_key_or_key_type",
    "builder_rejects_missing_bucket_object_or_recipients",
]

required_lib = [
    "pub mod recipient_keys",
    "RecipientEnvelopeBuilder",
    "RecipientKeyResolver",
]

required_workflow = [
    "Check trustless local proxy recipient keys surface",
    "./scripts/check_trustless_local_proxy_recipient_keys_surface.py",
]

for token in required_source:
    if token not in recipient_keys:
        raise SystemExit(f"FAILED: missing trustless recipient key source token: {token}")

for token in required_tests:
    if token not in recipient_keys:
        raise SystemExit(f"FAILED: missing trustless recipient key test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless recipient key lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless recipient key workflow token: {token}")

print("Trustless local proxy recipient keys surface guard passed.")
