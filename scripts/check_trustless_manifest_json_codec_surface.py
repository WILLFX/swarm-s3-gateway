#!/usr/bin/env python3
from pathlib import Path

codec = Path("trustless-proxy/src/manifest_codec.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessManifestJsonCodec",
    "TrustlessManifestJsonCodecError",
    "ManifestJsonDocument",
    "ManifestJsonEntry",
    "encode_manifest",
    "decode_manifest",
    "canonical_manifest",
    "serde_json::to_vec",
    "serde_json::from_slice",
    "s3w.trustless.manifest",
]

required_tests = [
    "manifest_json_codec_encodes_manifest_to_deterministic_bytes",
    "manifest_json_codec_decodes_manifest_from_json_bytes",
    "manifest_json_codec_round_trips_manifest_to_same_canonical_bytes",
    "manifest_json_codec_rejects_empty_json_input",
    "manifest_json_codec_rejects_unsupported_schema_version",
    "manifest_json_codec_rejects_duplicate_object_key_ids",
    "manifest_json_codec_rejects_missing_required_fields",
]

required_lib = [
    "pub mod manifest_codec",
    "TrustlessManifestJsonCodec",
    "TrustlessManifestJsonCodecError",
]

required_workflow = [
    "Check trustless manifest JSON codec surface",
    "./scripts/check_trustless_manifest_json_codec_surface.py",
]

for token in required_source:
    if token not in codec:
        raise SystemExit(f"FAILED: missing manifest JSON codec token: {token}")

for forbidden in [
    "gateway_plaintext_payload",
    "send_plaintext_to_gateway",
    "remote_plaintext_body",
    "plaintext_private_key",
]:
    if forbidden in codec:
        raise SystemExit(f"FAILED: forbidden manifest JSON codec token: {forbidden}")

for token in required_tests:
    if token not in codec:
        raise SystemExit(f"FAILED: missing manifest JSON codec test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing manifest JSON codec lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing manifest JSON codec workflow token: {token}")

print("Trustless manifest JSON codec surface guard passed.")
