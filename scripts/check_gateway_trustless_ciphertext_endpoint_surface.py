#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

endpoint = ROOT / "gateway/src/routes/trustless_ciphertext_gateway.rs"
routes_mod = ROOT / "gateway/src/routes/mod.rs"
main_rs = ROOT / "gateway/src/main.rs"

errors = []

def require_file(path: Path):
    if not path.exists():
        errors.append(f"missing required file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text()

endpoint_text = require_file(endpoint)
routes_text = require_file(routes_mod)
main_text = require_file(main_rs)
production_endpoint_text = endpoint_text.split("#[cfg(test)]", 1)[0]

def require_tokens(label: str, text: str, tokens: list[str]):
    for token in tokens:
        if token not in text:
            errors.append(f"{label} missing token: {token}")

def forbid_tokens(label: str, text: str, tokens: list[str]):
    for token in tokens:
        if token in text:
            errors.append(f"{label} contains forbidden token: {token}")

def extract_match_arm(label: str, next_label: str) -> str:
    start_token = f"CiphertextGatewayAction::{label} => {{"
    end_token = f"CiphertextGatewayAction::{next_label} => {{"
    start = production_endpoint_text.find(start_token)
    if start == -1:
        errors.append(f"endpoint missing match arm: {label}")
        return ""
    end = production_endpoint_text.find(end_token, start + len(start_token))
    if end == -1:
        errors.append(f"endpoint missing following match arm after {label}: {next_label}")
        return ""
    return production_endpoint_text[start:end]

required_endpoint_tokens = [
    'const WIRE_VERSION: u32 = 1',
    'const TRUSTLESS_MANIFEST_KEY: &str = "__s3w_trustless_manifest"',
    'put_ciphertext_object',
    'get_ciphertext_object',
    'head_ciphertext_object',
    'list_ciphertext_manifest',
    'delete_ciphertext_object',
    'create_trustless_bucket',
    'ciphertext_hex',
    'ciphertext_reference_hex',
    'encrypted_manifest_hex',
    'encrypted_manifest_reference_hex',
    'expected_manifest_reference_hex',
    'gateway_plaintext_access',
    'put_object_and_update_pointer',
    'update_bucket_manifest_root_for_put_anchor',
    'update_bucket_manifest_root_for_delete_anchor',
    'gateway plaintext access is forbidden',
    'gateway_plaintext_access: false',
    'ciphertext_reference_hex is required',
    'read_reference_target_bytes',
]

require_tokens("endpoint", endpoint_text, required_endpoint_tokens)

get_arm_text = extract_match_arm("GetCiphertextObject", "HeadCiphertextObject")
head_arm_text = extract_match_arm("HeadCiphertextObject", "ListCiphertextManifest")

required_reference_only_tokens = [
    'reject_all_payloads(&request)',
    'reject_expected_manifest_reference(&request)',
    'decode_required_reference(',
    'request.ciphertext_reference_hex.as_deref()',
    '"ciphertext_reference_hex"',
    'let reference_hex = hex::encode(reference);',
]

require_tokens(
    "get_ciphertext_object arm",
    get_arm_text,
    required_reference_only_tokens
    + [
        'read_reference_target_bytes(',
        'ciphertext_reference_hex: Some(target.reference_hex)',
    ],
)
require_tokens(
    "head_ciphertext_object arm",
    head_arm_text,
    required_reference_only_tokens
    + [
        'get_bytes(&reference_hex)',
        'metadata_response(action)',
    ],
)

forbid_tokens(
    "get_ciphertext_object arm",
    get_arm_text,
    [
        'put_object_and_update_pointer',
        'get_pointer_bytes',
        'BeeClient::derive_topic',
        'TRUSTLESS_MANIFEST_KEY',
    ],
)
forbid_tokens(
    "head_ciphertext_object arm",
    head_arm_text,
    [
        'put_object_and_update_pointer',
        'get_pointer_bytes',
        'BeeClient::derive_topic',
        'TRUSTLESS_MANIFEST_KEY',
    ],
)

if "pub mod trustless_ciphertext_gateway;" not in routes_text:
    errors.append("routes/mod.rs does not export trustless_ciphertext_gateway")

if '"/trustless/v1/ciphertext-gateway"' not in main_text:
    errors.append("main.rs does not wire /trustless/v1/ciphertext-gateway")

if "post(routes::trustless_ciphertext_gateway::handle)" not in main_text:
    errors.append("main.rs does not route POST to trustless ciphertext handler")

for forbidden in [
    "plaintext_payload",
    "plaintext_object",
    "plaintext_manifest",
    "data_key",
    "private_key",
    "raw_private_key",
    "private_key_material",
]:
    if forbidden in endpoint_text:
        errors.append(f"endpoint contains forbidden trustless remote field/token: {forbidden}")

if "gateway_plaintext_access: true" in endpoint_text:
    errors.append("endpoint must never set gateway_plaintext_access true")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

print("gateway trustless ciphertext endpoint surface OK")
