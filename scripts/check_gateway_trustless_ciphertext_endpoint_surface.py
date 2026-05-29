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
    'encrypted_manifest_hex',
    'gateway_plaintext_access',
    'put_object_and_update_pointer',
    'get_pointer_bytes',
    'BeeClient::derive_topic',
    'gateway plaintext access is forbidden',
    'gateway_plaintext_access: false',
]

for token in required_endpoint_tokens:
    if token not in endpoint_text:
        errors.append(f"endpoint missing token: {token}")

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
