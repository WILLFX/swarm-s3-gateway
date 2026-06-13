#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

errors = []


def read(path: str) -> str:
    full = ROOT / path
    if not full.exists():
        errors.append(f"missing required file: {path}")
        return ""
    return full.read_text()


boundary = read("trustless-proxy/src/gateway_boundary.rs")
remote_http = read("trustless-proxy/src/remote_gateway_http.rs")
endpoint = read("gateway/src/routes/trustless_ciphertext_gateway.rs")
create_bucket = read("gateway/src/routes/create_bucket.rs")
access_model = read("docs/security/trustless-private-access-model.md")
chain_privacy = read("docs/security/chain-privacy-surface.md")
workflow = read(".github/workflows/rust.yml")

endpoint_production = endpoint.split("#[cfg(test)]", 1)[0]
create_production = create_bucket.split("#[cfg(test)]", 1)[0]


def require(label: str, text: str, tokens: list[str]) -> None:
    for token in tokens:
        if token not in text:
            errors.append(f"{label} missing token: {token}")


def forbid(label: str, text: str, tokens: list[str]) -> None:
    for token in tokens:
        if token in text:
            errors.append(f"{label} contains forbidden token: {token}")


def struct_body(label: str, text: str, name: str) -> str:
    found = re.search(rf"struct\s+{name}\s*\{{(?P<body>.*?)\n\}}", text, re.S)
    if not found:
        errors.append(f"{label} missing struct: {name}")
        return ""
    return found.group("body")


boundary_request = struct_body(
    "local proxy ciphertext boundary", boundary, "CiphertextGatewayRequest"
)
http_envelope = struct_body(
    "remote HTTP client", remote_http, "RemoteGatewayHttpRequestEnvelope"
)
endpoint_request = struct_body(
    "gateway ciphertext endpoint", endpoint_production, "CiphertextGatewayRequest"
)

for label, body in [
    ("local proxy ciphertext boundary request", boundary_request),
    ("remote HTTP envelope", http_envelope),
    ("gateway ciphertext endpoint request", endpoint_request),
]:
    require(label, body, ["bucket_id_hex"])
    forbid(
        label,
        body,
        [
            "bucket:",
            "object_key",
            "objectKey",
            "object_key_id",
            "objectKeyId",
            "caller_object_id",
            "callerSuppliedObjectId",
            "key:",
        ],
    )

require(
    "gateway ciphertext endpoint production",
    endpoint_production,
    [
        "#[serde(deny_unknown_fields)]",
        "decode_bucket_id_hex",
        ".fetch_bucket(bucket_id)",
        "authorize_trustless_bucket(&state, &principal, &request.bucket_id_hex)",
    ],
)
forbid(
    "gateway ciphertext endpoint production",
    endpoint_production,
    ["bucket_name_hash", "bucket: String"],
)
if re.search(r"\brequest\.bucket\b(?!_id_hex)", endpoint_production):
    errors.append("gateway ciphertext endpoint production must not read plaintext request.bucket")

require(
    "trustless bucket create route production",
    create_production,
    [
        'const TRUSTLESS_BUCKET_ID_HEADER: &str = "x-s3w-bucket-id";',
        "CreateBucketMode::Legacy { .. } => Ok(bucket_name_hash(owner, bucket))",
        "CreateBucketMode::TrustlessPrivate => parse_trustless_bucket_id_header(headers)",
        "parse_trustless_bucket_id_header",
        "must decode to exactly 32 bytes",
    ],
)

require(
    "trustless private access model docs",
    access_model,
    [
        "Remote trustless ciphertext requests carry `bucket_id_hex`, not plaintext bucket names.",
        "Legacy remote JSON fields such as `bucket`, `key`, and `object_key_id` are rejected.",
        "Trustless bucket IDs must be random or secret-salted opaque 32-byte identifiers.",
    ],
)
require(
    "chain privacy surface docs",
    chain_privacy,
    [
        "Trustless bucket-name privacy depends on opaque bucket IDs.",
        "`x-s3w-bucket-id`",
        "A deterministic low-entropy hash of owner plus bucket name is dictionary-guessable.",
    ],
)

if "check_trustless_bucket_id_privacy_surface.py" not in workflow:
    errors.append("rust workflow does not run check_trustless_bucket_id_privacy_surface.py")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

print("Trustless bucket id privacy surface guard passed.")
