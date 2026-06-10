#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

endpoint = ROOT / "gateway/src/routes/trustless_ciphertext_gateway.rs"
docs = ROOT / "docs/security/trustless-private-access-model.md"
workflow = ROOT / ".github/workflows/rust.yml"

errors = []


def require_file(path: Path) -> str:
    if not path.exists():
        errors.append(f"missing required file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text()


endpoint_text = require_file(endpoint)
docs_text = require_file(docs)
workflow_text = require_file(workflow)
production_endpoint_text = endpoint_text.split("#[cfg(test)]", 1)[0]


def require_tokens(label: str, text: str, tokens: list[str]) -> None:
    for token in tokens:
        if token not in text:
            errors.append(f"{label} missing token: {token}")


def forbid_tokens(label: str, text: str, tokens: list[str]) -> None:
    for token in tokens:
        if token in text:
            errors.append(f"{label} contains forbidden token: {token}")


require_tokens(
    "trustless ciphertext endpoint production code",
    production_endpoint_text,
    [
        "enforce_owner_only_trustless_auth(principal, &chain_bucket)?;",
        "fn enforce_owner_only_trustless_auth(",
        "chain_bucket.owner != principal.owner",
        "trustless remote gateway access is owner-only until bucket-scoped delegation is implemented",
    ],
)

require_tokens(
    "trustless ciphertext endpoint tests",
    endpoint_text,
    [
        "owner_only_trustless_auth_rejects_non_owner_delegate_shape",
        "owner_only_trustless_auth_allows_bucket_owner",
    ],
)

forbid_tokens(
    "trustless ciphertext endpoint production code",
    production_endpoint_text,
    [
        "is_delegate_authorized",
        "get_delegation",
        "encode_identity_is_delegate_authorized",
        "encode_identity_get_delegation",
        "OP_GET_OBJECT",
        "OP_PUT_OBJECT",
        "OP_DELETE_OBJECT",
        "OP_LIST_OBJECTS",
        "allowed_operations",
    ],
)

require_tokens(
    "trustless private access model docs",
    docs_text,
    [
        "The remote trustless gateway is owner-only in the current implementation.",
        "Current identity-contract delegation is owner-wide, not bucket-scoped.",
        "Do not wire owner-wide delegation into the trustless remote gateway path.",
    ],
)

if "check_trustless_owner_only_auth_surface.py" not in workflow_text:
    errors.append("rust workflow does not run check_trustless_owner_only_auth_surface.py")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

print("trustless owner-only auth surface OK")
