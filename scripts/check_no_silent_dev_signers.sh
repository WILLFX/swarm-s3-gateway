#!/usr/bin/env bash
set -euo pipefail

echo "Checking for silent development signer fallbacks..."

if grep -RIn --include="*.rs" "dev::alice" gateway/src contracts 2>/dev/null; then
  echo "FAILED: dev::alice must not be used in gateway/operator code. Use explicit signer env vars instead." >&2
  exit 1
fi

if grep -RIn --include="*.rs" "unwrap_or_else(|_| \"//Alice\"" gateway/src contracts 2>/dev/null; then
  echo "FAILED: silent //Alice fallback detected. Gate local dev defaults behind S3GW_ENABLE_DEV_DEFAULTS." >&2
  exit 1
fi

if grep -RIn --include="*.rs" "OWNER_SURI" gateway/src contracts 2>/dev/null; then
  echo "FAILED: legacy OWNER_SURI detected. Use S3GW_BUCKET_OWNER_SIGNER_SURI." >&2
  exit 1
fi

echo "No silent development signer fallbacks found."
