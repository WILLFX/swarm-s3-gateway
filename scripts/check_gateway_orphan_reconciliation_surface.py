#!/usr/bin/env python3
from pathlib import Path

root = Path(".")
module = (root / "gateway/src/orphan_reconciliation.rs").read_text()
worker = (root / "gateway/src/bin/reconcile_orphans.rs").read_text()
bee = (root / "gateway/src/bee/client.rs").read_text()
app_state = (root / "gateway/src/app_state.rs").read_text()
workflow = (root / ".github/workflows/rust.yml").read_text()
docs = (root / "docs/private-lifecycle-operator-guide.md").read_text()

required = {
    "journal env": (module, "S3GW_BEE_WRITE_JOURNAL_PATH"),
    "journal wrapper": (app_state, "JournaledBeeStorage::new"),
    "pinned uploads": (bee, '"Swarm-Pin", "true"'),
    "pin list API": (bee, "pub async fn list_pins"),
    "pin status API": (bee, "pub async fn is_pinned"),
    "unpin API": (bee, "pub async fn unpin_reference"),
    "dry-run apply flag": (worker, '"--apply"'),
    "journal load": (worker, "GatewayWriteJournal::load_records"),
    "per-bucket chain verification": (worker, ".get_bucket(bucket_id)"),
    "unpin gated by policy": (worker, "apply && auto_unpin_allowed && pinned"),
    "trustless ciphertext report-only kind": (module, "TrustlessCiphertextPayload"),
    "trustless decrypt refusal": (module, "gateway cannot decrypt trustless manifests"),
    "report status enum": (module, "ReconciliationReportStatus"),
    "manifest holder proof status": (module, "ManifestHolderProofRequired"),
    "manifest holder proof requirement": (module, "ManifestHolderReachabilityProof"),
    "worker report status output": (worker, "report_status"),
    "worker proof output": (worker, "proof_required"),
    "pending report-only policy": (module, "anchor result is pending"),
    "anchor attempt candidates": (module, "collect_anchor_attempt_candidates"),
    "docs journal env": (docs, "S3GW_BEE_WRITE_JOURNAL_PATH"),
    "docs explicit apply": (docs, "--apply"),
    "docs manifest-holder status": (docs, "report_status=manifest_holder_proof_required"),
    "workflow guard": (workflow, "check_gateway_orphan_reconciliation_surface.py"),
}

for label, (content, token) in required.items():
    if token not in content:
        raise SystemExit(f"FAILED: missing {label}: {token}")

for forbidden in [
    "list_bucket_ids",
    "list_buckets_by_owner",
    "get_bucket_count",
    "get_owner_bucket_count",
]:
    if forbidden in module or forbidden in worker:
        raise SystemExit(f"FAILED: orphan reconciliation must not depend on {forbidden}")

print("Gateway orphan reconciliation surface guard passed.")
