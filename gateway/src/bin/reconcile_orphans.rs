use anyhow::{anyhow, bail, Context, Result};
use gateway::{
    bee::client::BeeClient,
    chain::registry::ChainRegistryClient,
    manifest::{
        read_private_bucket_manifest_v2, read_private_object_manifest_v2, BucketManifest,
        ObjectManifest,
    },
    orphan_reconciliation::{
        collect_anchor_attempt_candidates, GatewayBeeReferenceKind, GatewayWriteJournal,
        JournalBucketType, ReconciliationCandidateSeed, ReconciliationProofRequirement,
        ReconciliationReportStatus,
    },
};
use serde::Serialize;
use std::{collections::HashSet, env, path::PathBuf};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse(env::args().skip(1))?;
    let records = GatewayWriteJournal::load_records(&args.journal)?;
    let candidates = collect_anchor_attempt_candidates(&records);

    let bee_api_url = required_env("S3GW_BEE_API_URL")?;
    let bee = BeeClient::from_env(&bee_api_url)
        .with_context(|| format!("failed to build Bee client for {bee_api_url}"))?;

    let rpc_url = required_env("S3GW_CHAIN_RPC_URL")?;
    let registry = ChainRegistryClient::connect(&rpc_url)
        .await
        .with_context(|| format!("failed to connect to chain RPC at {rpc_url}"))?;

    let master_key = load_optional_master_service_key()?;
    let mut report = ReconciliationReport {
        apply: args.apply,
        journal: args.journal.display().to_string(),
        candidates: Vec::new(),
    };

    for candidate in candidates {
        let row =
            evaluate_candidate(&bee, &registry, master_key.as_ref(), candidate, args.apply).await?;
        report.candidates.push(row);
    }

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Debug)]
struct Args {
    journal: PathBuf,
    apply: bool,
}

impl Args {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let mut journal = None;
        let mut apply = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--journal" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow!("--journal requires a path"))?;
                    journal = Some(PathBuf::from(value));
                }
                "--apply" => apply = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => bail!("unsupported argument: {arg}"),
            }
        }

        let journal = journal.ok_or_else(|| anyhow!("missing required --journal path"))?;
        Ok(Self { journal, apply })
    }
}

fn print_help() {
    println!(
        "Usage: reconcile_orphans --journal PATH [--apply]\n\n\
         Dry-run is the default. --apply unpins only candidates whose reachability can be verified."
    );
}

#[derive(Debug, Serialize)]
struct ReconciliationReport {
    apply: bool,
    journal: String,
    candidates: Vec<ReconciliationCandidateReport>,
}

#[derive(Debug, Serialize)]
struct ReconciliationCandidateReport {
    attempt_event_id: String,
    action: String,
    bucket: String,
    bucket_id_hex: String,
    reference_hex: String,
    reference_kind: String,
    pinned: bool,
    auto_unpin_allowed: bool,
    report_status: ReconciliationReportStatus,
    proof_required: Option<ReconciliationProofRequirement>,
    reason: String,
    applied_unpin: bool,
}

async fn evaluate_candidate(
    bee: &BeeClient,
    registry: &ChainRegistryClient,
    master_key: Option<&[u8; 32]>,
    candidate: ReconciliationCandidateSeed,
    apply: bool,
) -> Result<ReconciliationCandidateReport> {
    let bucket_id = decode_32(&candidate.bucket_id_hex, "bucket_id_hex")?;
    let chain_bucket = registry
        .get_bucket(bucket_id)
        .await
        .with_context(|| format!("failed to read bucket {}", candidate.bucket_id_hex))?;
    let pinned = bee.is_pinned(&candidate.reference.reference_hex).await?;

    let mut auto_unpin_allowed = candidate.auto_unpin_allowed;
    let mut report_status = candidate.report_status;
    let mut proof_required = candidate.proof_required;
    let mut reason = candidate.policy_reason.clone();

    if let Some(chain_bucket) = chain_bucket {
        let current_root_hex = hex::encode(&chain_bucket.bucket_manifest_root);
        if !current_root_hex.is_empty() && current_root_hex == candidate.reference.reference_hex {
            auto_unpin_allowed = false;
            report_status = ReconciliationReportStatus::NotProvenUnreachable;
            proof_required = None;
            reason = "reference is the current chain bucket manifest root".to_string();
        } else if candidate.report_status != ReconciliationReportStatus::ManifestHolderProofRequired
        {
            match reachable_refs_for_bucket(
                bee,
                master_key,
                &candidate,
                &chain_bucket,
                &current_root_hex,
            )
            .await
            {
                Ok(reachable) if reachable.contains(&candidate.reference.reference_hex) => {
                    auto_unpin_allowed = false;
                    report_status = ReconciliationReportStatus::NotProvenUnreachable;
                    proof_required = None;
                    reason = "reference is reachable from current chain bucket state".to_string();
                }
                Ok(_) => {}
                Err(err) => {
                    auto_unpin_allowed = false;
                    report_status = ReconciliationReportStatus::NotProvenUnreachable;
                    proof_required = Some(ReconciliationProofRequirement::ChainReachabilityCheck);
                    reason = format!("could not prove reference unreachable: {err}");
                }
            }
        }
    }

    let applied_unpin = if apply && auto_unpin_allowed && pinned {
        bee.unpin_reference(&candidate.reference.reference_hex)
            .await?;
        true
    } else {
        false
    };

    Ok(ReconciliationCandidateReport {
        attempt_event_id: candidate.attempt_event_id,
        action: format!("{:?}", candidate.action),
        bucket: candidate.bucket,
        bucket_id_hex: candidate.bucket_id_hex,
        reference_hex: candidate.reference.reference_hex,
        reference_kind: format!("{:?}", candidate.reference.kind),
        pinned,
        auto_unpin_allowed,
        report_status,
        proof_required,
        reason,
        applied_unpin,
    })
}

async fn reachable_refs_for_bucket(
    bee: &BeeClient,
    master_key: Option<&[u8; 32]>,
    candidate: &ReconciliationCandidateSeed,
    chain_bucket: &common::types::ChainBucketRecord,
    current_root_hex: &str,
) -> Result<HashSet<String>> {
    let mut reachable = HashSet::new();
    if current_root_hex.is_empty() {
        return Ok(reachable);
    }
    reachable.insert(current_root_hex.to_string());

    match candidate.bucket_type {
        JournalBucketType::Public => {
            add_public_reachable_refs(bee, current_root_hex, &mut reachable).await?;
        }
        JournalBucketType::TrustedGatewayPrivate => {
            let master_key = master_key.ok_or_else(|| {
                anyhow!("S3GW_MASTER_SERVICE_KEY_HEX is required for private reachability checks")
            })?;
            add_trusted_private_reachable_refs(
                bee,
                master_key,
                candidate,
                chain_bucket,
                &mut reachable,
            )
            .await?;
        }
        JournalBucketType::TrustlessPrivate => {
            if candidate.reference.kind == GatewayBeeReferenceKind::TrustlessCiphertextPayload {
                bail!("trustless ciphertext payload refs are encrypted-manifest local state");
            }
        }
    }

    Ok(reachable)
}

async fn add_public_reachable_refs(
    bee: &BeeClient,
    current_root_hex: &str,
    reachable: &mut HashSet<String>,
) -> Result<()> {
    let manifest_bytes = bee.get_bytes(current_root_hex).await?.with_context(|| {
        format!("current public bucket root {current_root_hex} not found in Bee")
    })?;
    let bucket_manifest: BucketManifest = serde_json::from_slice(&manifest_bytes)
        .context("failed to decode public bucket manifest")?;

    for object_manifest_ref in bucket_manifest.objects.values() {
        reachable.insert(object_manifest_ref.clone());
        let Some(object_manifest_bytes) = bee.get_bytes(object_manifest_ref).await? else {
            continue;
        };
        let object_manifest: ObjectManifest = serde_json::from_slice(&object_manifest_bytes)
            .context("failed to decode public object manifest")?;
        reachable.insert(object_manifest.swarm_reference);
    }

    Ok(())
}

async fn add_trusted_private_reachable_refs(
    bee: &BeeClient,
    master_key: &[u8; 32],
    candidate: &ReconciliationCandidateSeed,
    chain_bucket: &common::types::ChainBucketRecord,
    reachable: &mut HashSet<String>,
) -> Result<()> {
    let owner = decode_32(&candidate.owner_hex, "owner_hex")?;
    let Some(bucket_manifest) = read_private_bucket_manifest_v2(
        bee,
        master_key,
        &owner,
        &candidate.bucket,
        chain_bucket.encryption_version,
        &chain_bucket.bucket_manifest_root,
    )
    .await?
    else {
        return Ok(());
    };

    for entry in bucket_manifest.manifest.objects.values() {
        reachable.insert(entry.object_manifest_reference.clone());
        let Some(object_manifest) = read_private_object_manifest_v2(
            bee,
            master_key,
            &owner,
            &candidate.bucket,
            &entry.object_key_id,
            entry.encryption_version,
            &entry.object_manifest_reference,
        )
        .await?
        else {
            continue;
        };
        reachable.insert(object_manifest.manifest.encrypted_swarm_reference);
    }

    Ok(())
}

fn decode_32(hex_value: &str, field_name: &str) -> Result<[u8; 32]> {
    let raw = hex_value.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw).with_context(|| format!("{field_name} must be valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{field_name} must decode to exactly 32 bytes"))
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("missing required environment variable: {name}"))
}

fn load_optional_master_service_key() -> Result<Option<[u8; 32]>> {
    let Some(value) = env::var("S3GW_MASTER_SERVICE_KEY_HEX")
        .ok()
        .or_else(|| env::var("MASTER_SERVICE_KEY_HEX").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    let bytes = hex::decode(value.trim_start_matches("0x"))
        .context("S3GW_MASTER_SERVICE_KEY_HEX must be valid hex")?;
    let key = bytes
        .try_into()
        .map_err(|_| anyhow!("S3GW_MASTER_SERVICE_KEY_HEX must decode to exactly 32 bytes"))?;

    Ok(Some(key))
}
