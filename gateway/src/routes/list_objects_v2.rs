use anyhow::{bail, Context, Result};
use axum::{
    extract::{Extension, Path, Query, State},
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord, ChainBucketType};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    app_state::AppState,
    crypto::bucket_name_hash,
    manifest::{
        read_private_bucket_manifest_v2, BucketManifest, ObjectManifest, PrivateBucketManifestV2,
    },
    s3_response::{
        chain_error_response, list_objects_v2_response, omit_swarm_ref_for_private_response,
        ListObjectsV2Entry, S3ErrorKind, S3ErrorResponse,
    },
};

type HmacSha256 = Hmac<Sha256>;

const LIST_CONTINUATION_TOKEN_PREFIX: &str = "s3gw-list-v1";

#[derive(Debug, Deserialize)]
pub struct ListObjectsV2Query {
    #[serde(rename = "list-type")]
    pub list_type: Option<u32>,
    pub prefix: Option<String>,
    #[serde(rename = "max-keys")]
    pub max_keys: Option<usize>,
    #[serde(rename = "continuation-token")]
    pub continuation_token: Option<String>,
}

pub async fn handle(
    Path(bucket): Path<String>,
    Query(query): Query<ListObjectsV2Query>,
    Extension(principal): Extension<AwsPrincipal>,
    State(state): State<AppState>,
) -> Response {
    if query.list_type != Some(2) {
        return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
            .with_message("this endpoint requires list-type=2")
            .with_resource(format!("/{bucket}"))
            .into_response();
    }

    let bucket_id = bucket_name_hash(&principal.owner, &bucket);

    let chain_bucket = match state.registry_client.fetch_bucket(bucket_id).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return S3ErrorResponse::new(S3ErrorKind::NoSuchBucket)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
        Err(err) => return chain_error_response(err),
    };

    let prefix = query.prefix.unwrap_or_default();
    let max_keys = query.max_keys.unwrap_or(1000);
    let snapshot = match resolve_list_snapshot(
        &chain_bucket,
        bucket_id,
        &prefix,
        query.continuation_token.as_deref(),
        &state.master_service_key,
    ) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                .with_message(format!("invalid continuation-token: {err}"))
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
    };

    let objects = if chain_bucket.is_private {
        let bucket_type = match state.registry_client.fetch_bucket_type(bucket_id).await {
            Ok(value) => value,
            Err(err) => return chain_error_response(err),
        };

        match bucket_type {
            Some(ChainBucketType::TrustlessPrivate) => {
                return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                    .with_message(
                        "trustless private buckets cannot be listed by the gateway; use the local trustless proxy",
                    )
                    .with_resource(format!("/{bucket}"))
                    .into_response();
            }
            Some(ChainBucketType::Public) => {
                return S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message("bucket type is public but bucket record is marked private")
                    .with_resource(format!("/{bucket}"))
                    .into_response();
            }
            Some(ChainBucketType::TrustedGatewayPrivate) | None => {
                match load_private_objects_from_anchored_bucket(
                    &state,
                    &principal,
                    &bucket,
                    &snapshot.manifest_root,
                    snapshot.encryption_version,
                    &prefix,
                )
                .await
                {
                    Ok(objects) => objects,
                    Err(err) => {
                        return S3ErrorResponse::new(S3ErrorKind::InternalError)
                            .with_message(format!(
                                "failed to load private anchored bucket listing: {err}"
                            ))
                            .with_resource(format!("/{bucket}"))
                            .into_response();
                    }
                }
            }
        }
    } else {
        match load_objects_from_anchored_bucket(&state, &snapshot.manifest_root, &prefix).await {
            Ok(objects) => objects,
            Err(err) => {
                return S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message(format!("failed to load anchored bucket listing: {err}"))
                    .with_resource(format!("/{bucket}"))
                    .into_response();
            }
        }
    };

    let page = page_list_objects(objects, max_keys, snapshot.after_key.as_deref());
    let next_continuation_token = match page.next_after_key.as_deref() {
        Some(after_key) => {
            match encode_list_continuation_token(&snapshot, after_key, &state.master_service_key) {
                Ok(token) => Some(token),
                Err(err) => {
                    return S3ErrorResponse::new(S3ErrorKind::InternalError)
                        .with_message(format!("failed to build continuation token: {err}"))
                        .with_resource(format!("/{bucket}"))
                        .into_response();
                }
            }
        }
        None => None,
    };

    omit_swarm_ref_for_private_response(
        list_objects_v2_response(
            &bucket,
            if prefix.is_empty() {
                None
            } else {
                Some(prefix.as_str())
            },
            max_keys,
            query.continuation_token.as_deref(),
            page.is_truncated,
            next_continuation_token.as_deref(),
            &page.objects,
        ),
        chain_bucket.is_private,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListObjectsPage {
    objects: Vec<ListObjectsV2Entry>,
    is_truncated: bool,
    next_after_key: Option<String>,
}

fn page_list_objects(
    mut objects: Vec<ListObjectsV2Entry>,
    max_keys: usize,
    continuation_token: Option<&str>,
) -> ListObjectsPage {
    objects.sort_by(|a, b| a.key.cmp(&b.key));

    let mut after_token = objects
        .into_iter()
        .filter(|object| continuation_token.is_none_or(|token| object.key.as_str() > token))
        .collect::<Vec<_>>();

    let is_truncated = after_token.len() > max_keys;
    let next_continuation_token = if is_truncated && max_keys > 0 {
        after_token
            .get(max_keys - 1)
            .map(|object| object.key.clone())
    } else {
        None
    };

    after_token.truncate(max_keys);

    ListObjectsPage {
        objects: after_token,
        is_truncated,
        next_after_key: next_continuation_token,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListSnapshot {
    bucket_id_hex: String,
    manifest_root: Vec<u8>,
    encryption_version: u32,
    creation_date: u64,
    prefix: String,
    after_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ListContinuationTokenPayload {
    schema: String,
    bucket_id_hex: String,
    manifest_root_hex: String,
    encryption_version: u32,
    creation_date: u64,
    prefix: String,
    after_key: String,
}

fn resolve_list_snapshot(
    chain_bucket: &ChainBucketRecord,
    bucket_id: [u8; 32],
    prefix: &str,
    continuation_token: Option<&str>,
    signing_key: &[u8; 32],
) -> Result<ListSnapshot> {
    let bucket_id_hex = hex::encode(bucket_id);

    let Some(continuation_token) = continuation_token else {
        return Ok(ListSnapshot {
            bucket_id_hex,
            manifest_root: chain_bucket.bucket_manifest_root.clone(),
            encryption_version: chain_bucket.encryption_version,
            creation_date: chain_bucket.creation_date,
            prefix: prefix.to_owned(),
            after_key: None,
        });
    };

    let payload = decode_list_continuation_token(continuation_token, signing_key)?;

    if payload.bucket_id_hex != bucket_id_hex {
        bail!("token bucket id does not match request bucket");
    }

    if payload.prefix != prefix {
        bail!("token prefix does not match request prefix");
    }

    if payload.encryption_version != chain_bucket.encryption_version {
        bail!("token encryption version does not match current bucket");
    }

    if payload.creation_date != chain_bucket.creation_date {
        bail!("token bucket creation date does not match current bucket");
    }

    let manifest_root = decode_swarm_reference_or_empty(&payload.manifest_root_hex)?;

    Ok(ListSnapshot {
        bucket_id_hex,
        manifest_root,
        encryption_version: payload.encryption_version,
        creation_date: payload.creation_date,
        prefix: payload.prefix,
        after_key: Some(payload.after_key),
    })
}

fn encode_list_continuation_token(
    snapshot: &ListSnapshot,
    after_key: &str,
    signing_key: &[u8; 32],
) -> Result<String> {
    let after_key = after_key.trim();

    if after_key.is_empty() {
        bail!("continuation after_key is required");
    }

    let payload = ListContinuationTokenPayload {
        schema: LIST_CONTINUATION_TOKEN_PREFIX.to_owned(),
        bucket_id_hex: snapshot.bucket_id_hex.clone(),
        manifest_root_hex: hex::encode(&snapshot.manifest_root),
        encryption_version: snapshot.encryption_version,
        creation_date: snapshot.creation_date,
        prefix: snapshot.prefix.clone(),
        after_key: after_key.to_owned(),
    };
    let payload_bytes =
        serde_json::to_vec(&payload).context("failed to encode continuation token payload")?;
    let signature = sign_list_token_payload(&payload_bytes, signing_key);

    Ok(format!(
        "{}:{}:{}",
        LIST_CONTINUATION_TOKEN_PREFIX,
        hex::encode(payload_bytes),
        hex::encode(signature)
    ))
}

fn decode_list_continuation_token(
    token: &str,
    signing_key: &[u8; 32],
) -> Result<ListContinuationTokenPayload> {
    let mut parts = token.trim().split(':');
    let prefix = parts.next().unwrap_or_default();
    let payload_hex = parts.next().unwrap_or_default();
    let signature_hex = parts.next().unwrap_or_default();

    if prefix != LIST_CONTINUATION_TOKEN_PREFIX
        || payload_hex.is_empty()
        || signature_hex.is_empty()
        || parts.next().is_some()
    {
        bail!("token must be an opaque signed s3gw-list-v1 token");
    }

    let payload_bytes =
        hex::decode(payload_hex).context("token payload must be hex encoded JSON")?;
    let signature = hex::decode(signature_hex).context("token signature must be hex encoded")?;
    let expected = sign_list_token_payload(&payload_bytes, signing_key);

    if signature.as_slice() != expected.as_slice() {
        bail!("token signature is invalid");
    }

    let payload: ListContinuationTokenPayload =
        serde_json::from_slice(&payload_bytes).context("token payload must decode as JSON")?;

    if payload.schema != LIST_CONTINUATION_TOKEN_PREFIX {
        bail!("token schema is invalid");
    }

    if payload.after_key.trim().is_empty() {
        bail!("token after_key is required");
    }

    let _ = decode_swarm_reference_or_empty(&payload.manifest_root_hex)?;

    Ok(payload)
}

fn sign_list_token_payload(payload: &[u8], signing_key: &[u8; 32]) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(signing_key).expect("HMAC accepts fixed-size signing keys");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

fn decode_swarm_reference_or_empty(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();

    if value.is_empty() {
        return Ok(Vec::new());
    }

    let bytes = hex::decode(value).context("manifest root must be hex encoded")?;

    if bytes.len() != 32 {
        bail!("manifest root must be a 32-byte Swarm reference");
    }

    Ok(bytes)
}

async fn load_private_objects_from_anchored_bucket(
    state: &AppState,
    principal: &AwsPrincipal,
    bucket: &str,
    manifest_root: &[u8],
    encryption_version: u32,
    prefix: &str,
) -> Result<Vec<ListObjectsV2Entry>> {
    if manifest_root.is_empty() {
        return Ok(Vec::new());
    }

    let bucket_manifest = match read_private_bucket_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        bucket,
        encryption_version,
        manifest_root,
    )
    .await?
    {
        Some(record) => record.manifest,
        None => return Ok(Vec::new()),
    };

    Ok(list_entries_from_private_bucket_manifest(
        &bucket_manifest,
        prefix,
    ))
}

fn list_entries_from_private_bucket_manifest(
    bucket_manifest: &PrivateBucketManifestV2,
    prefix: &str,
) -> Vec<ListObjectsV2Entry> {
    let mut objects = Vec::new();

    for entry in bucket_manifest.objects.values() {
        if !entry.object_key.starts_with(prefix) {
            continue;
        }

        objects.push(ListObjectsV2Entry {
            key: entry.object_key.clone(),
            last_modified: entry.last_modified.clone(),
            etag: entry.etag.clone(),
            size: entry.size,
            storage_class: "STANDARD".to_string(),
        });
    }

    objects
}

async fn load_objects_from_anchored_bucket(
    state: &AppState,
    manifest_root: &[u8],
    prefix: &str,
) -> Result<Vec<ListObjectsV2Entry>> {
    if manifest_root.is_empty() {
        return Ok(Vec::new());
    }

    let bucket_manifest = read_bucket_manifest_from_root(state, manifest_root).await?;

    let mut objects = Vec::new();

    for (key, object_manifest_ref) in bucket_manifest.objects {
        if !key.starts_with(prefix) {
            continue;
        }

        let object_manifest =
            read_object_manifest_by_reference(state, &object_manifest_ref).await?;

        objects.push(ListObjectsV2Entry {
            key,
            last_modified: object_manifest.last_modified,
            etag: object_manifest.etag,
            size: object_manifest.size,
            storage_class: "STANDARD".to_string(),
        });
    }

    Ok(objects)
}

async fn read_bucket_manifest_from_root(
    state: &AppState,
    bucket_manifest_root: &[u8],
) -> Result<BucketManifest> {
    if bucket_manifest_root.len() != 32 {
        anyhow::bail!(
            "bucket_manifest_root must be 32 bytes, got {}",
            bucket_manifest_root.len()
        );
    }

    let manifest_reference = hex::encode(bucket_manifest_root);

    let manifest_bytes = state
        .bee_client
        .get_bytes(&manifest_reference)
        .await?
        .context("anchored bucket manifest root not found in Swarm")?;

    serde_json::from_slice(&manifest_bytes).context("failed to decode bucket manifest JSON")
}

async fn read_object_manifest_by_reference(
    state: &AppState,
    object_manifest_ref: &str,
) -> Result<ObjectManifest> {
    let manifest_bytes = state
        .bee_client
        .get_bytes(object_manifest_ref)
        .await?
        .context("anchored object manifest not found in Swarm")?;

    serde_json::from_slice(&manifest_bytes).context("failed to decode object manifest JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PrivateBucketObjectEntry;
    use std::collections::BTreeMap;

    fn list_entry(key: &str) -> ListObjectsV2Entry {
        ListObjectsV2Entry {
            key: key.to_string(),
            last_modified: "2026-05-14T00:00:00Z".to_string(),
            etag: format!("etag-{key}"),
            size: 1,
            storage_class: "STANDARD".to_string(),
        }
    }

    fn private_entry(
        object_key: &str,
        object_manifest_reference: &str,
        size: u64,
    ) -> PrivateBucketObjectEntry {
        PrivateBucketObjectEntry {
            object_key: object_key.to_string(),
            object_key_id: [3u8; 32],
            object_manifest_reference: object_manifest_reference.to_string(),
            encryption_version: 1,
            size,
            etag: format!("etag-{object_key}"),
            content_type: "text/plain".to_string(),
            last_modified: "2026-05-14T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn list_pagination_sorts_truncates_and_returns_next_token() {
        let page = page_list_objects(
            vec![
                list_entry("docs/c.txt"),
                list_entry("docs/a.txt"),
                list_entry("docs/b.txt"),
            ],
            2,
            None,
        );

        assert_eq!(
            page.objects
                .iter()
                .map(|object| object.key.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/a.txt", "docs/b.txt"]
        );
        assert!(page.is_truncated);
        assert_eq!(page.next_after_key.as_deref(), Some("docs/b.txt"));
    }

    #[test]
    fn list_pagination_resumes_after_continuation_token() {
        let page = page_list_objects(
            vec![
                list_entry("docs/c.txt"),
                list_entry("docs/a.txt"),
                list_entry("docs/b.txt"),
            ],
            2,
            Some("docs/b.txt"),
        );

        assert_eq!(
            page.objects
                .iter()
                .map(|object| object.key.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/c.txt"]
        );
        assert!(!page.is_truncated);
        assert!(page.next_after_key.is_none());
    }

    #[test]
    fn list_continuation_token_is_signed_and_bound_to_snapshot() {
        let signing_key = [9u8; 32];
        let bucket_id = [7u8; 32];
        let chain_bucket = ChainBucketRecord {
            owner: [1u8; 32],
            is_private: false,
            bucket_generation: 1,
            bucket_state_epoch: 1,
            encryption_version: 3,
            creation_date: 42,
            bucket_manifest_root: vec![4u8; 32],
        };
        let snapshot = resolve_list_snapshot(&chain_bucket, bucket_id, "docs/", None, &signing_key)
            .expect("initial snapshot should resolve from chain root");
        let token = encode_list_continuation_token(&snapshot, "docs/b.txt", &signing_key)
            .expect("token should encode");

        let resumed = resolve_list_snapshot(
            &ChainBucketRecord {
                bucket_manifest_root: vec![8u8; 32],
                ..chain_bucket.clone()
            },
            bucket_id,
            "docs/",
            Some(&token),
            &signing_key,
        )
        .expect("signed token should resolve its original snapshot even after root advances");

        assert_eq!(resumed.manifest_root, vec![4u8; 32]);
        assert_eq!(resumed.after_key.as_deref(), Some("docs/b.txt"));

        let err = resolve_list_snapshot(
            &chain_bucket,
            bucket_id,
            "images/",
            Some(&token),
            &signing_key,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("prefix"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn list_continuation_token_rejects_signature_tampering() {
        let signing_key = [9u8; 32];
        let chain_bucket = ChainBucketRecord {
            owner: [1u8; 32],
            is_private: false,
            bucket_generation: 1,
            bucket_state_epoch: 1,
            encryption_version: 1,
            creation_date: 1,
            bucket_manifest_root: vec![4u8; 32],
        };
        let snapshot =
            resolve_list_snapshot(&chain_bucket, [7u8; 32], "", None, &signing_key).unwrap();
        let mut token = encode_list_continuation_token(&snapshot, "b.txt", &signing_key).unwrap();
        token.push('0');

        let err = resolve_list_snapshot(&chain_bucket, [7u8; 32], "", Some(&token), &signing_key)
            .unwrap_err();

        assert!(
            err.to_string().contains("signature") || err.to_string().contains("token"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn private_list_objects_uses_bucket_manifest_entry_metadata_only() {
        let mut objects = BTreeMap::new();

        objects.insert(
            "entry-a".to_string(),
            private_entry(
                "secret.txt",
                "object-manifest-reference-that-must-not-be-read",
                38,
            ),
        );

        let manifest = PrivateBucketManifestV2 { objects };

        let listed = list_entries_from_private_bucket_manifest(&manifest, "");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "secret.txt");
        assert_eq!(listed[0].size, 38);
        assert_eq!(listed[0].etag, "etag-secret.txt");
        // This test intentionally never dereferences object_manifest_reference.
        // Private listing must be satisfied from PrivateBucketManifestV2 entry metadata only.
    }

    #[test]
    fn private_list_objects_applies_prefix_without_reading_object_manifests() {
        let mut objects = BTreeMap::new();

        objects.insert(
            "entry-a".to_string(),
            private_entry("docs/a.txt", "manifest-a-that-must-not-be-read", 10),
        );

        objects.insert(
            "entry-b".to_string(),
            private_entry("images/b.txt", "manifest-b-that-must-not-be-read", 20),
        );

        let manifest = PrivateBucketManifestV2 { objects };

        let listed = list_entries_from_private_bucket_manifest(&manifest, "docs/");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "docs/a.txt");
        assert_eq!(listed[0].size, 10);
    }
}
