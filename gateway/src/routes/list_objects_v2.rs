use anyhow::{Context, Result};
use axum::{
    extract::{Extension, Path, Query, State},
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord, ChainBucketType};
use serde::Deserialize;

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
                    &chain_bucket,
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
        match load_objects_from_anchored_bucket(&state, &chain_bucket, &prefix).await {
            Ok(objects) => objects,
            Err(err) => {
                return S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message(format!("failed to load anchored bucket listing: {err}"))
                    .with_resource(format!("/{bucket}"))
                    .into_response();
            }
        }
    };

    let page = page_list_objects(objects, max_keys, query.continuation_token.as_deref());

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
            page.next_continuation_token.as_deref(),
            &page.objects,
        ),
        chain_bucket.is_private,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListObjectsPage {
    objects: Vec<ListObjectsV2Entry>,
    is_truncated: bool,
    next_continuation_token: Option<String>,
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
        next_continuation_token,
    }
}

async fn load_private_objects_from_anchored_bucket(
    state: &AppState,
    principal: &AwsPrincipal,
    bucket: &str,
    chain_bucket: &ChainBucketRecord,
    prefix: &str,
) -> Result<Vec<ListObjectsV2Entry>> {
    if chain_bucket.bucket_manifest_root.is_empty() {
        return Ok(Vec::new());
    }

    let bucket_manifest = match read_private_bucket_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        bucket,
        chain_bucket.encryption_version,
        &chain_bucket.bucket_manifest_root,
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
    chain_bucket: &ChainBucketRecord,
    prefix: &str,
) -> Result<Vec<ListObjectsV2Entry>> {
    if chain_bucket.bucket_manifest_root.is_empty() {
        return Ok(Vec::new());
    }

    let bucket_manifest =
        read_bucket_manifest_from_root(state, &chain_bucket.bucket_manifest_root).await?;

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
        assert_eq!(page.next_continuation_token.as_deref(), Some("docs/b.txt"));
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
        assert!(page.next_continuation_token.is_none());
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
