use anyhow::{Context, Result};
use axum::{
    extract::{Extension, Path, State},
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord, ChainBucketType};

use crate::{
    app_state::{AppState, ObjectMetadata},
    crypto::bucket_name_hash,
    manifest::{BucketManifest, ObjectManifest},
    routes::private_object_read::resolve_private_object_from_bucket,
    s3_response::{
        S3ErrorKind, S3ErrorResponse, chain_error_response, head_object_response,
        omit_swarm_ref_for_private_response,
    },
};

pub async fn handle(
    Path((bucket, key)): Path<(String, String)>,
    Extension(principal): Extension<AwsPrincipal>,
    State(state): State<AppState>,
) -> Response {
    if key.is_empty() {
        return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
            .with_message("object key must not be empty")
            .with_resource(format!("/{bucket}/"))
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

    if chain_bucket.is_private {
        let bucket_type = match state.registry_client.fetch_bucket_type(bucket_id).await {
            Ok(value) => value,
            Err(err) => return chain_error_response(err),
        };

        match bucket_type {
            Some(ChainBucketType::TrustlessPrivate) => {
                return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                    .with_message(
                        "trustless private buckets cannot be decrypted by the gateway; use the local trustless proxy",
                    )
                    .with_resource(format!("/{bucket}/{key}"))
                    .into_response();
            }
            Some(ChainBucketType::Public) => {
                return S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message("bucket type is public but bucket record is marked private")
                    .with_resource(format!("/{bucket}/{key}"))
                    .into_response();
            }
            Some(ChainBucketType::TrustedGatewayPrivate) | None => {
                return handle_private_head_object(
                    &state,
                    &principal,
                    &chain_bucket,
                    &bucket,
                    &key,
                )
                .await;
            }
        }
    }

    let metadata =
        match load_metadata_from_anchored_bucket(&state, &bucket, &key, &chain_bucket).await {
            Ok(Some(metadata)) => metadata,
            Ok(None) => {
                return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
                    .with_resource(format!("/{bucket}/{key}"))
                    .into_response();
            }
            Err(err) => {
                return S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message(format!("failed to resolve anchored object metadata: {err}"))
                    .with_resource(format!("/{bucket}/{key}"))
                    .into_response();
            }
        };

    omit_swarm_ref_for_private_response(
        head_object_response(
            &metadata.swarm_reference,
            &metadata.content_type,
            metadata.size,
            &metadata.etag,
            &metadata.last_modified,
        ),
        metadata.is_private,
    )
}

async fn handle_private_head_object(
    state: &AppState,
    principal: &AwsPrincipal,
    chain_bucket: &ChainBucketRecord,
    bucket: &str,
    key: &str,
) -> Response {
    let resolved = match resolve_private_object_from_bucket(
        state,
        &principal.owner,
        bucket,
        key,
        chain_bucket,
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to resolve private object metadata: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    let metadata = resolved.metadata();

    omit_swarm_ref_for_private_response(
        head_object_response(
            &metadata.swarm_reference,
            &metadata.content_type,
            metadata.size,
            &metadata.etag,
            &metadata.last_modified,
        ),
        metadata.is_private,
    )
}

async fn load_metadata_from_anchored_bucket(
    state: &AppState,
    _bucket: &str,
    key: &str,
    chain_bucket: &ChainBucketRecord,
) -> Result<Option<ObjectMetadata>> {
    if chain_bucket.bucket_manifest_root.is_empty() {
        return Ok(None);
    }

    let bucket_manifest =
        read_bucket_manifest_from_root(state, &chain_bucket.bucket_manifest_root).await?;

    let Some(object_manifest_ref) = bucket_manifest.objects.get(key) else {
        return Ok(None);
    };

    let object_manifest = read_object_manifest_by_reference(state, object_manifest_ref).await?;

    Ok(Some(ObjectMetadata {
        swarm_reference: object_manifest.swarm_reference,
        size: object_manifest.size,
        etag: object_manifest.etag,
        content_type: object_manifest.content_type,
        last_modified: object_manifest.last_modified,
        is_private: false,
        encryption_version: None,
    }))
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
