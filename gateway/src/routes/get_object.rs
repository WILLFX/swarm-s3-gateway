use anyhow::{Context, Error as AnyhowError, Result};
use axum::{
    extract::{Extension, Path, State},
    response::Response,
};
use bytes::Bytes;
use common::types::{AwsPrincipal, ChainBucketRecord, ChainBucketType};
use reqwest::Error as ReqwestError;

use crate::{
    app_state::{AppState, ObjectMetadata},
    crypto::{bucket_name_hash, decrypt_blob, derive_private_object_payload_key},
    manifest::{BucketManifest, ObjectManifest},
    routes::private_object_read::{private_object_payload_aad, resolve_private_object_from_bucket},
    s3_response::{
        S3ErrorKind, S3ErrorResponse, bee_error_response, bee_unavailable_response,
        chain_error_response, get_object_response, omit_swarm_ref_for_private_response,
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
                return handle_private_get_object(&state, &principal, &chain_bucket, &bucket, &key)
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

    let object_bytes = match state.bee_client.get_bytes(&metadata.swarm_reference).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
        Err(err) if is_bee_unreachable(&err) => return bee_unavailable_response(err),
        Err(err) => return bee_error_response(err),
    };

    omit_swarm_ref_for_private_response(
        get_object_response(
            &metadata.swarm_reference,
            &metadata.content_type,
            Bytes::from(object_bytes),
        ),
        metadata.is_private,
    )
}

async fn handle_private_get_object(
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

    let encrypted_bytes = match state
        .bee_client
        .get_bytes(&resolved.object_manifest.encrypted_swarm_reference)
        .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
        Err(err) if is_bee_unreachable(&err) => return bee_unavailable_response(err),
        Err(err) => return bee_error_response(err),
    };

    let payload_key = derive_private_object_payload_key(
        &state.master_service_key,
        &principal.owner,
        bucket,
        &resolved.object_key_id,
        resolved.object_manifest.encryption_version,
    );

    let payload_aad = private_object_payload_aad(
        &principal.owner,
        bucket,
        &resolved.object_key_id,
        resolved.object_manifest.encryption_version,
    );

    let plaintext = match decrypt_blob(&payload_key, &payload_aad, &encrypted_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to decrypt private object payload: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    omit_swarm_ref_for_private_response(
        get_object_response(
            &resolved.object_manifest.encrypted_swarm_reference,
            &resolved.object_manifest.content_type,
            Bytes::from(plaintext),
        ),
        true,
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

fn is_bee_unreachable(err: &AnyhowError) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<ReqwestError>()
            .map(|e| e.is_connect() || e.is_timeout())
            .unwrap_or(false)
    })
}
