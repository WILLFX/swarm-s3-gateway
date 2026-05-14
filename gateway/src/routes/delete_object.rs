use anyhow::{Context, Result};
use axum::{
    extract::{Extension, Path, State},
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord};

use crate::{
    app_state::AppState,
    crypto::bucket_name_hash,
    manifest::{BucketManifest, read_private_bucket_manifest_v2, write_private_bucket_manifest_v2},
    s3_response::{S3ErrorKind, S3ErrorResponse, chain_error_response, no_content_response},
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
        return handle_private_delete_object(
            &state,
            &principal,
            &chain_bucket,
            bucket_id,
            &bucket,
            &key,
        )
        .await;
    }

    let mut bucket_manifest = match read_bucket_manifest_from_root(&state, &chain_bucket).await {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to read anchored bucket manifest: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    if bucket_manifest.objects.remove(&key).is_none() {
        return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
            .with_resource(format!("/{bucket}/{key}"))
            .into_response();
    }

    let new_bucket_record = match crate::manifest::write_bucket_manifest(
        state.bee_client.as_ref(),
        &bucket,
        &bucket_manifest,
    )
    .await
    {
        Ok(record) => record,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to write updated bucket manifest: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    if let Err(err) = state
        .anchor_client
        .update_bucket_manifest_root_for_delete_anchor(
            bucket_id,
            new_bucket_record.manifest_reference,
        )
        .await
    {
        return chain_error_response(err);
    }

    no_content_response()
}

async fn handle_private_delete_object(
    state: &AppState,
    principal: &AwsPrincipal,
    chain_bucket: &ChainBucketRecord,
    bucket_id: [u8; 32],
    bucket: &str,
    key: &str,
) -> Response {
    if chain_bucket.bucket_manifest_root.is_empty() {
        return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
            .with_resource(format!("/{bucket}/{key}"))
            .into_response();
    }

    let mut bucket_manifest = match read_private_bucket_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        bucket,
        chain_bucket.encryption_version,
        &chain_bucket.bucket_manifest_root,
    )
    .await
    {
        Ok(Some(record)) => record.manifest,
        Ok(None) => {
            return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to read private bucket manifest: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    let Some(manifest_key_to_remove) = bucket_manifest
        .objects
        .iter()
        .find(|(_, entry)| entry.object_key == key)
        .map(|(manifest_key, _)| manifest_key.clone())
    else {
        return S3ErrorResponse::new(S3ErrorKind::NoSuchKey)
            .with_resource(format!("/{bucket}/{key}"))
            .into_response();
    };

    bucket_manifest.objects.remove(&manifest_key_to_remove);

    let new_bucket_record = match write_private_bucket_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        bucket,
        chain_bucket.encryption_version,
        &bucket_manifest,
    )
    .await
    {
        Ok(record) => record,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!(
                    "failed to write updated private bucket manifest: {err}"
                ))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    if let Err(err) = state
        .anchor_client
        .update_bucket_manifest_root_for_delete_anchor(
            bucket_id,
            new_bucket_record.manifest_reference,
        )
        .await
    {
        return chain_error_response(err);
    }

    no_content_response()
}

async fn read_bucket_manifest_from_root(
    state: &AppState,
    chain_bucket: &ChainBucketRecord,
) -> Result<Option<BucketManifest>> {
    if chain_bucket.bucket_manifest_root.is_empty() {
        return Ok(None);
    }

    if chain_bucket.bucket_manifest_root.len() != 32 {
        anyhow::bail!(
            "bucket_manifest_root must be 32 bytes, got {}",
            chain_bucket.bucket_manifest_root.len()
        );
    }

    let manifest_reference = hex::encode(&chain_bucket.bucket_manifest_root);

    let manifest_bytes = state
        .bee_client
        .get_bytes(&manifest_reference)
        .await?
        .context("anchored bucket manifest root not found in Swarm")?;

    let manifest =
        serde_json::from_slice(&manifest_bytes).context("failed to decode bucket manifest JSON")?;

    Ok(Some(manifest))
}
