use crate::{
    app_state::{AppState, ObjectMetadata},
    crypto::{
        bucket_name_hash, derive_private_object_index_key, derive_private_object_payload_key,
        encrypt_blob_random, private_object_key_id,
    },
    manifest::{
        BucketManifest, ObjectManifest, PrivateBucketManifestV2, PrivateBucketObjectEntry,
        PrivateObjectManifestV2, read_bucket_manifest, read_private_bucket_manifest_v2,
        write_bucket_manifest, write_object_manifest, write_private_bucket_manifest_v2,
        write_private_object_manifest_v2,
    },
    s3_response::{
        S3ErrorKind, S3ErrorResponse, bee_error_response, bee_unavailable_response,
        chain_error_response, omit_swarm_ref_for_private_response, put_object_response,
    },
};
use anyhow::{Error as AnyhowError, Result};
use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    http::{HeaderMap, header},
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord};
use reqwest::Error as ReqwestError;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub async fn handle(
    Path((bucket, key)): Path<(String, String)>,
    Extension(principal): Extension<AwsPrincipal>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if key.is_empty() {
        return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
            .with_message("object key must not be empty")
            .with_resource(format!("/{bucket}/"))
            .into_response();
    }

    let chain_bucket_hash = bucket_name_hash(&principal.owner, &bucket);
    let chain_bucket = match state.registry_client.fetch_bucket(chain_bucket_hash).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return S3ErrorResponse::new(S3ErrorKind::NoSuchBucket)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
        Err(err) => return chain_error_response(err),
    };

    let size = body.len() as u64;
    let etag_bytes = sha256_32(&body);
    let etag = hex::encode(etag_bytes);
    let bucket_id = chain_bucket_hash;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let last_modified = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(v) => v,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to format last_modified: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    if chain_bucket.is_private {
        return handle_private_put_object(
            &state,
            &principal,
            &chain_bucket,
            &bucket,
            &key,
            body,
            content_type,
            last_modified,
            size,
            etag,
            etag_bytes,
            bucket_id,
        )
        .await;
    }

    let object_key_id = sha256_32(key.as_bytes());

    let put = match state
        .bee_client
        .put_object_and_update_pointer(&bucket, &key, body)
        .await
    {
        Ok(result) => result,
        Err(err) if is_bee_unreachable(&err) => return bee_unavailable_response(err),
        Err(err) => return bee_error_response(err),
    };

    let metadata = ObjectMetadata {
        swarm_reference: put.swarm_reference.clone(),
        size,
        etag,
        content_type,
        last_modified,
        is_private: false,
        encryption_version: None,
    };

    let bucket_manifest_root = match write_public_manifests(&state, &bucket, &key, &metadata).await
    {
        Ok(bucket_manifest_root) => bucket_manifest_root,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to write public bucket manifest: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    if let Err(err) = state
        .anchor_client
        .submit_anchor_object(
            principal.owner,
            bucket_id,
            object_key_id,
            put.swarm_reference.clone(),
            bucket_manifest_root,
            size,
            etag_bytes,
        )
        .await
    {
        return chain_error_response(err);
    }

    put_object_response(&put.swarm_reference)
}

async fn write_public_manifests(
    state: &AppState,
    bucket: &str,
    key: &str,
    metadata: &ObjectMetadata,
) -> Result<String> {
    let object_manifest = ObjectManifest {
        swarm_reference: metadata.swarm_reference.clone(),
        size: metadata.size,
        etag: metadata.etag.clone(),
        content_type: metadata.content_type.clone(),
        last_modified: metadata.last_modified.clone(),
    };

    let object_record =
        write_object_manifest(state.bee_client.as_ref(), bucket, key, &object_manifest).await?;

    let mut bucket_manifest = match read_bucket_manifest(state.bee_client.as_ref(), bucket).await? {
        Some(record) => record.manifest,
        None => BucketManifest::default(),
    };

    bucket_manifest
        .objects
        .insert(key.to_string(), object_record.manifest_reference);

    let bucket_record =
        write_bucket_manifest(state.bee_client.as_ref(), bucket, &bucket_manifest).await?;

    Ok(bucket_record.manifest_reference)
}

async fn handle_private_put_object(
    state: &AppState,
    principal: &AwsPrincipal,
    chain_bucket: &ChainBucketRecord,
    bucket: &str,
    key: &str,
    body: Bytes,
    content_type: String,
    last_modified: String,
    size: u64,
    etag: String,
    etag_bytes: [u8; 32],
    bucket_id: [u8; 32],
) -> Response {
    let encryption_version = chain_bucket.encryption_version;

    let private_index_key = derive_private_object_index_key(
        &state.master_service_key,
        &principal.owner,
        bucket,
        encryption_version,
    );
    let object_key_id = private_object_key_id(&private_index_key, key);
    let object_key_id_hex = hex::encode(object_key_id);

    let payload_key = derive_private_object_payload_key(
        &state.master_service_key,
        &principal.owner,
        bucket,
        &object_key_id,
        encryption_version,
    );
    let payload_aad =
        private_object_payload_aad(&principal.owner, bucket, &object_key_id, encryption_version);

    let encrypted_payload = match encrypt_blob_random(&payload_key, &payload_aad, &body) {
        Ok(bytes) => bytes,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to encrypt private object payload: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    let encrypted_put = match state
        .bee_client
        .put_bytes(Bytes::from(encrypted_payload))
        .await
    {
        Ok(result) => result,
        Err(err) if is_bee_unreachable(&err) => return bee_unavailable_response(err),
        Err(err) => return bee_error_response(err),
    };

    let private_object_manifest = PrivateObjectManifestV2 {
        object_key_id,
        encrypted_swarm_reference: encrypted_put.reference.clone(),
        encryption_version,
        size,
        etag: etag.clone(),
        content_type: content_type.clone(),
        last_modified: last_modified.clone(),
    };

    let object_manifest_record = match write_private_object_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        bucket,
        &object_key_id,
        encryption_version,
        &private_object_manifest,
    )
    .await
    {
        Ok(record) => record,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to write private object manifest v2: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    let mut bucket_manifest = match read_private_bucket_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        bucket,
        encryption_version,
        &chain_bucket.bucket_manifest_root,
    )
    .await
    {
        Ok(Some(record)) => record.manifest,
        Ok(None) => PrivateBucketManifestV2::default(),
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to read private bucket manifest v2: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    bucket_manifest.objects.insert(
        object_key_id_hex,
        PrivateBucketObjectEntry {
            object_key: key.to_string(),
            object_key_id,
            object_manifest_reference: object_manifest_record.manifest_reference,
            encryption_version,
            size,
            etag: etag.clone(),
            content_type,
            last_modified,
        },
    );

    let bucket_manifest_record = match write_private_bucket_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        bucket,
        encryption_version,
        &bucket_manifest,
    )
    .await
    {
        Ok(record) => record,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to write private bucket manifest v2: {err}"))
                .with_resource(format!("/{bucket}/{key}"))
                .into_response();
        }
    };

    if let Err(err) = state
        .anchor_client
        .submit_anchor_object(
            principal.owner,
            bucket_id,
            object_key_id,
            encrypted_put.reference.clone(),
            bucket_manifest_record.manifest_reference,
            size,
            etag_bytes,
        )
        .await
    {
        return chain_error_response(err);
    }

    omit_swarm_ref_for_private_response(put_object_response(&encrypted_put.reference), true)
}

fn private_object_payload_aad(
    owner: &common::types::SubstrateAddress32,
    bucket: &str,
    object_key_id: &[u8; 32],
    encryption_version: u32,
) -> Vec<u8> {
    let normalized_bucket = bucket.to_ascii_lowercase();

    let mut aad = Vec::new();
    aad.extend_from_slice(b"s3gw/v1/private-object-payload");
    aad.push(0);
    aad.extend_from_slice(owner);
    aad.push(0);
    aad.extend_from_slice(normalized_bucket.as_bytes());
    aad.push(0);
    aad.extend_from_slice(object_key_id);
    aad.push(0);
    aad.extend_from_slice(&encryption_version.to_le_bytes());
    aad
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn is_bee_unreachable(err: &AnyhowError) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<ReqwestError>()
            .map(|e| e.is_connect() || e.is_timeout())
            .unwrap_or(false)
    })
}
