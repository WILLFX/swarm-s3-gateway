use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord};

use crate::{
    app_state::AppState,
    crypto::bucket_name_hash,
    manifest::{
        BucketManifest, read_owner_catalog_manifest, read_private_bucket_manifest_v2,
        write_owner_catalog_manifest,
    },
    s3_response::{S3ErrorKind, S3ErrorResponse, chain_error_response, no_content_response},
};

const OWNER_SIGNATURE_HEADER: &str = "x-s3gw-owner-signature";

pub async fn handle(
    Path(bucket): Path<String>,
    Extension(principal): Extension<AwsPrincipal>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let owner_signature = match parse_owner_signature(&headers) {
        Ok(signature) => signature,
        Err(message) => {
            return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                .with_message(message)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
    };

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

    if let Err(response) =
        ensure_bucket_manifest_empty(&state, principal.owner, &bucket, &chain_bucket).await
    {
        return response;
    }

    let owner_catalog_root =
        match write_owner_catalog_without_bucket(&state, principal.owner, &bucket).await {
            Ok(root) => root,
            Err(err) => {
                return S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message(format!("failed to write owner bucket catalog: {err}"))
                    .with_resource(format!("/{bucket}"))
                    .into_response();
            }
        };

    match state
        .anchor_client
        .delete_bucket_anchor(bucket_id, owner_signature, owner_catalog_root)
        .await
    {
        Ok(_) => no_content_response(),
        Err(err) => chain_error_response(err),
    }
}

async fn ensure_bucket_manifest_empty(
    state: &AppState,
    owner: common::types::SubstrateAddress32,
    bucket: &str,
    chain_bucket: &ChainBucketRecord,
) -> Result<(), Response> {
    if chain_bucket.bucket_manifest_root.is_empty() {
        return Ok(());
    }

    if chain_bucket.is_private {
        let manifest = match read_private_bucket_manifest_v2(
            state.bee_client.as_ref(),
            &state.master_service_key,
            &owner,
            bucket,
            chain_bucket.encryption_version,
            &chain_bucket.bucket_manifest_root,
        )
        .await
        {
            Ok(Some(record)) => record.manifest,
            Ok(None) => {
                return Err(S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message("anchored private bucket manifest root was not found in Swarm")
                    .with_resource(format!("/{bucket}"))
                    .into_response());
            }
            Err(err) => {
                return Err(S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message(format!("failed to read private bucket manifest: {err}"))
                    .with_resource(format!("/{bucket}"))
                    .into_response());
            }
        };

        return if manifest.objects.is_empty() {
            Ok(())
        } else {
            Err(S3ErrorResponse::new(S3ErrorKind::BucketNotEmpty)
                .with_resource(format!("/{bucket}"))
                .into_response())
        };
    }

    let manifest_reference = hex::encode(&chain_bucket.bucket_manifest_root);

    let manifest_bytes = match state.bee_client.get_bytes(&manifest_reference).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!(
                    "anchored bucket manifest root was not found in Swarm: {manifest_reference}"
                ))
                .with_resource(format!("/{bucket}"))
                .into_response());
        }
        Err(err) => {
            return Err(S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!(
                    "failed to read anchored bucket manifest from Swarm: {err}"
                ))
                .with_resource(format!("/{bucket}"))
                .into_response());
        }
    };

    let manifest: BucketManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            return Err(S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to decode anchored bucket manifest: {err}"))
                .with_resource(format!("/{bucket}"))
                .into_response());
        }
    };

    if manifest.objects.is_empty() {
        Ok(())
    } else {
        Err(S3ErrorResponse::new(S3ErrorKind::BucketNotEmpty)
            .with_resource(format!("/{bucket}"))
            .into_response())
    }
}

fn parse_owner_signature(headers: &HeaderMap) -> Result<[u8; 64], String> {
    let value = headers
        .get(OWNER_SIGNATURE_HEADER)
        .ok_or_else(|| format!("missing required header: {OWNER_SIGNATURE_HEADER}"))?
        .to_str()
        .map_err(|_| format!("{OWNER_SIGNATURE_HEADER} must be valid ASCII hex"))?;

    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|err| format!("{OWNER_SIGNATURE_HEADER} must be hex: {err}"))?;

    bytes
        .try_into()
        .map_err(|_| format!("{OWNER_SIGNATURE_HEADER} must decode to exactly 64 bytes"))
}

async fn write_owner_catalog_without_bucket(
    state: &AppState,
    owner: common::types::SubstrateAddress32,
    bucket: &str,
) -> anyhow::Result<String> {
    let root = state
        .registry_client
        .fetch_owner_catalog_root(owner)
        .await?;

    let mut catalog = read_owner_catalog_manifest(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &owner,
        &root,
    )
    .await?;

    catalog.buckets.remove(bucket);

    let record = write_owner_catalog_manifest(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &owner,
        &catalog,
    )
    .await?;

    Ok(record.manifest_reference)
}
