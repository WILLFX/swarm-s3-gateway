use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord, ChainBucketType};

use crate::{
    app_state::AppState,
    crypto::bucket_name_hash,
    manifest::{
        BucketManifest, PrivateBucketManifestV2, read_owner_catalog_manifest,
        read_private_bucket_manifest_v2, write_owner_catalog_manifest,
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

    if chain_bucket.is_private {
        let bucket_type = match state.registry_client.fetch_bucket_type(bucket_id).await {
            Ok(value) => value,
            Err(err) => return chain_error_response(err),
        };

        match bucket_type {
            Some(ChainBucketType::TrustlessPrivate) => {
                return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                    .with_message(
                        "trustless private buckets cannot be deleted by the gateway; use the local trustless proxy",
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
            Some(ChainBucketType::TrustedGatewayPrivate) | None => {}
        }
    }

    if let Err(response) =
        ensure_bucket_manifest_empty(&state, principal.owner, &bucket, &chain_bucket).await
    {
        return response;
    }

    let (expected_owner_catalog_root, owner_catalog_root) =
        match write_owner_catalog_without_bucket(&state, principal.owner, &bucket).await {
            Ok(roots) => roots,
            Err(err) => {
                return S3ErrorResponse::new(S3ErrorKind::InternalError)
                    .with_message(format!("failed to write owner bucket catalog: {err}"))
                    .with_resource(format!("/{bucket}"))
                    .into_response();
            }
        };

    match state
        .anchor_client
        .delete_bucket_anchor(
            bucket_id,
            owner_signature,
            expected_owner_catalog_root,
            owner_catalog_root,
        )
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

        return ensure_private_bucket_manifest_empty(bucket, &manifest);
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

fn ensure_private_bucket_manifest_empty(
    bucket: &str,
    manifest: &PrivateBucketManifestV2,
) -> Result<(), Response> {
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
) -> anyhow::Result<(String, String)> {
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

    Ok((hex::encode(root), record.manifest_reference))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PrivateBucketObjectEntry;
    use axum::http::StatusCode;
    use std::collections::BTreeMap;

    fn private_entry(object_key: &str) -> PrivateBucketObjectEntry {
        PrivateBucketObjectEntry {
            object_key: object_key.to_string(),
            object_key_id: [4u8; 32],
            object_manifest_reference:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            encryption_version: 1,
            size: 38,
            etag: "etag".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-05-14T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn private_delete_bucket_allows_empty_private_manifest() {
        let manifest = PrivateBucketManifestV2::default();

        let result = ensure_private_bucket_manifest_empty("test-bucket-private", &manifest);

        assert!(result.is_ok());
    }

    #[test]
    fn private_delete_bucket_rejects_non_empty_private_manifest() {
        let mut objects = BTreeMap::new();
        objects.insert("entry-a".to_string(), private_entry("secret.txt"));

        let manifest = PrivateBucketManifestV2 { objects };

        let response = ensure_private_bucket_manifest_empty("test-bucket-private", &manifest)
            .expect_err("non-empty private bucket manifest must be rejected");

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
