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
    traits::AnchorClient,
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

    if let Err(err) = anchor_delete_object_manifest_root(
        state.anchor_client.as_ref(),
        bucket_id,
        hex::encode(&chain_bucket.bucket_manifest_root),
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

    if let Err(err) = anchor_delete_object_manifest_root(
        state.anchor_client.as_ref(),
        bucket_id,
        hex::encode(&chain_bucket.bucket_manifest_root),
        new_bucket_record.manifest_reference,
    )
    .await
    {
        return chain_error_response(err);
    }

    no_content_response()
}

async fn anchor_delete_object_manifest_root(
    anchor_client: &dyn AnchorClient,
    bucket_id: [u8; 32],
    expected_bucket_manifest_root: String,
    bucket_manifest_root: String,
) -> anyhow::Result<String> {
    anchor_client
        .update_bucket_manifest_root_for_delete_anchor(
            bucket_id,
            expected_bucket_manifest_root,
            bucket_manifest_root,
        )
        .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use common::types::SubstrateAddress32;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct RecordingAnchorClient {
        put_calls: AtomicUsize,
        delete_calls: AtomicUsize,
    }

    #[async_trait]
    impl AnchorClient for RecordingAnchorClient {
        async fn create_bucket_anchor(
            &self,
            _owner: SubstrateAddress32,
            _bucket_id: [u8; 32],
            _is_private: bool,
            _owner_signature: [u8; 64],
            _expected_owner_catalog_root: String,
            _owner_catalog_root: String,
        ) -> anyhow::Result<String> {
            Ok("create".to_string())
        }

        async fn create_trustless_bucket_anchor(
            &self,
            _owner: SubstrateAddress32,
            _bucket_id: [u8; 32],
            _owner_signature: [u8; 64],
            _expected_owner_catalog_root: String,
            _owner_catalog_root: String,
        ) -> anyhow::Result<String> {
            anyhow::bail!("create_trustless_bucket_anchor should not be used by these tests")
        }

        async fn delete_bucket_anchor(
            &self,
            _bucket_id: [u8; 32],
            _owner_signature: [u8; 64],
            _expected_owner_catalog_root: String,
            _owner_catalog_root: String,
        ) -> anyhow::Result<String> {
            Ok("delete-bucket".to_string())
        }

        async fn update_bucket_manifest_root_for_put_anchor(
            &self,
            _bucket_id: [u8; 32],
            _expected_bucket_manifest_root: String,
            _bucket_manifest_root: String,
        ) -> anyhow::Result<String> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            Ok("put-root".to_string())
        }

        async fn update_bucket_manifest_root_for_delete_anchor(
            &self,
            _bucket_id: [u8; 32],
            _expected_bucket_manifest_root: String,
            _bucket_manifest_root: String,
        ) -> anyhow::Result<String> {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            Ok("delete-root".to_string())
        }

        async fn submit_anchor_object(
            &self,
            _owner: SubstrateAddress32,
            _bucket_id: [u8; 32],
            _object_key_id: [u8; 32],
            _swarm_ref: String,
            _expected_bucket_manifest_root: String,
            _bucket_manifest_root: String,
            _size: u64,
            _etag: [u8; 32],
        ) -> anyhow::Result<String> {
            Ok("submit-object".to_string())
        }
    }

    #[tokio::test]
    async fn delete_object_manifest_root_uses_delete_anchor_not_put_anchor() {
        let client = RecordingAnchorClient::default();

        let tx = anchor_delete_object_manifest_root(
            &client,
            [1u8; 32],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )
        .await
        .unwrap();

        assert_eq!(tx, "delete-root");
        assert_eq!(client.delete_calls.load(Ordering::SeqCst), 1);
        assert_eq!(client.put_calls.load(Ordering::SeqCst), 0);
    }
}
