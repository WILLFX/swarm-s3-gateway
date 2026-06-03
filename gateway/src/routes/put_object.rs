use crate::{
    app_state::{AppState, ObjectMetadata},
    bee::client::BeeStorage,
    crypto::{
        bucket_name_hash, derive_private_object_index_key, derive_private_object_payload_key,
        encrypt_blob_random, private_object_key_id,
    },
    manifest::{
        read_private_bucket_manifest_v2, write_bucket_manifest, write_object_manifest,
        write_private_bucket_manifest_v2, write_private_object_manifest_v2, BucketManifest,
        ObjectManifest, PrivateBucketManifestV2, PrivateBucketObjectEntry, PrivateObjectManifestV2,
    },
    s3_response::{
        bee_error_response, bee_unavailable_response, chain_error_response,
        omit_swarm_ref_for_private_response, put_object_response, S3ErrorKind, S3ErrorResponse,
    },
};
use anyhow::{Context, Error as AnyhowError, Result};
use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    http::{header, HeaderMap},
    response::Response,
};
use common::types::{AwsPrincipal, ChainBucketRecord, ChainBucketType};
use reqwest::Error as ReqwestError;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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
        let bucket_type = match state.registry_client.fetch_bucket_type(bucket_id).await {
            Ok(value) => value,
            Err(err) => return chain_error_response(err),
        };

        match bucket_type {
            Some(ChainBucketType::TrustlessPrivate) => {
                return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                    .with_message(
                        "trustless private buckets cannot be written by the gateway; use the local trustless proxy",
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
        }
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

    let bucket_manifest_root = match write_public_manifests(
        state.bee_client.as_ref(),
        &bucket,
        &key,
        &metadata,
        &chain_bucket.bucket_manifest_root,
    )
    .await
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
            hex::encode(&chain_bucket.bucket_manifest_root),
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
    bee: &dyn BeeStorage,
    bucket: &str,
    key: &str,
    metadata: &ObjectMetadata,
    current_bucket_manifest_root: &[u8],
) -> Result<String> {
    let mut bucket_manifest =
        read_public_bucket_manifest_from_root(bee, current_bucket_manifest_root).await?;

    let object_manifest = ObjectManifest {
        swarm_reference: metadata.swarm_reference.clone(),
        size: metadata.size,
        etag: metadata.etag.clone(),
        content_type: metadata.content_type.clone(),
        last_modified: metadata.last_modified.clone(),
    };

    let object_record = write_object_manifest(bee, bucket, key, &object_manifest).await?;

    bucket_manifest
        .objects
        .insert(key.to_string(), object_record.manifest_reference);

    let bucket_record = write_bucket_manifest(bee, bucket, &bucket_manifest).await?;

    Ok(bucket_record.manifest_reference)
}

async fn read_public_bucket_manifest_from_root(
    bee: &dyn BeeStorage,
    bucket_manifest_root: &[u8],
) -> Result<BucketManifest> {
    if bucket_manifest_root.is_empty() {
        return Ok(BucketManifest::default());
    }

    if bucket_manifest_root.len() != 32 {
        anyhow::bail!(
            "bucket_manifest_root must be 32 bytes, got {}",
            bucket_manifest_root.len()
        );
    }

    let manifest_reference = hex::encode(bucket_manifest_root);

    let manifest_bytes = bee
        .get_bytes(&manifest_reference)
        .await?
        .context("anchored bucket manifest root not found in Swarm")?;

    serde_json::from_slice(&manifest_bytes).context("failed to decode bucket manifest JSON")
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
            hex::encode(&chain_bucket.bucket_manifest_root),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bee::client::{BeePutBytesResult, FeedPointerResult};
    use std::{collections::HashMap, sync::Mutex};

    #[derive(Default)]
    struct MockBeeStorage {
        inner: Mutex<MockBeeInner>,
    }

    #[derive(Default)]
    struct MockBeeInner {
        bytes: HashMap<String, Bytes>,
        pointer_payload: Option<Vec<u8>>,
        get_pointer_calls: usize,
    }

    impl MockBeeStorage {
        fn set_pointer_reference(&self, reference: &str) -> Result<()> {
            self.inner.lock().unwrap().pointer_payload = Some(hex::decode(reference)?);
            Ok(())
        }

        fn get_pointer_calls(&self) -> usize {
            self.inner.lock().unwrap().get_pointer_calls
        }

        fn stored_bytes_len(&self) -> usize {
            self.inner.lock().unwrap().bytes.len()
        }

        fn read_bucket_manifest(&self, reference: &str) -> BucketManifest {
            let inner = self.inner.lock().unwrap();
            let bytes = inner
                .bytes
                .get(reference)
                .expect("bucket manifest reference must be stored");

            serde_json::from_slice(bytes).expect("stored bucket manifest must decode")
        }
    }

    #[async_trait::async_trait]
    impl BeeStorage for MockBeeStorage {
        async fn get_bytes(&self, reference: &str) -> Result<Option<Bytes>> {
            Ok(self.inner.lock().unwrap().bytes.get(reference).cloned())
        }

        async fn put_bytes(&self, data: Bytes) -> Result<BeePutBytesResult> {
            let reference = hex::encode(sha256_32(&data));
            self.inner
                .lock()
                .unwrap()
                .bytes
                .insert(reference.clone(), data);
            Ok(BeePutBytesResult { reference })
        }

        async fn get_pointer_bytes(&self, _topic: [u8; 32]) -> Result<Option<Vec<u8>>> {
            let mut inner = self.inner.lock().unwrap();
            inner.get_pointer_calls += 1;
            Ok(inner.pointer_payload.clone())
        }

        async fn put_object_and_update_pointer(
            &self,
            _bucket: &str,
            _key: &str,
            data: Bytes,
        ) -> Result<FeedPointerResult> {
            let reference = hex::encode(sha256_32(&data));
            self.inner
                .lock()
                .unwrap()
                .bytes
                .insert(reference.clone(), data);

            Ok(FeedPointerResult {
                owner: "owner".to_string(),
                topic_hex: hex::encode([0u8; 32]),
                swarm_reference: reference.clone(),
                manifest_reference: reference.clone(),
                soc_reference: reference,
            })
        }
    }

    fn public_metadata(swarm_reference: &str) -> ObjectMetadata {
        ObjectMetadata {
            swarm_reference: swarm_reference.to_string(),
            size: 11,
            etag: "etag".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-06-04T00:00:00Z".to_string(),
            is_private: false,
            encryption_version: None,
        }
    }

    #[tokio::test]
    async fn public_manifest_write_uses_chain_root_not_bee_pointer() -> Result<()> {
        let bee = MockBeeStorage::default();

        let mut anchored_manifest = BucketManifest::default();
        anchored_manifest.objects.insert(
            "existing.txt".to_string(),
            "existing-object-manifest-ref".to_string(),
        );
        let anchored_record = write_bucket_manifest(&bee, "bucket", &anchored_manifest).await?;

        let mut poisoned_manifest = BucketManifest::default();
        poisoned_manifest
            .objects
            .insert("stale.txt".to_string(), "stale-ref".to_string());
        let poisoned_record = write_bucket_manifest(&bee, "bucket", &poisoned_manifest).await?;
        bee.set_pointer_reference(&poisoned_record.manifest_reference)?;

        let current_root = hex::decode(&anchored_record.manifest_reference)?;
        let new_root = write_public_manifests(
            &bee,
            "bucket",
            "new.txt",
            &public_metadata("new-object-ref"),
            &current_root,
        )
        .await?;

        let updated_manifest = bee.read_bucket_manifest(&new_root);
        assert_eq!(
            updated_manifest.objects.get("existing.txt"),
            Some(&"existing-object-manifest-ref".to_string())
        );
        assert!(updated_manifest.objects.contains_key("new.txt"));
        assert!(!updated_manifest.objects.contains_key("stale.txt"));
        assert_eq!(bee.get_pointer_calls(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn public_manifest_write_allows_empty_chain_root() -> Result<()> {
        let bee = MockBeeStorage::default();

        let new_root = write_public_manifests(
            &bee,
            "bucket",
            "new.txt",
            &public_metadata("new-object-ref"),
            &[],
        )
        .await?;

        let updated_manifest = bee.read_bucket_manifest(&new_root);
        assert_eq!(updated_manifest.objects.len(), 1);
        assert!(updated_manifest.objects.contains_key("new.txt"));
        assert_eq!(bee.get_pointer_calls(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn public_manifest_write_rejects_malformed_chain_root_before_writes() {
        let bee = MockBeeStorage::default();

        let error = write_public_manifests(
            &bee,
            "bucket",
            "new.txt",
            &public_metadata("new-object-ref"),
            &[1, 2, 3],
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("bucket_manifest_root must be 32 bytes"));
        assert_eq!(bee.stored_bytes_len(), 0);
        assert_eq!(bee.get_pointer_calls(), 0);
    }
}
