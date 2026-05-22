use anyhow::{Result, bail};
use async_trait::async_trait;
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use bytes::Bytes;
use common::types::{
    AccessKeyHash, AwsPrincipal, ChainBucketRecord, ChainRegistryEntry, SubstrateAddress32,
};
use gateway::{
    app_state::AppState,
    auth::sigv4::RegistryBackedSigV4Validator,
    bee::client::{BeePutBytesResult, BeeStorage, FeedPointerResult},
    crypto::{
        bucket_name_hash, decrypt_blob, derive_private_object_index_key,
        derive_private_object_payload_key, private_object_key_id,
    },
    manifest::{read_private_bucket_manifest_v2, read_private_object_manifest_v2},
    routes::{private_object_read::private_object_payload_aad, put_object},
    traits::{AnchorClient, RegistryClient, SecretUnwrapper},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct MockBeeStorage {
    inner: Mutex<MockBeeInner>,
}

#[derive(Default)]
struct MockBeeInner {
    bytes: HashMap<String, Bytes>,
    put_calls: Vec<String>,
    next_reference_byte: u8,
}

impl MockBeeStorage {
    fn insert_bytes(&self, reference: String, bytes: Bytes) {
        self.inner.lock().unwrap().bytes.insert(reference, bytes);
    }

    fn get_stored_bytes(&self, reference: &str) -> Option<Bytes> {
        self.inner.lock().unwrap().bytes.get(reference).cloned()
    }

    fn put_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().put_calls.clone()
    }
}

#[async_trait]
impl BeeStorage for MockBeeStorage {
    async fn get_bytes(&self, reference: &str) -> Result<Option<Bytes>> {
        Ok(self.inner.lock().unwrap().bytes.get(reference).cloned())
    }

    async fn put_bytes(&self, data: Bytes) -> Result<BeePutBytesResult> {
        let mut inner = self.inner.lock().unwrap();

        inner.next_reference_byte = inner.next_reference_byte.wrapping_add(1);
        if inner.next_reference_byte == 0 {
            inner.next_reference_byte = 1;
        }

        let reference = hex::encode([inner.next_reference_byte; 32]);
        inner.put_calls.push(reference.clone());
        inner.bytes.insert(reference.clone(), data);

        Ok(BeePutBytesResult { reference })
    }

    async fn get_pointer_bytes(&self, _topic: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn put_object_and_update_pointer(
        &self,
        _bucket: &str,
        _key: &str,
        _data: Bytes,
    ) -> Result<FeedPointerResult> {
        bail!("put_object_and_update_pointer should not be used by private PUT")
    }
}

struct MockRegistryClient {
    bucket: ChainBucketRecord,
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn fetch_entry(&self, _access_key_hash: AccessKeyHash) -> Result<ChainRegistryEntry> {
        bail!("fetch_entry should not be used by direct private PUT route test")
    }

    async fn fetch_bucket(&self, _bucket_name_hash: [u8; 32]) -> Result<Option<ChainBucketRecord>> {
        Ok(Some(self.bucket.clone()))
    }

    async fn fetch_owner_catalog_root(&self, _owner: SubstrateAddress32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

struct MockSecretUnwrapper;

#[async_trait]
impl SecretUnwrapper for MockSecretUnwrapper {
    async fn unwrap_sigv4_secret(
        &self,
        _key_version: u32,
        _nonce: &[u8],
        _ciphertext: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>> {
        bail!("unwrap_sigv4_secret should not be used by direct private PUT route test")
    }
}

#[derive(Debug, Clone)]
struct AnchorSubmitRecord {
    owner: SubstrateAddress32,
    bucket_id: [u8; 32],
    object_key_id: [u8; 32],
    swarm_ref: String,
    bucket_manifest_root: String,
    size: u64,
    etag: [u8; 32],
}

#[derive(Default)]
struct RecordingAnchorClient {
    submit: Mutex<Option<AnchorSubmitRecord>>,
}

impl RecordingAnchorClient {
    fn submitted(&self) -> Option<AnchorSubmitRecord> {
        self.submit.lock().unwrap().clone()
    }
}

#[async_trait]
impl AnchorClient for RecordingAnchorClient {
    async fn create_bucket_anchor(
        &self,
        _owner: SubstrateAddress32,
        _bucket_id: [u8; 32],
        _is_private: bool,
        _owner_signature: [u8; 64],
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("create_bucket_anchor should not be used by private PUT")
    }

    async fn delete_bucket_anchor(
        &self,
        _bucket_id: [u8; 32],
        _owner_signature: [u8; 64],
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("delete_bucket_anchor should not be used by private PUT")
    }

    async fn update_bucket_manifest_root_for_put_anchor(
        &self,
        _bucket_id: [u8; 32],
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("update_bucket_manifest_root_for_put_anchor should not be called directly here")
    }

    async fn update_bucket_manifest_root_for_delete_anchor(
        &self,
        _bucket_id: [u8; 32],
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("delete anchor must not be used by private PUT")
    }

    async fn submit_anchor_object(
        &self,
        owner: SubstrateAddress32,
        bucket_id: [u8; 32],
        object_key_id: [u8; 32],
        swarm_ref: String,
        bucket_manifest_root: String,
        size: u64,
        etag: [u8; 32],
    ) -> Result<String> {
        *self.submit.lock().unwrap() = Some(AnchorSubmitRecord {
            owner,
            bucket_id,
            object_key_id,
            swarm_ref,
            bucket_manifest_root,
            size,
            etag,
        });

        Ok("mock-private-put-anchor-tx".to_string())
    }
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn build_state(
    bee: Arc<MockBeeStorage>,
    anchor: Arc<RecordingAnchorClient>,
    chain_bucket: ChainBucketRecord,
    master_service_key: [u8; 32],
) -> AppState {
    let registry: Arc<dyn RegistryClient> = Arc::new(MockRegistryClient {
        bucket: chain_bucket,
    });
    let unwrapper: Arc<dyn SecretUnwrapper> = Arc::new(MockSecretUnwrapper);
    let bee_client: Arc<dyn BeeStorage> = bee;
    let anchor_client: Arc<dyn AnchorClient> = anchor;

    let sigv4_validator = Arc::new(RegistryBackedSigV4Validator {
        registry: registry.clone(),
        unwrapper: unwrapper.clone(),
        expected_service: "s3".to_string(),
        expected_region: Some("us-east-1".to_string()),
        allow_unsigned_payload: false,
    });

    AppState {
        sigv4_validator,
        registry_client: registry,
        secret_unwrapper: unwrapper,
        bee_client,
        anchor_client,
        master_service_key,
        identity_contract_address: None,
        bucket_contract_address: None,
    }
}

#[tokio::test]
async fn private_put_encrypts_payload_writes_manifests_anchors_and_hides_swarm_ref() -> Result<()> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "private-bucket".to_string();
    let key = "secret.txt".to_string();
    let body = Bytes::from_static(b"private put payload");
    let encryption_version = 1u32;

    let private_index_key =
        derive_private_object_index_key(&master_service_key, &owner, &bucket, encryption_version);
    let expected_object_key_id = private_object_key_id(&private_index_key, &key);
    let expected_bucket_id = bucket_name_hash(&owner, &bucket);
    let expected_etag = sha256_32(&body);

    let chain_bucket = ChainBucketRecord {
        owner,
        is_private: true,
        encryption_version,
        creation_date: 0,
        bucket_manifest_root: Vec::new(),
    };

    let bee = Arc::new(MockBeeStorage::default());
    let anchor = Arc::new(RecordingAnchorClient::default());

    let state = build_state(
        bee.clone(),
        anchor.clone(),
        chain_bucket,
        master_service_key,
    );

    let principal = AwsPrincipal {
        access_key_id: "test-access-key".to_string(),
        owner,
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

    let response = put_object::handle(
        Path((bucket.clone(), key.clone())),
        Extension(principal),
        State(state),
        headers,
        body.clone(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("x-amz-meta-swarm-ref").is_none(),
        "private PUT must not expose encrypted payload Swarm reference"
    );

    let submitted = anchor
        .submitted()
        .expect("private PUT must submit an anchor record");

    assert_eq!(submitted.owner, owner);
    assert_eq!(submitted.bucket_id, expected_bucket_id);
    assert_eq!(submitted.object_key_id, expected_object_key_id);
    assert_eq!(submitted.size, body.len() as u64);
    assert_eq!(submitted.etag, expected_etag);

    let put_calls = bee.put_calls();
    assert_eq!(
        put_calls.len(),
        3,
        "private PUT should upload encrypted payload, object manifest, and bucket manifest"
    );
    assert_eq!(submitted.swarm_ref, put_calls[0]);
    assert_eq!(submitted.bucket_manifest_root, put_calls[2]);

    let encrypted_payload = bee
        .get_stored_bytes(&submitted.swarm_ref)
        .expect("encrypted payload bytes must be stored in Bee");

    assert_ne!(
        encrypted_payload.as_ref(),
        body.as_ref(),
        "private payload must not be stored as plaintext"
    );

    let payload_key = derive_private_object_payload_key(
        &master_service_key,
        &owner,
        &bucket,
        &expected_object_key_id,
        encryption_version,
    );
    let payload_aad =
        private_object_payload_aad(&owner, &bucket, &expected_object_key_id, encryption_version);
    let decrypted_payload = decrypt_blob(&payload_key, &payload_aad, &encrypted_payload)?;

    assert_eq!(decrypted_payload, body.as_ref());

    let bucket_root_bytes = hex::decode(&submitted.bucket_manifest_root)?;
    let bucket_manifest_record = read_private_bucket_manifest_v2(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &bucket,
        encryption_version,
        &bucket_root_bytes,
    )
    .await?
    .expect("private bucket manifest must be readable");

    let bucket_entry = bucket_manifest_record
        .manifest
        .objects
        .get(&hex::encode(expected_object_key_id))
        .expect("private bucket manifest must contain object entry");

    assert_eq!(bucket_entry.object_key, key);
    assert_eq!(bucket_entry.object_key_id, expected_object_key_id);
    assert_eq!(bucket_entry.encryption_version, encryption_version);
    assert_eq!(bucket_entry.size, body.len() as u64);

    let object_manifest_record = read_private_object_manifest_v2(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &bucket,
        &expected_object_key_id,
        encryption_version,
        &bucket_entry.object_manifest_reference,
    )
    .await?
    .expect("private object manifest must be readable");

    assert_eq!(
        object_manifest_record.manifest.encrypted_swarm_reference,
        submitted.swarm_ref
    );
    assert_eq!(
        object_manifest_record.manifest.object_key_id,
        expected_object_key_id
    );
    assert_eq!(
        object_manifest_record.manifest.encryption_version,
        encryption_version
    );

    Ok(())
}

#[tokio::test]
async fn private_put_does_not_anchor_when_existing_bucket_manifest_cannot_decrypt() -> Result<()> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "private-bucket".to_string();
    let key = "secret.txt".to_string();
    let body = Bytes::from_static(b"private put payload");
    let encryption_version = 1u32;

    let corrupt_bucket_manifest_reference = hex::encode([211u8; 32]);

    let chain_bucket = ChainBucketRecord {
        owner,
        is_private: true,
        encryption_version,
        creation_date: 0,
        bucket_manifest_root: hex::decode(&corrupt_bucket_manifest_reference)?,
    };

    let bee = Arc::new(MockBeeStorage::default());
    bee.insert_bytes(
        corrupt_bucket_manifest_reference,
        Bytes::from_static(b"not-a-valid-encrypted-private-bucket-manifest"),
    );

    let anchor = Arc::new(RecordingAnchorClient::default());

    let state = build_state(
        bee.clone(),
        anchor.clone(),
        chain_bucket,
        master_service_key,
    );

    let principal = AwsPrincipal {
        access_key_id: "test-access-key".to_string(),
        owner,
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

    let response = put_object::handle(
        Path((bucket, key)),
        Extension(principal),
        State(state),
        headers,
        body,
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        response.headers().get("x-amz-meta-swarm-ref").is_none(),
        "failed private PUT must not expose an encrypted Swarm reference"
    );
    assert!(
        anchor.submitted().is_none(),
        "private PUT must not anchor a new object when existing bucket manifest cannot decrypt"
    );

    let put_calls = bee.put_calls();
    assert!(
        put_calls.len() < 3,
        "private PUT must not write a replacement bucket manifest after decrypt failure"
    );

    Ok(())
}
