use anyhow::{Result, bail};
use async_trait::async_trait;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
};
use bytes::Bytes;
use common::types::{
    AccessKeyHash, AwsPrincipal, ChainBucketRecord, ChainBucketType, ChainRegistryEntry,
    SubstrateAddress32,
};
use gateway::{
    app_state::AppState,
    auth::sigv4::RegistryBackedSigV4Validator,
    bee::client::{BeePutBytesResult, BeeStorage, FeedPointerResult},
    crypto::{bucket_name_hash, derive_private_object_index_key, private_object_key_id},
    manifest::{
        PrivateBucketManifestV2, PrivateBucketObjectEntry, read_private_bucket_manifest_v2,
        write_private_bucket_manifest_v2,
    },
    routes::delete_object,
    traits::{AnchorClient, RegistryClient, SecretUnwrapper},
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct MockBeeStorage {
    inner: Mutex<MockBeeInner>,
}

#[derive(Default)]
struct MockBeeInner {
    bytes: HashMap<String, Bytes>,
    get_calls: Vec<String>,
    put_calls: Vec<String>,
    next_reference_byte: u8,
}

impl MockBeeStorage {
    fn insert_bytes(&self, reference: String, bytes: Bytes) {
        self.inner.lock().unwrap().bytes.insert(reference, bytes);
    }

    fn clear_calls(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.get_calls.clear();
        inner.put_calls.clear();
    }

    fn get_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().get_calls.clone()
    }

    fn put_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().put_calls.clone()
    }
}

#[async_trait]
impl BeeStorage for MockBeeStorage {
    async fn get_bytes(&self, reference: &str) -> Result<Option<Bytes>> {
        let mut inner = self.inner.lock().unwrap();
        inner.get_calls.push(reference.to_string());
        Ok(inner.bytes.get(reference).cloned())
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
        bail!("put_object_and_update_pointer should not be used by private DELETE")
    }
}

struct MockRegistryClient {
    bucket: ChainBucketRecord,
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn fetch_entry(&self, _access_key_hash: AccessKeyHash) -> Result<ChainRegistryEntry> {
        bail!("fetch_entry should not be used by direct private DELETE route test")
    }

    async fn fetch_bucket(&self, _bucket_name_hash: [u8; 32]) -> Result<Option<ChainBucketRecord>> {
        Ok(Some(self.bucket.clone()))
    }

    async fn fetch_bucket_type(
        &self,
        _bucket_name_hash: [u8; 32],
    ) -> Result<Option<ChainBucketType>> {
        Ok(None)
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
        bail!("unwrap_sigv4_secret should not be used by direct private DELETE route test")
    }
}

#[derive(Debug, Clone)]
struct DeleteAnchorRecord {
    bucket_id: [u8; 32],
    expected_bucket_manifest_root: String,
    bucket_manifest_root: String,
}

#[derive(Default)]
struct RecordingAnchorClient {
    delete_call: Mutex<Option<DeleteAnchorRecord>>,
    put_anchor_calls: Mutex<usize>,
}

impl RecordingAnchorClient {
    fn delete_call(&self) -> Option<DeleteAnchorRecord> {
        self.delete_call.lock().unwrap().clone()
    }

    fn put_anchor_calls(&self) -> usize {
        *self.put_anchor_calls.lock().unwrap()
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
        _expected_owner_catalog_root: String,
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("create_bucket_anchor should not be used by private DELETE")
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
    ) -> Result<String> {
        bail!("delete_bucket_anchor should not be used by private DELETE object")
    }

    async fn update_bucket_manifest_root_for_put_anchor(
        &self,
        _bucket_id: [u8; 32],
        _expected_bucket_manifest_root: String,
        _bucket_manifest_root: String,
    ) -> Result<String> {
        *self.put_anchor_calls.lock().unwrap() += 1;
        bail!("put anchor must not be used by private DELETE")
    }

    async fn update_bucket_manifest_root_for_delete_anchor(
        &self,
        bucket_id: [u8; 32],
        expected_bucket_manifest_root: String,
        bucket_manifest_root: String,
    ) -> Result<String> {
        *self.delete_call.lock().unwrap() = Some(DeleteAnchorRecord {
            bucket_id,
            expected_bucket_manifest_root,
            bucket_manifest_root,
        });

        Ok("mock-private-delete-anchor-tx".to_string())
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
    ) -> Result<String> {
        bail!("submit_anchor_object should not be used by private DELETE")
    }
}

struct PrivateDeleteFixture {
    state: AppState,
    bee: Arc<MockBeeStorage>,
    anchor: Arc<RecordingAnchorClient>,
    principal: AwsPrincipal,
    owner: SubstrateAddress32,
    bucket: String,
    delete_key: String,
    keep_key: String,
    delete_object_key_id: [u8; 32],
    keep_object_key_id: [u8; 32],
    bucket_manifest_reference: String,
    delete_object_manifest_reference: String,
    expected_bucket_id: [u8; 32],
    encryption_version: u32,
    master_service_key: [u8; 32],
}

async fn private_delete_fixture() -> Result<PrivateDeleteFixture> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "private-bucket".to_string();
    let delete_key = "delete-me.txt".to_string();
    let keep_key = "keep-me.txt".to_string();
    let encryption_version = 1u32;

    let bee = Arc::new(MockBeeStorage::default());
    let anchor = Arc::new(RecordingAnchorClient::default());

    let private_index_key =
        derive_private_object_index_key(&master_service_key, &owner, &bucket, encryption_version);

    let delete_object_key_id = private_object_key_id(&private_index_key, &delete_key);
    let keep_object_key_id = private_object_key_id(&private_index_key, &keep_key);

    let delete_object_manifest_reference = hex::encode([90u8; 32]);
    let keep_object_manifest_reference = hex::encode([91u8; 32]);

    let mut objects = BTreeMap::new();

    objects.insert(
        hex::encode(delete_object_key_id),
        PrivateBucketObjectEntry {
            object_key: delete_key.clone(),
            object_key_id: delete_object_key_id,
            object_manifest_reference: delete_object_manifest_reference.clone(),
            encryption_version,
            size: 111,
            etag: "etag-delete-me".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-05-14T00:00:00Z".to_string(),
        },
    );

    objects.insert(
        hex::encode(keep_object_key_id),
        PrivateBucketObjectEntry {
            object_key: keep_key.clone(),
            object_key_id: keep_object_key_id,
            object_manifest_reference: keep_object_manifest_reference,
            encryption_version,
            size: 222,
            etag: "etag-keep-me".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-05-14T00:00:01Z".to_string(),
        },
    );

    let initial_manifest = PrivateBucketManifestV2 { objects };

    let initial_record = write_private_bucket_manifest_v2(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &bucket,
        encryption_version,
        &initial_manifest,
    )
    .await?;

    let bucket_manifest_root = hex::decode(&initial_record.manifest_reference)?;
    let expected_bucket_id = bucket_name_hash(&owner, &bucket);

    let chain_bucket = ChainBucketRecord {
        owner,
        is_private: true,
        encryption_version,
        creation_date: 0,
        bucket_manifest_root,
    };

    let registry: Arc<dyn RegistryClient> = Arc::new(MockRegistryClient {
        bucket: chain_bucket,
    });
    let unwrapper: Arc<dyn SecretUnwrapper> = Arc::new(MockSecretUnwrapper);
    let bee_client: Arc<dyn BeeStorage> = bee.clone();
    let anchor_client: Arc<dyn AnchorClient> = anchor.clone();

    let sigv4_validator = Arc::new(RegistryBackedSigV4Validator {
        registry: registry.clone(),
        unwrapper: unwrapper.clone(),
        expected_service: "s3".to_string(),
        expected_region: Some("us-east-1".to_string()),
        allow_unsigned_payload: false,
    });

    let state = AppState {
        sigv4_validator,
        registry_client: registry,
        secret_unwrapper: unwrapper,
        bee_client,
        anchor_client,
        master_service_key,
        identity_contract_address: None,
        bucket_contract_address: None,
    };

    bee.clear_calls();

    Ok(PrivateDeleteFixture {
        state,
        bee,
        anchor,
        principal: AwsPrincipal {
            access_key_id: "test-access-key".to_string(),
            owner,
        },
        owner,
        bucket,
        delete_key,
        keep_key,
        delete_object_key_id,
        keep_object_key_id,
        bucket_manifest_reference: initial_record.manifest_reference,
        delete_object_manifest_reference,
        expected_bucket_id,
        encryption_version,
        master_service_key,
    })
}

#[tokio::test]
async fn private_delete_removes_entry_writes_manifest_and_uses_delete_anchor() -> Result<()> {
    let fixture = private_delete_fixture().await?;

    let response = delete_object::handle(
        Path((fixture.bucket.clone(), fixture.delete_key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let get_calls = fixture.bee.get_calls();
    assert_eq!(
        get_calls,
        vec![fixture.bucket_manifest_reference.clone()],
        "private DELETE should only read the encrypted private bucket manifest"
    );
    assert!(
        !get_calls.contains(&fixture.delete_object_manifest_reference),
        "private DELETE must not fetch the private object manifest or payload"
    );

    let put_calls = fixture.bee.put_calls();
    assert_eq!(
        put_calls.len(),
        1,
        "private DELETE should write exactly one updated private bucket manifest"
    );

    let delete_anchor = fixture
        .anchor
        .delete_call()
        .expect("private DELETE must update the delete manifest root anchor");

    assert_eq!(delete_anchor.bucket_id, fixture.expected_bucket_id);
    assert_eq!(
        delete_anchor.expected_bucket_manifest_root, fixture.bucket_manifest_reference,
        "private DELETE must CAS against the bucket manifest root it read"
    );
    assert_eq!(delete_anchor.bucket_manifest_root, put_calls[0]);
    assert_eq!(fixture.anchor.put_anchor_calls(), 0);

    let new_root_bytes = hex::decode(&delete_anchor.bucket_manifest_root)?;
    let updated_manifest = read_private_bucket_manifest_v2(
        fixture.bee.as_ref(),
        &fixture.master_service_key,
        &fixture.owner,
        &fixture.bucket,
        fixture.encryption_version,
        &new_root_bytes,
    )
    .await?
    .expect("updated private bucket manifest must be readable");

    assert!(
        !updated_manifest
            .manifest
            .objects
            .contains_key(&hex::encode(fixture.delete_object_key_id)),
        "deleted object entry must be removed from private bucket manifest"
    );

    let kept_entry = updated_manifest
        .manifest
        .objects
        .get(&hex::encode(fixture.keep_object_key_id))
        .expect("non-deleted object entry must remain");

    assert_eq!(kept_entry.object_key, fixture.keep_key);

    Ok(())
}

#[tokio::test]
async fn private_delete_does_not_write_or_anchor_when_bucket_manifest_cannot_decrypt() -> Result<()>
{
    let fixture = private_delete_fixture().await?;

    fixture.bee.insert_bytes(
        fixture.bucket_manifest_reference.clone(),
        Bytes::from_static(b"not-a-valid-encrypted-private-bucket-manifest"),
    );

    let response = delete_object::handle(
        Path((fixture.bucket.clone(), fixture.delete_key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let get_calls = fixture.bee.get_calls();
    assert_eq!(
        get_calls,
        vec![fixture.bucket_manifest_reference.clone()],
        "private DELETE should stop at the undecryptable bucket manifest"
    );
    assert!(
        !get_calls.contains(&fixture.delete_object_manifest_reference),
        "private DELETE must not fetch object manifests when bucket manifest cannot decrypt"
    );

    assert!(
        fixture.bee.put_calls().is_empty(),
        "private DELETE must not write a replacement bucket manifest after decrypt failure"
    );
    assert!(
        fixture.anchor.delete_call().is_none(),
        "private DELETE must not anchor a new bucket manifest root after decrypt failure"
    );
    assert_eq!(
        fixture.anchor.put_anchor_calls(),
        0,
        "private DELETE must not use put anchor path after decrypt failure"
    );

    Ok(())
}
