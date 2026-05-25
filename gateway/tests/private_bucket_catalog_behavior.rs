use anyhow::{Result, bail};
use async_trait::async_trait;
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
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
    crypto::bucket_name_hash,
    manifest::{
        PrivateBucketManifestV2, PrivateBucketObjectEntry, RootCatalogManifest,
        read_owner_catalog_manifest, write_owner_catalog_manifest,
        write_private_bucket_manifest_v2,
    },
    routes::{create_bucket, delete_bucket},
    traits::{AnchorClient, RegistryClient, SecretUnwrapper},
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

const OWNER_SIGNATURE_HEADER: &str = "x-s3gw-owner-signature";
const BUCKET_VISIBILITY_HEADER: &str = "x-s3gw-bucket-visibility";
const BUCKET_TYPE_HEADER: &str = "x-s3gw-bucket-type";
const EXPECTED_OWNER_CATALOG_ROOT_HEADER: &str = "x-s3gw-expected-owner-catalog-root";
const OWNER_CATALOG_ROOT_HEADER: &str = "x-s3gw-owner-catalog-root";

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
        bail!("put_object_and_update_pointer should not be used by bucket catalog tests")
    }
}

#[derive(Clone)]
struct MockRegistryClient {
    bucket: Option<ChainBucketRecord>,
    owner_catalog_root: Vec<u8>,
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn fetch_entry(&self, _access_key_hash: AccessKeyHash) -> Result<ChainRegistryEntry> {
        bail!("fetch_entry should not be used by direct bucket catalog route tests")
    }

    async fn fetch_bucket(&self, _bucket_name_hash: [u8; 32]) -> Result<Option<ChainBucketRecord>> {
        Ok(self.bucket.clone())
    }

    async fn fetch_bucket_type(
        &self,
        _bucket_name_hash: [u8; 32],
    ) -> Result<Option<ChainBucketType>> {
        Ok(None)
    }

    async fn fetch_owner_catalog_root(&self, _owner: SubstrateAddress32) -> Result<Vec<u8>> {
        Ok(self.owner_catalog_root.clone())
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
        bail!("unwrap_sigv4_secret should not be used by direct bucket catalog route tests")
    }
}

#[derive(Debug, Clone)]
struct CreateBucketAnchorRecord {
    owner: SubstrateAddress32,
    bucket_id: [u8; 32],
    is_private: bool,
    owner_signature: [u8; 64],
    expected_owner_catalog_root: String,
    owner_catalog_root: String,
}

#[derive(Debug, Clone)]
struct TrustlessCreateBucketAnchorRecord {
    owner: SubstrateAddress32,
    bucket_id: [u8; 32],
    owner_signature: [u8; 64],
    expected_owner_catalog_root: String,
    owner_catalog_root: String,
}

#[derive(Debug, Clone)]
struct DeleteBucketAnchorRecord {
    bucket_id: [u8; 32],
    owner_signature: [u8; 64],
    expected_owner_catalog_root: String,
    owner_catalog_root: String,
}

#[derive(Default)]
struct RecordingAnchorClient {
    create_call: Mutex<Option<CreateBucketAnchorRecord>>,
    trustless_create_call: Mutex<Option<TrustlessCreateBucketAnchorRecord>>,
    delete_call: Mutex<Option<DeleteBucketAnchorRecord>>,
}

impl RecordingAnchorClient {
    fn create_call(&self) -> Option<CreateBucketAnchorRecord> {
        self.create_call.lock().unwrap().clone()
    }

    fn trustless_create_call(&self) -> Option<TrustlessCreateBucketAnchorRecord> {
        self.trustless_create_call.lock().unwrap().clone()
    }

    fn delete_call(&self) -> Option<DeleteBucketAnchorRecord> {
        self.delete_call.lock().unwrap().clone()
    }
}

#[async_trait]
impl AnchorClient for RecordingAnchorClient {
    async fn create_bucket_anchor(
        &self,
        owner: SubstrateAddress32,
        bucket_id: [u8; 32],
        is_private: bool,
        owner_signature: [u8; 64],
        expected_owner_catalog_root: String,
        owner_catalog_root: String,
    ) -> Result<String> {
        *self.create_call.lock().unwrap() = Some(CreateBucketAnchorRecord {
            owner,
            bucket_id,
            is_private,
            owner_signature,
            expected_owner_catalog_root,
            owner_catalog_root,
        });

        Ok("mock-create-bucket-anchor-tx".to_string())
    }

    async fn create_trustless_bucket_anchor(
        &self,
        owner: SubstrateAddress32,
        bucket_id: [u8; 32],
        owner_signature: [u8; 64],
        expected_owner_catalog_root: String,
        owner_catalog_root: String,
    ) -> anyhow::Result<String> {
        *self.trustless_create_call.lock().unwrap() = Some(TrustlessCreateBucketAnchorRecord {
            owner,
            bucket_id,
            owner_signature,
            expected_owner_catalog_root,
            owner_catalog_root,
        });

        Ok("mock-create-trustless-bucket-anchor-tx".to_string())
    }

    async fn delete_bucket_anchor(
        &self,
        bucket_id: [u8; 32],
        owner_signature: [u8; 64],
        expected_owner_catalog_root: String,
        owner_catalog_root: String,
    ) -> Result<String> {
        *self.delete_call.lock().unwrap() = Some(DeleteBucketAnchorRecord {
            bucket_id,
            owner_signature,
            expected_owner_catalog_root,
            owner_catalog_root,
        });

        Ok("mock-delete-bucket-anchor-tx".to_string())
    }

    async fn update_bucket_manifest_root_for_put_anchor(
        &self,
        _bucket_id: [u8; 32],
        _expected_bucket_manifest_root: String,
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("put object manifest-root anchor should not be used by bucket catalog tests")
    }

    async fn update_bucket_manifest_root_for_delete_anchor(
        &self,
        _bucket_id: [u8; 32],
        _expected_bucket_manifest_root: String,
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("delete object manifest-root anchor should not be used by bucket catalog tests")
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
        bail!("submit_anchor_object should not be used by bucket catalog tests")
    }
}

fn owner_signature() -> [u8; 64] {
    [77u8; 64]
}

fn headers_with_owner_signature() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        OWNER_SIGNATURE_HEADER,
        HeaderValue::from_str(&format!("0x{}", hex::encode(owner_signature()))).unwrap(),
    );
    headers
}

fn private_create_headers() -> HeaderMap {
    let mut headers = headers_with_owner_signature();
    headers.insert(
        BUCKET_VISIBILITY_HEADER,
        HeaderValue::from_static("private"),
    );
    headers
}

fn trustless_create_headers(
    expected_owner_catalog_root: &str,
    owner_catalog_root: &str,
) -> HeaderMap {
    let mut headers = headers_with_owner_signature();
    headers.insert(
        BUCKET_TYPE_HEADER,
        HeaderValue::from_static("trustless-private"),
    );
    headers.insert(
        EXPECTED_OWNER_CATALOG_ROOT_HEADER,
        HeaderValue::from_str(expected_owner_catalog_root).unwrap(),
    );
    headers.insert(
        OWNER_CATALOG_ROOT_HEADER,
        HeaderValue::from_str(owner_catalog_root).unwrap(),
    );
    headers
}

fn build_state(
    bee: Arc<MockBeeStorage>,
    anchor: Arc<RecordingAnchorClient>,
    registry: MockRegistryClient,
    master_service_key: [u8; 32],
) -> AppState {
    let registry: Arc<dyn RegistryClient> = Arc::new(registry);
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

async fn write_catalog_root(
    bee: &MockBeeStorage,
    master_service_key: &[u8; 32],
    owner: &SubstrateAddress32,
    catalog: &RootCatalogManifest,
) -> Result<String> {
    Ok(
        write_owner_catalog_manifest(bee, master_service_key, owner, catalog)
            .await?
            .manifest_reference,
    )
}

async fn read_catalog_root(
    bee: &MockBeeStorage,
    master_service_key: &[u8; 32],
    owner: &SubstrateAddress32,
    root: &str,
) -> Result<RootCatalogManifest> {
    let root_bytes = hex::decode(root)?;
    read_owner_catalog_manifest(bee, master_service_key, owner, &root_bytes).await
}

#[tokio::test]
async fn private_create_bucket_writes_owner_catalog_and_create_anchor() -> Result<()> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "private-bucket".to_string();
    let existing_bucket = "existing-bucket".to_string();

    let bee = Arc::new(MockBeeStorage::default());
    let anchor = Arc::new(RecordingAnchorClient::default());

    let mut initial_catalog = RootCatalogManifest::default();
    initial_catalog
        .buckets
        .insert(existing_bucket.clone(), "existing-root".to_string());

    let initial_root =
        write_catalog_root(bee.as_ref(), &master_service_key, &owner, &initial_catalog).await?;

    bee.clear_calls();

    let state = build_state(
        bee.clone(),
        anchor.clone(),
        MockRegistryClient {
            bucket: None,
            owner_catalog_root: hex::decode(&initial_root)?,
        },
        master_service_key,
    );

    let principal = AwsPrincipal {
        access_key_id: "test-access-key".to_string(),
        owner,
    };

    let response = create_bucket::handle(
        Path(bucket.clone()),
        Extension(principal),
        State(state),
        private_create_headers(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let create_anchor = anchor
        .create_call()
        .expect("private create bucket must call create_bucket_anchor");

    assert_eq!(create_anchor.owner, owner);
    assert_eq!(create_anchor.bucket_id, bucket_name_hash(&owner, &bucket));
    assert!(create_anchor.is_private);
    assert_eq!(create_anchor.owner_signature, owner_signature());
    assert_eq!(
        create_anchor.expected_owner_catalog_root, initial_root,
        "private bucket create must CAS against the owner catalog root it read"
    );

    let put_calls = bee.put_calls();
    assert_eq!(
        put_calls,
        vec![create_anchor.owner_catalog_root.clone()],
        "private bucket create should write exactly one updated encrypted owner catalog"
    );

    let get_calls = bee.get_calls();
    assert_eq!(
        get_calls,
        vec![initial_root.clone()],
        "private bucket create should read the previous encrypted owner catalog root"
    );

    let updated_catalog = read_catalog_root(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &create_anchor.owner_catalog_root,
    )
    .await?;

    assert!(updated_catalog.buckets.contains_key(&existing_bucket));
    assert!(updated_catalog.buckets.contains_key(&bucket));

    Ok(())
}

#[tokio::test]
async fn trustless_create_bucket_uses_client_supplied_catalog_roots_without_bee_writes()
-> Result<()> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "trustless-bucket".to_string();
    let expected_owner_catalog_root = hex::encode([11u8; 32]);
    let owner_catalog_root = hex::encode([12u8; 32]);

    let bee = Arc::new(MockBeeStorage::default());
    let anchor = Arc::new(RecordingAnchorClient::default());

    let state = build_state(
        bee.clone(),
        anchor.clone(),
        MockRegistryClient {
            bucket: None,
            owner_catalog_root: vec![11u8; 32],
        },
        master_service_key,
    );

    let principal = AwsPrincipal {
        access_key_id: "test-access-key".to_string(),
        owner,
    };

    let response = create_bucket::handle(
        Path(bucket.clone()),
        Extension(principal),
        State(state),
        trustless_create_headers(&expected_owner_catalog_root, &owner_catalog_root),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    assert!(
        anchor.create_call().is_none(),
        "trustless bucket create must not call legacy create_bucket_anchor"
    );

    let trustless_anchor = anchor
        .trustless_create_call()
        .expect("trustless bucket create must call create_trustless_bucket_anchor");

    assert_eq!(trustless_anchor.owner, owner);
    assert_eq!(
        trustless_anchor.bucket_id,
        bucket_name_hash(&owner, &bucket)
    );
    assert_eq!(trustless_anchor.owner_signature, owner_signature());
    assert_eq!(
        trustless_anchor.expected_owner_catalog_root,
        expected_owner_catalog_root
    );
    assert_eq!(trustless_anchor.owner_catalog_root, owner_catalog_root);

    assert!(
        bee.get_calls().is_empty(),
        "trustless create must not read/decrypt an owner catalog through the gateway"
    );
    assert!(
        bee.put_calls().is_empty(),
        "trustless create must not write/encrypt an owner catalog through the gateway"
    );

    Ok(())
}

#[tokio::test]
async fn private_delete_empty_bucket_removes_owner_catalog_entry_and_delete_anchor() -> Result<()> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "private-bucket".to_string();
    let keep_bucket = "keep-bucket".to_string();
    let encryption_version = 1u32;

    let bee = Arc::new(MockBeeStorage::default());
    let anchor = Arc::new(RecordingAnchorClient::default());

    let mut initial_catalog = RootCatalogManifest::default();
    initial_catalog
        .buckets
        .insert(bucket.clone(), "bucket-root".to_string());
    initial_catalog
        .buckets
        .insert(keep_bucket.clone(), "keep-root".to_string());

    let initial_root =
        write_catalog_root(bee.as_ref(), &master_service_key, &owner, &initial_catalog).await?;

    bee.clear_calls();

    let chain_bucket = ChainBucketRecord {
        owner,
        is_private: true,
        encryption_version,
        creation_date: 0,
        bucket_manifest_root: Vec::new(),
    };

    let state = build_state(
        bee.clone(),
        anchor.clone(),
        MockRegistryClient {
            bucket: Some(chain_bucket),
            owner_catalog_root: hex::decode(&initial_root)?,
        },
        master_service_key,
    );

    let principal = AwsPrincipal {
        access_key_id: "test-access-key".to_string(),
        owner,
    };

    let response = delete_bucket::handle(
        Path(bucket.clone()),
        Extension(principal),
        State(state),
        headers_with_owner_signature(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let delete_anchor = anchor
        .delete_call()
        .expect("private delete bucket must call delete_bucket_anchor");

    assert_eq!(delete_anchor.bucket_id, bucket_name_hash(&owner, &bucket));
    assert_eq!(delete_anchor.owner_signature, owner_signature());
    assert_eq!(
        delete_anchor.expected_owner_catalog_root, initial_root,
        "private bucket delete must CAS against the owner catalog root it read"
    );

    let put_calls = bee.put_calls();
    assert_eq!(
        put_calls,
        vec![delete_anchor.owner_catalog_root.clone()],
        "private bucket delete should write exactly one updated encrypted owner catalog"
    );

    let get_calls = bee.get_calls();
    assert_eq!(
        get_calls,
        vec![initial_root.clone()],
        "empty private bucket delete should only read the previous encrypted owner catalog root"
    );

    let updated_catalog = read_catalog_root(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &delete_anchor.owner_catalog_root,
    )
    .await?;

    assert!(!updated_catalog.buckets.contains_key(&bucket));
    assert!(updated_catalog.buckets.contains_key(&keep_bucket));

    Ok(())
}

#[tokio::test]
async fn private_delete_non_empty_bucket_rejects_before_catalog_update_or_delete_anchor()
-> Result<()> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "private-bucket".to_string();
    let encryption_version = 1u32;

    let bee = Arc::new(MockBeeStorage::default());
    let anchor = Arc::new(RecordingAnchorClient::default());

    let mut private_objects = BTreeMap::new();
    private_objects.insert(
        hex::encode([9u8; 32]),
        PrivateBucketObjectEntry {
            object_key: "still-here.txt".to_string(),
            object_key_id: [9u8; 32],
            object_manifest_reference: hex::encode([10u8; 32]),
            encryption_version,
            size: 123,
            etag: "etag-still-here".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-05-14T00:00:00Z".to_string(),
        },
    );

    let private_manifest = PrivateBucketManifestV2 {
        objects: private_objects,
    };

    let private_manifest_record = write_private_bucket_manifest_v2(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &bucket,
        encryption_version,
        &private_manifest,
    )
    .await?;

    bee.clear_calls();

    let chain_bucket = ChainBucketRecord {
        owner,
        is_private: true,
        encryption_version,
        creation_date: 0,
        bucket_manifest_root: hex::decode(&private_manifest_record.manifest_reference)?,
    };

    let state = build_state(
        bee.clone(),
        anchor.clone(),
        MockRegistryClient {
            bucket: Some(chain_bucket),
            owner_catalog_root: Vec::new(),
        },
        master_service_key,
    );

    let principal = AwsPrincipal {
        access_key_id: "test-access-key".to_string(),
        owner,
    };

    let response = delete_bucket::handle(
        Path(bucket.clone()),
        Extension(principal),
        State(state),
        headers_with_owner_signature(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);

    assert!(
        anchor.delete_call().is_none(),
        "non-empty private bucket delete must not call delete_bucket_anchor"
    );

    assert!(
        bee.put_calls().is_empty(),
        "non-empty private bucket delete must not write an updated owner catalog"
    );

    assert_eq!(
        bee.get_calls(),
        vec![private_manifest_record.manifest_reference],
        "non-empty private bucket delete should only read the private bucket manifest"
    );

    Ok(())
}
