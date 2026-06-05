use anyhow::{bail, Result};
use async_trait::async_trait;
use axum::{
    body::to_bytes,
    extract::{Extension, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
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
    manifest::BucketManifest,
    routes::{
        get_object,
        list_objects_v2::{self, ListObjectsV2Query},
        put_object,
    },
    traits::{AnchorClient, RegistryClient, SecretUnwrapper},
};
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
    fn put_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().put_calls.clone()
    }

    fn read_bucket_manifest(&self, reference: &str) -> BucketManifest {
        let inner = self.inner.lock().unwrap();
        let bytes = inner
            .bytes
            .get(reference)
            .expect("bucket manifest reference must be stored");

        serde_json::from_slice(bytes).expect("stored public bucket manifest must decode")
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
        data: Bytes,
    ) -> Result<FeedPointerResult> {
        let put = self.put_bytes(data).await?;

        Ok(FeedPointerResult {
            owner: "owner".to_string(),
            topic_hex: hex::encode([0u8; 32]),
            swarm_reference: put.reference.clone(),
            manifest_reference: "mock-feed-manifest".to_string(),
            soc_reference: "mock-soc".to_string(),
        })
    }
}

struct MockRegistryClient {
    bucket: ChainBucketRecord,
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn fetch_entry(&self, _access_key_hash: AccessKeyHash) -> Result<ChainRegistryEntry> {
        bail!("fetch_entry should not be used by direct public route tests")
    }

    async fn fetch_bucket(&self, _bucket_name_hash: [u8; 32]) -> Result<Option<ChainBucketRecord>> {
        Ok(Some(self.bucket.clone()))
    }

    async fn fetch_bucket_type(
        &self,
        _bucket_name_hash: [u8; 32],
    ) -> Result<Option<ChainBucketType>> {
        Ok(Some(ChainBucketType::Public))
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
        bail!("unwrap_sigv4_secret should not be used by direct public route tests")
    }
}

#[derive(Debug, Clone)]
struct AnchorSubmitRecord {
    expected_bucket_manifest_root: String,
    bucket_manifest_root: String,
}

#[derive(Default)]
struct FailingAnchorClient {
    submit: Mutex<Option<AnchorSubmitRecord>>,
}

impl FailingAnchorClient {
    fn submitted(&self) -> Option<AnchorSubmitRecord> {
        self.submit.lock().unwrap().clone()
    }
}

#[async_trait]
impl AnchorClient for FailingAnchorClient {
    async fn create_bucket_anchor(
        &self,
        _owner: SubstrateAddress32,
        _bucket_id: [u8; 32],
        _is_private: bool,
        _owner_signature: [u8; 64],
        _expected_owner_catalog_root: String,
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("create_bucket_anchor should not be used by public PUT")
    }

    async fn create_trustless_bucket_anchor(
        &self,
        _owner: SubstrateAddress32,
        _bucket_id: [u8; 32],
        _owner_signature: [u8; 64],
        _expected_owner_catalog_root: String,
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("create_trustless_bucket_anchor should not be used by public PUT")
    }

    async fn delete_bucket_anchor(
        &self,
        _bucket_id: [u8; 32],
        _owner_signature: [u8; 64],
        _expected_owner_catalog_root: String,
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("delete_bucket_anchor should not be used by public PUT")
    }

    async fn update_bucket_manifest_root_for_put_anchor(
        &self,
        _bucket_id: [u8; 32],
        _expected_bucket_manifest_root: String,
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("update_bucket_manifest_root_for_put_anchor should not be used by public PUT")
    }

    async fn update_bucket_manifest_root_for_delete_anchor(
        &self,
        _bucket_id: [u8; 32],
        _expected_bucket_manifest_root: String,
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("delete anchor should not be used by public PUT")
    }

    async fn submit_anchor_object(
        &self,
        _owner: SubstrateAddress32,
        _bucket_id: [u8; 32],
        _object_key_id: [u8; 32],
        _swarm_ref: String,
        expected_bucket_manifest_root: String,
        bucket_manifest_root: String,
        _size: u64,
        _etag: [u8; 32],
    ) -> Result<String> {
        *self.submit.lock().unwrap() = Some(AnchorSubmitRecord {
            expected_bucket_manifest_root,
            bucket_manifest_root,
        });

        bail!(
            "bucket contract error for bucket::update_bucket_manifest_root_for_put_cas: StaleBucketManifestRoot"
        )
    }
}

fn build_state(
    bee: Arc<MockBeeStorage>,
    anchor: Arc<FailingAnchorClient>,
    chain_bucket: ChainBucketRecord,
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
        orphan_journal: None,
        master_service_key: [0u8; 32],
        max_request_body_bytes: 64 * 1024 * 1024,
        identity_contract_address: None,
        bucket_contract_address: None,
    }
}

#[tokio::test]
async fn public_put_failed_anchor_leaves_staged_bee_writes_out_of_chain_visible_state() -> Result<()>
{
    let owner = [7u8; 32];
    let bucket = "public-bucket".to_string();
    let key = "new.txt".to_string();

    let chain_bucket = ChainBucketRecord {
        owner,
        is_private: false,
        encryption_version: 0,
        creation_date: 0,
        bucket_manifest_root: Vec::new(),
    };

    let bee = Arc::new(MockBeeStorage::default());
    let anchor = Arc::new(FailingAnchorClient::default());
    let state = build_state(bee.clone(), anchor.clone(), chain_bucket);

    let principal = AwsPrincipal {
        access_key_id: "test-access-key".to_string(),
        owner,
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

    let put_response = put_object::handle(
        Path((bucket.clone(), key.clone())),
        Extension(principal.clone()),
        State(state.clone()),
        headers,
        Bytes::from_static(b"public payload that loses cas"),
    )
    .await;

    assert_eq!(put_response.status(), StatusCode::PRECONDITION_FAILED);

    let submitted = anchor
        .submitted()
        .expect("public PUT should attempt an anchor after staging Bee writes");
    assert_eq!(
        submitted.expected_bucket_manifest_root, "",
        "public PUT into an empty chain root must CAS against the empty root"
    );

    let put_calls = bee.put_calls();
    assert_eq!(
        put_calls.len(),
        3,
        "failed public PUT may still stage object bytes, object manifest, and bucket manifest"
    );
    assert_eq!(submitted.bucket_manifest_root, put_calls[2]);

    let staged_manifest = bee.read_bucket_manifest(&submitted.bucket_manifest_root);
    assert!(
        staged_manifest.objects.contains_key(&key),
        "replacement manifest exists in Bee but is not authoritative without the chain anchor"
    );

    let get_response = get_object::handle(
        Path((bucket.clone(), key.clone())),
        Extension(principal.clone()),
        State(state.clone()),
    )
    .await;
    assert_eq!(
        get_response.status(),
        StatusCode::NOT_FOUND,
        "GET must resolve from the unchanged chain root, not the staged Bee pointer"
    );

    let list_response = list_objects_v2::handle(
        Path(bucket),
        Query(ListObjectsV2Query {
            list_type: Some(2),
            prefix: None,
            max_keys: Some(1000),
            continuation_token: None,
        }),
        Extension(principal),
        State(state),
    )
    .await;
    assert_eq!(list_response.status(), StatusCode::OK);

    let body = to_bytes(list_response.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(
        !body.contains("<Key>new.txt</Key>"),
        "LIST must resolve from the unchanged chain root, not the staged Bee manifest"
    );

    Ok(())
}
