use anyhow::{Result, bail};
use async_trait::async_trait;
use axum::{
    body::to_bytes,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
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
        derive_private_object_index_key, derive_private_object_payload_key, encrypt_blob_random,
        private_object_key_id,
    },
    manifest::{
        PrivateBucketManifestV2, PrivateBucketObjectEntry, PrivateObjectManifestV2,
        write_private_bucket_manifest_v2, write_private_object_manifest_v2,
    },
    routes::{
        get_object, head_object,
        list_objects_v2::{self, ListObjectsV2Query},
        private_object_read::private_object_payload_aad,
    },
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
    next_reference_byte: u8,
}

impl MockBeeStorage {
    fn insert_bytes(&self, reference: String, bytes: Bytes) {
        self.inner.lock().unwrap().bytes.insert(reference, bytes);
    }

    fn get_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().get_calls.clone()
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
        bail!("put_object_and_update_pointer should not be used by private route behavior tests")
    }
}

struct MockRegistryClient {
    bucket: ChainBucketRecord,
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn fetch_entry(&self, _access_key_hash: AccessKeyHash) -> Result<ChainRegistryEntry> {
        bail!("fetch_entry should not be used by direct route behavior tests")
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
        bail!("unwrap_sigv4_secret should not be used by direct route behavior tests")
    }
}

struct MockAnchorClient;

#[async_trait]
impl AnchorClient for MockAnchorClient {
    async fn create_bucket_anchor(
        &self,
        _owner: SubstrateAddress32,
        _bucket_id: [u8; 32],
        _is_private: bool,
        _owner_signature: [u8; 64],
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("create_bucket_anchor should not be used by private route behavior tests")
    }

    async fn delete_bucket_anchor(
        &self,
        _bucket_id: [u8; 32],
        _owner_signature: [u8; 64],
        _owner_catalog_root: String,
    ) -> Result<String> {
        bail!("delete_bucket_anchor should not be used by private route behavior tests")
    }

    async fn update_bucket_manifest_root_for_put_anchor(
        &self,
        _bucket_id: [u8; 32],
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("update_bucket_manifest_root_for_put_anchor should not be used by these tests")
    }

    async fn update_bucket_manifest_root_for_delete_anchor(
        &self,
        _bucket_id: [u8; 32],
        _bucket_manifest_root: String,
    ) -> Result<String> {
        bail!("update_bucket_manifest_root_for_delete_anchor should not be used by these tests")
    }

    async fn submit_anchor_object(
        &self,
        _owner: SubstrateAddress32,
        _bucket_id: [u8; 32],
        _object_key_id: [u8; 32],
        _swarm_ref: String,
        _bucket_manifest_root: String,
        _size: u64,
        _etag: [u8; 32],
    ) -> Result<String> {
        bail!("submit_anchor_object should not be used by private route behavior tests")
    }
}

struct PrivateFixture {
    state: AppState,
    bee: Arc<MockBeeStorage>,
    principal: AwsPrincipal,
    bucket: String,
    key: String,
    plaintext: Bytes,
    object_key_id: [u8; 32],
    encryption_version: u32,
    bucket_manifest_reference: String,
    object_manifest_reference: String,
    encrypted_payload_reference: String,
}

async fn private_fixture() -> Result<PrivateFixture> {
    let master_service_key = [42u8; 32];
    let owner = [7u8; 32];
    let bucket = "private-bucket".to_string();
    let key = "secret.txt".to_string();
    let encryption_version = 1u32;
    let plaintext = Bytes::from_static(b"private route payload");

    let bee = Arc::new(MockBeeStorage::default());

    let private_index_key =
        derive_private_object_index_key(&master_service_key, &owner, &bucket, encryption_version);
    let object_key_id = private_object_key_id(&private_index_key, &key);

    let payload_key = derive_private_object_payload_key(
        &master_service_key,
        &owner,
        &bucket,
        &object_key_id,
        encryption_version,
    );
    let payload_aad =
        private_object_payload_aad(&owner, &bucket, &object_key_id, encryption_version);

    let encrypted_payload = encrypt_blob_random(&payload_key, &payload_aad, &plaintext)?;
    let encrypted_payload_reference = hex::encode([200u8; 32]);
    bee.insert_bytes(
        encrypted_payload_reference.clone(),
        Bytes::from(encrypted_payload),
    );

    let private_object_manifest = PrivateObjectManifestV2 {
        object_key_id,
        encrypted_swarm_reference: encrypted_payload_reference.clone(),
        encryption_version,
        size: plaintext.len() as u64,
        etag: "etag-private-secret".to_string(),
        content_type: "text/plain".to_string(),
        last_modified: "2026-05-14T00:00:00Z".to_string(),
    };

    let object_manifest_record = write_private_object_manifest_v2(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &bucket,
        &object_key_id,
        encryption_version,
        &private_object_manifest,
    )
    .await?;

    let mut objects = BTreeMap::new();
    objects.insert(
        hex::encode(object_key_id),
        PrivateBucketObjectEntry {
            object_key: key.clone(),
            object_key_id,
            object_manifest_reference: object_manifest_record.manifest_reference.clone(),
            encryption_version,
            size: plaintext.len() as u64,
            etag: "etag-private-secret".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-05-14T00:00:00Z".to_string(),
        },
    );

    let private_bucket_manifest = PrivateBucketManifestV2 { objects };

    let bucket_manifest_record = write_private_bucket_manifest_v2(
        bee.as_ref(),
        &master_service_key,
        &owner,
        &bucket,
        encryption_version,
        &private_bucket_manifest,
    )
    .await?;

    let bucket_manifest_root = hex::decode(&bucket_manifest_record.manifest_reference)?;

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
    let anchor_client: Arc<dyn AnchorClient> = Arc::new(MockAnchorClient);
    let bee_client: Arc<dyn BeeStorage> = bee.clone();

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

    Ok(PrivateFixture {
        state,
        bee,
        principal: AwsPrincipal {
            access_key_id: "test-access-key".to_string(),
            owner,
        },
        bucket,
        key,
        plaintext,
        object_key_id,
        encryption_version,
        bucket_manifest_reference: bucket_manifest_record.manifest_reference,
        object_manifest_reference: object_manifest_record.manifest_reference,
        encrypted_payload_reference,
    })
}

#[tokio::test]
async fn private_get_decrypts_payload_and_omits_swarm_ref_header() -> Result<()> {
    let fixture = private_fixture().await?;

    let response = get_object::handle(
        Path((fixture.bucket.clone(), fixture.key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("x-amz-meta-swarm-ref").is_none(),
        "private GET must not expose the encrypted Swarm payload reference"
    );

    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(body, fixture.plaintext);

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(calls.contains(&fixture.object_manifest_reference));
    assert!(calls.contains(&fixture.encrypted_payload_reference));

    Ok(())
}

#[tokio::test]
async fn private_head_reads_metadata_but_not_payload_and_omits_swarm_ref_header() -> Result<()> {
    let fixture = private_fixture().await?;

    let response = head_object::handle(
        Path((fixture.bucket.clone(), fixture.key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("x-amz-meta-swarm-ref").is_none(),
        "private HEAD must not expose the encrypted Swarm payload reference"
    );

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(calls.contains(&fixture.object_manifest_reference));
    assert!(
        !calls.contains(&fixture.encrypted_payload_reference),
        "private HEAD must not fetch encrypted payload bytes"
    );

    Ok(())
}

#[tokio::test]
async fn private_list_reads_bucket_manifest_only_and_omits_swarm_ref_header() -> Result<()> {
    let fixture = private_fixture().await?;

    let response = list_objects_v2::handle(
        Path(fixture.bucket.clone()),
        Query(ListObjectsV2Query {
            list_type: Some(2),
            prefix: None,
            max_keys: Some(1000),
            continuation_token: None,
        }),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("x-amz-meta-swarm-ref").is_none(),
        "private ListObjectsV2 must not expose Swarm references"
    );

    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.contains("<Key>secret.txt</Key>"));

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(
        !calls.contains(&fixture.object_manifest_reference),
        "private ListObjectsV2 must not fetch private object manifests"
    );
    assert!(
        !calls.contains(&fixture.encrypted_payload_reference),
        "private ListObjectsV2 must not fetch encrypted payload bytes"
    );

    Ok(())
}

#[tokio::test]
async fn private_get_fails_closed_when_bucket_manifest_cannot_decrypt() -> Result<()> {
    let fixture = private_fixture().await?;

    fixture.bee.insert_bytes(
        fixture.bucket_manifest_reference.clone(),
        Bytes::from_static(b"not-a-valid-encrypted-private-bucket-manifest"),
    );

    let response = get_object::handle(
        Path((fixture.bucket.clone(), fixture.key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("private route payload"),
        "failed private GET must not leak plaintext payload"
    );

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(
        !calls.contains(&fixture.object_manifest_reference),
        "GET must stop before object manifest when bucket manifest cannot decrypt"
    );
    assert!(
        !calls.contains(&fixture.encrypted_payload_reference),
        "GET must stop before payload when bucket manifest cannot decrypt"
    );

    Ok(())
}

#[tokio::test]
async fn private_head_fails_closed_when_object_manifest_cannot_decrypt() -> Result<()> {
    let fixture = private_fixture().await?;

    fixture.bee.insert_bytes(
        fixture.object_manifest_reference.clone(),
        Bytes::from_static(b"not-a-valid-encrypted-private-object-manifest"),
    );

    let response = head_object::handle(
        Path((fixture.bucket.clone(), fixture.key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        response.headers().get("x-amz-meta-swarm-ref").is_none(),
        "failed private HEAD must not expose Swarm references"
    );

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(calls.contains(&fixture.object_manifest_reference));
    assert!(
        !calls.contains(&fixture.encrypted_payload_reference),
        "private HEAD must fail closed without fetching encrypted payload bytes"
    );

    Ok(())
}

#[tokio::test]
async fn private_list_fails_closed_when_bucket_manifest_cannot_decrypt() -> Result<()> {
    let fixture = private_fixture().await?;

    fixture.bee.insert_bytes(
        fixture.bucket_manifest_reference.clone(),
        Bytes::from_static(b"not-a-valid-encrypted-private-bucket-manifest"),
    );

    let response = list_objects_v2::handle(
        Path(fixture.bucket.clone()),
        Query(ListObjectsV2Query {
            list_type: Some(2),
            prefix: None,
            max_keys: Some(1000),
            continuation_token: None,
        }),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("secret.txt"),
        "failed private ListObjectsV2 must not leak object keys from undecryptable manifests"
    );

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(
        !calls.contains(&fixture.object_manifest_reference),
        "private ListObjectsV2 must not fetch object manifests"
    );
    assert!(
        !calls.contains(&fixture.encrypted_payload_reference),
        "private ListObjectsV2 must not fetch encrypted payload bytes"
    );

    Ok(())
}

#[tokio::test]
async fn private_get_fails_closed_when_payload_cannot_decrypt() -> Result<()> {
    let fixture = private_fixture().await?;

    fixture.bee.insert_bytes(
        fixture.encrypted_payload_reference.clone(),
        Bytes::from_static(b"not-a-valid-encrypted-private-payload"),
    );

    let response = get_object::handle(
        Path((fixture.bucket.clone(), fixture.key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("private route payload"),
        "failed private GET must not leak plaintext payload"
    );

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(calls.contains(&fixture.object_manifest_reference));
    assert!(calls.contains(&fixture.encrypted_payload_reference));

    Ok(())
}

#[tokio::test]
async fn private_get_fails_closed_when_object_manifest_version_mismatches_entry() -> Result<()> {
    let fixture = private_fixture().await?;

    let mismatched_manifest = PrivateObjectManifestV2 {
        object_key_id: fixture.object_key_id,
        encrypted_swarm_reference: fixture.encrypted_payload_reference.clone(),
        encryption_version: fixture.encryption_version + 1,
        size: fixture.plaintext.len() as u64,
        etag: "etag-private-secret".to_string(),
        content_type: "text/plain".to_string(),
        last_modified: "2026-05-14T00:00:00Z".to_string(),
    };

    let mismatched_record = write_private_object_manifest_v2(
        fixture.bee.as_ref(),
        &fixture.state.master_service_key,
        &fixture.principal.owner,
        &fixture.bucket,
        &fixture.object_key_id,
        fixture.encryption_version,
        &mismatched_manifest,
    )
    .await?;

    let mismatched_bytes = {
        let inner = fixture.bee.inner.lock().unwrap();
        inner
            .bytes
            .get(&mismatched_record.manifest_reference)
            .cloned()
            .expect("mismatched object manifest bytes should exist")
    };

    fixture
        .bee
        .insert_bytes(fixture.object_manifest_reference.clone(), mismatched_bytes);

    let response = get_object::handle(
        Path((fixture.bucket.clone(), fixture.key.clone())),
        Extension(fixture.principal.clone()),
        State(fixture.state.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("private route payload"),
        "version mismatch must fail closed without leaking plaintext payload"
    );

    let calls = fixture.bee.get_calls();
    assert!(calls.contains(&fixture.bucket_manifest_reference));
    assert!(calls.contains(&fixture.object_manifest_reference));
    assert!(
        !calls.contains(&fixture.encrypted_payload_reference),
        "GET must stop before payload when object manifest version mismatches bucket entry"
    );

    Ok(())
}
