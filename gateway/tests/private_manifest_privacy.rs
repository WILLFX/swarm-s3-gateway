use anyhow::{Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use common::types::SubstrateAddress32;
use gateway::{
    bee::client::{BeePutBytesResult, BeeStorage, FeedPointerResult},
    manifest::{
        PrivateBucketManifestV2, PrivateBucketObjectEntry, PrivateObjectManifestV2,
        RootCatalogManifest, read_owner_catalog_manifest, read_private_bucket_manifest_v2,
        read_private_object_manifest_v2, write_owner_catalog_manifest,
        write_private_bucket_manifest_v2, write_private_object_manifest_v2,
    },
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

#[derive(Default)]
struct MockBeeStorage {
    inner: Mutex<MockBeeInner>,
}

#[derive(Default)]
struct MockBeeInner {
    bytes: HashMap<String, Bytes>,
    next_reference_byte: u8,
}

impl MockBeeStorage {
    fn get_stored_bytes(&self, reference: &str) -> Option<Bytes> {
        self.inner.lock().unwrap().bytes.get(reference).cloned()
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
        bail!("put_object_and_update_pointer should not be called by manifest privacy tests")
    }
}

fn reference_bytes(reference: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(reference)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("reference must decode to 32 bytes"))?;
    Ok(arr)
}

fn bytes_contain_ascii(bytes: &Bytes, needle: &str) -> bool {
    bytes
        .as_ref()
        .windows(needle.as_bytes().len())
        .any(|window| window == needle.as_bytes())
}

#[tokio::test]
async fn encrypted_owner_catalog_bytes_do_not_expose_plaintext_bucket_name() -> Result<()> {
    let bee = MockBeeStorage::default();
    let master_key = [7u8; 32];
    let owner: SubstrateAddress32 = [9u8; 32];

    let bucket_name = "super-private-client-tax-bucket-never-plaintext";
    let bucket_root = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let mut catalog = RootCatalogManifest::default();
    catalog
        .buckets
        .insert(bucket_name.to_string(), bucket_root.to_string());

    let record = write_owner_catalog_manifest(&bee, &master_key, &owner, &catalog).await?;
    let stored = bee
        .get_stored_bytes(&record.manifest_reference)
        .expect("owner catalog bytes should be uploaded");

    assert!(
        !bytes_contain_ascii(&stored, bucket_name),
        "encrypted owner catalog bytes leaked plaintext bucket name"
    );
    assert!(
        !bytes_contain_ascii(&stored, bucket_root),
        "encrypted owner catalog bytes leaked bucket root string"
    );

    let decoded = read_owner_catalog_manifest(
        &bee,
        &master_key,
        &owner,
        &reference_bytes(&record.manifest_reference)?,
    )
    .await?;

    assert_eq!(decoded, catalog);

    Ok(())
}

#[tokio::test]
async fn encrypted_private_bucket_manifest_bytes_do_not_expose_plaintext_object_metadata()
-> Result<()> {
    let bee = MockBeeStorage::default();
    let master_key = [11u8; 32];
    let owner: SubstrateAddress32 = [12u8; 32];
    let bucket = "private-audit-bucket";
    let encryption_version = 1;

    let object_key = "super-private-object-key-never-plaintext.txt";
    let object_manifest_reference =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let content_type = "application/x-s3gw-private-audit";

    let object_key_id = [44u8; 32];

    let entry = PrivateBucketObjectEntry {
        object_key: object_key.to_string(),
        object_key_id,
        object_manifest_reference: object_manifest_reference.to_string(),
        encryption_version,
        size: 12345,
        etag: "private-etag-never-plaintext".to_string(),
        content_type: content_type.to_string(),
        last_modified: "2026-01-01T00:00:00Z".to_string(),
    };

    let mut objects = BTreeMap::new();
    objects.insert(hex::encode(object_key_id), entry);

    let manifest = PrivateBucketManifestV2 { objects };

    let record = write_private_bucket_manifest_v2(
        &bee,
        &master_key,
        &owner,
        bucket,
        encryption_version,
        &manifest,
    )
    .await?;

    let stored = bee
        .get_stored_bytes(&record.manifest_reference)
        .expect("private bucket manifest bytes should be uploaded");

    for forbidden in [
        object_key,
        object_manifest_reference,
        content_type,
        "private-etag-never-plaintext",
    ] {
        assert!(
            !bytes_contain_ascii(&stored, forbidden),
            "encrypted private bucket manifest bytes leaked plaintext marker: {forbidden}"
        );
    }

    let decoded = read_private_bucket_manifest_v2(
        &bee,
        &master_key,
        &owner,
        bucket,
        encryption_version,
        &reference_bytes(&record.manifest_reference)?,
    )
    .await?
    .expect("private bucket manifest should decode");

    assert_eq!(decoded.manifest, manifest);

    Ok(())
}

#[tokio::test]
async fn encrypted_private_object_manifest_bytes_do_not_expose_plaintext_object_metadata()
-> Result<()> {
    let bee = MockBeeStorage::default();
    let master_key = [21u8; 32];
    let owner: SubstrateAddress32 = [22u8; 32];
    let bucket = "private-audit-bucket";
    let encryption_version = 1;
    let object_key_id = [33u8; 32];

    let encrypted_swarm_reference =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let content_type = "application/x-s3gw-private-object-audit";

    let manifest = PrivateObjectManifestV2 {
        object_key_id,
        encrypted_swarm_reference: encrypted_swarm_reference.to_string(),
        encryption_version,
        size: 98765,
        etag: "object-manifest-etag-never-plaintext".to_string(),
        content_type: content_type.to_string(),
        last_modified: "2026-02-02T00:00:00Z".to_string(),
    };

    let record = write_private_object_manifest_v2(
        &bee,
        &master_key,
        &owner,
        bucket,
        &object_key_id,
        encryption_version,
        &manifest,
    )
    .await?;

    let stored = bee
        .get_stored_bytes(&record.manifest_reference)
        .expect("private object manifest bytes should be uploaded");

    for forbidden in [
        encrypted_swarm_reference,
        content_type,
        "object-manifest-etag-never-plaintext",
    ] {
        assert!(
            !bytes_contain_ascii(&stored, forbidden),
            "encrypted private object manifest bytes leaked plaintext marker: {forbidden}"
        );
    }

    let decoded = read_private_object_manifest_v2(
        &bee,
        &master_key,
        &owner,
        bucket,
        &object_key_id,
        encryption_version,
        &record.manifest_reference,
    )
    .await?
    .expect("private object manifest should decode");

    assert_eq!(decoded.manifest, manifest);

    Ok(())
}
