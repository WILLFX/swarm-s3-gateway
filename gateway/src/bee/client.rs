use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use reqwest::{Client, StatusCode};
use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{env, time::Duration};

#[derive(Clone, Debug)]
pub struct BeeClient {
    http: Client,
    base_url: String,
    postage_batch_id: String,
    feed_owner_hex: String,
    feed_secret_key: SecretKey,
}

#[derive(Debug, Clone)]
pub struct BeePutBytesResult {
    pub reference: String,
}

#[derive(Debug, Clone)]
pub struct FeedPointerResult {
    pub owner: String,
    pub topic_hex: String,
    pub manifest_reference: String,
    pub soc_reference: String,
}

#[derive(Debug, Deserialize)]
struct BeeReferenceResponse {
    reference: String,
}

impl BeeClient {
    /// Builds a Bee client from:
    /// - `base_url` passed by caller
    /// - `S3GW_BEE_STAMP_BATCH_ID` from env
    /// - `S3GW_GAS_TANK_SEED` from env
    ///
    /// The postage batch is required for every upload.
    /// The Gas Tank seed is deterministically transformed into a secp256k1
    /// feed-signing key so every gateway instance derives the same Bee feed owner.
    pub fn from_env(base_url: impl Into<String>) -> Result<Self> {
        let postage_batch_id = env::var("S3GW_BEE_STAMP_BATCH_ID")
            .context("missing required environment variable: S3GW_BEE_STAMP_BATCH_ID")?;

        validate_batch_id(&postage_batch_id)?;

        let gas_tank_seed = env::var("S3GW_GAS_TANK_SEED")
            .context("missing required environment variable: S3GW_GAS_TANK_SEED")?;

        let feed_secret_key = derive_feed_secret_key_from_seed(&gas_tank_seed)?;
        let feed_owner_hex = ethereum_address_from_secret_key(&feed_secret_key);

        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build reqwest Bee client")?;

        Ok(Self {
            http,
            base_url: trim_trailing_slash(base_url.into()),
            postage_batch_id,
            feed_owner_hex,
            feed_secret_key,
        })
    }

    pub fn postage_batch_id(&self) -> &str {
        &self.postage_batch_id
    }

    pub fn feed_owner_hex(&self) -> &str {
        &self.feed_owner_hex
    }

    pub fn derive_topic(bucket: &str, key: &str) -> [u8; 32] {
        let joined = format!("{bucket}/{key}");
        let digest = Sha256::digest(joined.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn derive_topic_hex(bucket: &str, key: &str) -> String {
        hex::encode(Self::derive_topic(bucket, key))
    }

    /// Raw bytes upload using Bee `/bytes`.
    pub async fn put_bytes(&self, data: Bytes) -> Result<BeePutBytesResult> {
        let url = format!("{}/bytes", self.base_url);

        let response = self
            .http
            .post(url)
            .header("Swarm-Postage-Batch-Id", &self.postage_batch_id)
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .context("Bee /bytes request failed")?;

        let status = response.status();
        let text = response
            .text()
            .await
            .context("failed to read Bee /bytes response body")?;

        if !status.is_success() {
            bail!("Bee /bytes failed with status {}: {}", status, text);
        }

        let parsed: BeeReferenceResponse =
            serde_json::from_str(&text).context("failed to parse Bee /bytes response JSON")?;

        Ok(BeePutBytesResult {
            reference: parsed.reference,
        })
    }

    /// Creates the feed manifest if needed for this deterministic topic.
    pub async fn ensure_feed_manifest(&self, bucket: &str, key: &str) -> Result<String> {
        let topic_hex = Self::derive_topic_hex(bucket, key);
        let url = format!(
            "{}/feeds/{}/{}?type=sequence",
            self.base_url, self.feed_owner_hex, topic_hex
        );

        let response = self
            .http
            .post(url)
            .header("Swarm-Postage-Batch-Id", &self.postage_batch_id)
            .send()
            .await
            .context("Bee feed manifest creation request failed")?;

        let status = response.status();
        let text = response
            .text()
            .await
            .context("failed to read Bee feed manifest response body")?;

        if !status.is_success() {
            bail!("Bee feed manifest creation failed with status {}: {}", status, text);
        }

        let parsed: BeeReferenceResponse = serde_json::from_str(&text)
            .context("failed to parse Bee feed manifest response JSON")?;

        Ok(parsed.reference)
    }

    /// Full storage-side helper:
    /// 1. Upload bytes to `/bytes`
    /// 2. Create the deterministic feed manifest for `{bucket}/{key}`
    /// 3. Publish the returned Swarm reference to a deterministic SOC-backed pointer
    ///
    /// Important:
    /// Bee's public REST docs clearly expose `/soc` as the write path behind feed updates,
    /// but they do not fully spell out the writer-side binary encoding used by bee-js for
    /// append-only feed indices. This implementation therefore uses a deterministic SOC-backed
    /// pointer at the topic identifier as the temporary mutable pointer for this slice.
    ///
    /// That keeps:
    /// - deterministic topic derivation
    /// - deterministic owner derivation
    /// - `/bytes` upload correctness
    /// - stable owner/topic addressing
    ///
    /// The true append-only sequence-feed writer can replace only `publish_soc_pointer(...)`
    /// in the next slice without changing the upload path or topic derivation.
    pub async fn put_object_and_update_pointer(
        &self,
        bucket: &str,
        key: &str,
        data: Bytes,
    ) -> Result<FeedPointerResult> {
        let put = self.put_bytes(data).await?;
        let manifest_reference = self.ensure_feed_manifest(bucket, key).await?;
        let topic_hex = Self::derive_topic_hex(bucket, key);
        let soc_reference = self.publish_soc_pointer(&topic_hex, &put.reference).await?;

        Ok(FeedPointerResult {
            owner: self.feed_owner_hex.clone(),
            topic_hex,
            manifest_reference,
            soc_reference,
        })
    }

    /// Stopgap deterministic pointer writer using `/soc/{owner}/{id}?sig=...`.
    ///
    /// Payload format:
    /// - 8-byte little-endian span
    /// - raw 32-byte Swarm reference payload
    ///
    /// Identifier:
    /// - the 32-byte deterministic topic
    ///
    /// Signature:
    /// - recoverable secp256k1 signature over keccak256(identifier || keccak256(span||payload))
    ///
    /// This keeps one stable owner+topic location per object while we postpone the full
    /// append-only sequence-feed writer.
    pub async fn publish_soc_pointer(
        &self,
        topic_hex: &str,
        swarm_reference_hex: &str,
    ) -> Result<String> {
        let identifier = decode_32(topic_hex, "topic_hex")?;
        let payload = decode_32(swarm_reference_hex, "swarm_reference_hex")?;

        let span = (payload.len() as u64).to_le_bytes();
        let mut soc_body = Vec::with_capacity(8 + payload.len());
        soc_body.extend_from_slice(&span);
        soc_body.extend_from_slice(&payload);

        let mut payload_hasher = Keccak256::new();
        payload_hasher.update(&soc_body);
        let payload_digest = payload_hasher.finalize();

        let mut digest_hasher = Keccak256::new();
        digest_hasher.update(identifier);
        digest_hasher.update(payload_digest);
        let digest = digest_hasher.finalize();

        let sig_hex = sign_digest_hex(&self.feed_secret_key, &digest)?;

        let url = format!(
            "{}/soc/{}/{}?sig={}",
            self.base_url, self.feed_owner_hex, topic_hex, sig_hex
        );

        let response = self
            .http
            .post(url)
            .header("Swarm-Postage-Batch-Id", &self.postage_batch_id)
            .header("Content-Type", "application/octet-stream")
            .body(soc_body)
            .send()
            .await
            .context("Bee /soc pointer update request failed")?;

        let status = response.status();
        let text = response
            .text()
            .await
            .context("failed to read Bee /soc response body")?;

        if !status.is_success() {
            bail!("Bee /soc pointer update failed with status {}: {}", status, text);
        }

        let parsed: BeeReferenceResponse =
            serde_json::from_str(&text).context("failed to parse Bee /soc response JSON")?;

        Ok(parsed.reference)
    }

    pub async fn get_pointer_bytes(&self, bucket: &str, key: &str) -> Result<Option<Bytes>> {
        let topic_hex = Self::derive_topic_hex(bucket, key);
        let url = format!(
            "{}/soc/{}/{}",
            self.base_url, self.feed_owner_hex, topic_hex
        );

        let response = self
            .http
            .get(url)
            .send()
            .await
            .context("Bee /soc read request failed")?;

        match response.status() {
            StatusCode::OK => {
                let data = response
                    .bytes()
                    .await
                    .context("failed to read Bee /soc body")?;
                Ok(Some(data))
            }
            StatusCode::NOT_FOUND => Ok(None),
            status => {
                let text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".to_string());
                bail!("Bee /soc read failed with status {}: {}", status, text)
            }
        }
    }
}

fn trim_trailing_slash(mut value: String) -> String {
    while value.ends_with('/') {
        value.pop();
    }
    value
}

fn validate_batch_id(batch_id: &str) -> Result<()> {
    let trimmed = batch_id.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("S3GW_BEE_STAMP_BATCH_ID must be a 64-character hex string");
    }
    Ok(())
}

fn decode_32(hex_value: &str, field_name: &str) -> Result<[u8; 32]> {
    let raw = hex_value.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw)
        .with_context(|| format!("{field_name} must be valid hex"))?;

    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{field_name} must decode to exactly 32 bytes"))?;

    Ok(arr)
}

fn derive_feed_secret_key_from_seed(seed: &str) -> Result<SecretKey> {
    let mut counter: u32 = 0;

    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"s3gw-bee-feed-owner");
        hasher.update(seed.as_bytes());
        hasher.update(counter.to_le_bytes());

        let digest = hasher.finalize();
        if let Ok(secret_key) = SecretKey::from_slice(&digest) {
            return Ok(secret_key);
        }

        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("failed to derive valid Bee feed secret key from seed"))?;
    }
}

fn ethereum_address_from_secret_key(secret_key: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, secret_key);
    let uncompressed = public_key.serialize_uncompressed();

    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..]);
    let digest = hasher.finalize();

    hex::encode(&digest[12..32])
}

fn sign_digest_hex(secret_key: &SecretKey, digest: &[u8]) -> Result<String> {
    if digest.len() != 32 {
        bail!("digest must be 32 bytes");
    }

    let message = Message::from_slice(digest).context("failed to construct secp256k1 message")?;
    let secp = Secp256k1::new();
    let signature: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, secret_key);
    let (recovery_id, compact) = signature.serialize_compact();

    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&compact);
    out.push(recovery_id.to_i32() as u8);

    Ok(hex::encode(out))
}
