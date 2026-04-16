use anyhow::{anyhow, Result};
use async_trait::async_trait;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Uri};
use bytes::Bytes;
use common::types::{AccessKeyHash, ChainRegistryEntry, SubstrateAddress32};
use gateway::auth::sigv4::RegistryBackedSigV4Validator;
use gateway::traits::{RegistryClient, SecretUnwrapper};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

struct MockRegistryClient {
    expected_hash: AccessKeyHash,
    entry: ChainRegistryEntry,
}

#[async_trait]
impl RegistryClient for MockRegistryClient {
    async fn fetch_entry(&self, access_key_hash: AccessKeyHash) -> Result<ChainRegistryEntry> {
        if access_key_hash != self.expected_hash {
            return Err(anyhow!("unexpected access key hash"));
        }
        Ok(self.entry.clone())
    }
}

struct FixedKeyUnwrapper {
    master_key: [u8; 32],
}

#[async_trait]
impl SecretUnwrapper for FixedKeyUnwrapper {
    async fn unwrap_sigv4_secret(
        &self,
        _key_version: u32,
        nonce: &[u8],
        encrypted_sigv4_secret: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| anyhow!("failed to init AES-GCM: {e:?}"))?;

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: encrypted_sigv4_secret,
                    aad,
                },
            )
            .map_err(|e| anyhow!("failed to unwrap test secret: {e:?}"))?;

        Ok(plaintext)
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| anyhow!("failed to initialize HMAC: {e}"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Result<Vec<u8>> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    hmac_sha256(&k_service, b"aws4_request")
}

fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match *b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn canonicalize_query(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    let mut pairs = raw
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (percent_encode(k), percent_encode(v))
        })
        .collect::<Vec<_>>();

    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn build_canonical_request(
    method: &Method,
    path: &str,
    raw_query: &str,
    headers: &HeaderMap,
    signed_headers: &[String],
    payload_hash: &str,
) -> Result<String> {
    let canonical_uri = canonical_uri(path);
    let canonical_query = canonicalize_query(raw_query);

    let mut canonical_headers = String::new();
    for header_name in signed_headers {
        let value = headers
            .get(header_name)
            .ok_or_else(|| anyhow!("missing signed header: {header_name}"))?
            .to_str()
            .map_err(|e| anyhow!("invalid signed header value: {e}"))?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        canonical_headers.push_str(&format!(
            "{}:{}\n",
            header_name.to_ascii_lowercase(),
            value.trim()
        ));
    }

    let signed_headers_line = signed_headers.join(";");

    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers_line,
        payload_hash
    ))
}

fn hash_access_key_id(access_key_id: &str) -> AccessKeyHash {
    let digest = Sha256::digest(access_key_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encrypt_sigv4_secret(
    master_key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext_secret: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|e| anyhow!("failed to init AES-GCM: {e:?}"))?;

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext_secret,
                aad,
            },
        )
        .map_err(|e| anyhow!("failed to encrypt test secret: {e:?}"))?;

    Ok(ciphertext)
}

fn build_signed_request(
    method: Method,
    uri: &str,
    host: &str,
    amz_date: &str,
    access_key_id: &str,
    secret: &str,
    body: Bytes,
) -> Result<Request<Bytes>> {
    let uri: Uri = uri.parse()?;
    let payload_hash = sha256_hex(&body);

    let signed_headers = vec![
        "host".to_string(),
        "x-amz-content-sha256".to_string(),
        "x-amz-date".to_string(),
    ];

    let mut req = Request::builder()
        .method(method.clone())
        .uri(uri.clone())
        .body(body.clone())?;

    req.headers_mut()
        .insert("host", HeaderValue::from_str(host)?);
    req.headers_mut()
        .insert("x-amz-date", HeaderValue::from_str(amz_date)?);
    req.headers_mut().insert(
        "x-amz-content-sha256",
        HeaderValue::from_str(&payload_hash)?,
    );

    let date = &amz_date[0..8];
    let region = "us-east-1";
    let service = "s3";
    let credential_scope = format!("{date}/{region}/{service}/aws4_request");

    let canonical_request = build_canonical_request(
        &method,
        uri.path(),
        uri.query().unwrap_or(""),
        req.headers(),
        &signed_headers,
        &payload_hash,
    )?;

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    let signing_key = derive_signing_key(secret, date, region, service)?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key_id,
        credential_scope,
        signed_headers.join(";"),
        signature
    );

    req.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&authorization)?,
    );

    Ok(req)
}

#[tokio::test]
async fn happy_path_registry_fetch_unwrap_and_sigv4_validate() -> Result<()> {
    let access_key_id = "AKIA_TEST_ACCESS_KEY_123456";
    let plaintext_sigv4_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    let owner: SubstrateAddress32 = [7u8; 32];
    let access_key_hash = hash_access_key_id(access_key_id);

    let master_key = [42u8; 32];
    let nonce = [9u8; 12];

    let encrypted_sigv4_secret = encrypt_sigv4_secret(
        &master_key,
        &nonce,
        &access_key_hash,
        plaintext_sigv4_secret.as_bytes(),
    )?;

    let registry_entry = ChainRegistryEntry {
        owner,
        encrypted_sigv4_secret,
        nonce: nonce,
        key_version: 1,
        enabled: true,
    };

    let registry = Arc::new(MockRegistryClient {
        expected_hash: access_key_hash,
        entry: registry_entry,
    });

    let unwrapper: Arc<dyn SecretUnwrapper> = Arc::new(FixedKeyUnwrapper { master_key });

    let validator = RegistryBackedSigV4Validator {
        registry,
        unwrapper,
        expected_service: "s3".to_string(),
        expected_region: Some("us-east-1".to_string()),
        allow_unsigned_payload: false,
    };

    let body = Bytes::from_static(b"hello swarm");
    let req = build_signed_request(
        Method::PUT,
        "https://example.local/my-bucket/test.txt",
        "example.local",
        "20250101T120000Z",
        access_key_id,
        plaintext_sigv4_secret,
        body,
    )?;

    let principal = validator.validate(&req).await?;

    assert_eq!(principal.access_key_id, access_key_id);
    assert_eq!(principal.owner, owner);

    Ok(())
}

#[tokio::test]
async fn revoked_credential_fails_even_with_valid_signature() -> Result<()> {
    let access_key_id = "AKIA_TEST_ACCESS_KEY_123456";
    let plaintext_sigv4_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    let owner: SubstrateAddress32 = [7u8; 32];
    let access_key_hash = hash_access_key_id(access_key_id);

    let master_key = [42u8; 32];
    let nonce = [9u8; 12];

    let encrypted_sigv4_secret = encrypt_sigv4_secret(
        &master_key,
        &nonce,
        &access_key_hash,
        plaintext_sigv4_secret.as_bytes(),
    )?;

    let registry_entry = ChainRegistryEntry {
        owner,
        encrypted_sigv4_secret,
        nonce: nonce,
        key_version: 1,
        enabled: false,
    };

    let registry = Arc::new(MockRegistryClient {
        expected_hash: access_key_hash,
        entry: registry_entry,
    });

    let unwrapper: Arc<dyn SecretUnwrapper> = Arc::new(FixedKeyUnwrapper { master_key });

    let validator = RegistryBackedSigV4Validator {
        registry,
        unwrapper,
        expected_service: "s3".to_string(),
        expected_region: Some("us-east-1".to_string()),
        allow_unsigned_payload: false,
    };

    let body = Bytes::from_static(b"hello swarm");
    let req = build_signed_request(
        Method::PUT,
        "https://example.local/my-bucket/test.txt",
        "example.local",
        "20250101T120000Z",
        access_key_id,
        plaintext_sigv4_secret,
        body,
    )?;

    let err = validator.validate(&req).await.unwrap_err();
    assert!(
        err.to_string().contains("credential disabled"),
        "unexpected error: {err:#}"
    );

    Ok(())
}

#[tokio::test]
async fn rotated_key_rejects_request_signed_with_old_secret() -> Result<()> {
    let access_key_id = "AKIA_TEST_ACCESS_KEY_123456";
    let old_sigv4_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let new_sigv4_secret = "ROTATEDKEY1234567890EXAMPLEKEYVALUE12345";

    let owner: SubstrateAddress32 = [7u8; 32];
    let access_key_hash = hash_access_key_id(access_key_id);

    let master_key = [42u8; 32];
    let nonce = [9u8; 12];

    let encrypted_sigv4_secret = encrypt_sigv4_secret(
        &master_key,
        &nonce,
        &access_key_hash,
        new_sigv4_secret.as_bytes(),
    )?;

    let registry_entry = ChainRegistryEntry {
        owner,
        encrypted_sigv4_secret,
        nonce: nonce,
        key_version: 2,
        enabled: true,
    };

    let registry = Arc::new(MockRegistryClient {
        expected_hash: access_key_hash,
        entry: registry_entry,
    });

    let unwrapper: Arc<dyn SecretUnwrapper> = Arc::new(FixedKeyUnwrapper { master_key });

    let validator = RegistryBackedSigV4Validator {
        registry,
        unwrapper,
        expected_service: "s3".to_string(),
        expected_region: Some("us-east-1".to_string()),
        allow_unsigned_payload: false,
    };

    let body = Bytes::from_static(b"hello swarm");
    let req = build_signed_request(
        Method::PUT,
        "https://example.local/my-bucket/test.txt",
        "example.local",
        "20250101T120000Z",
        access_key_id,
        old_sigv4_secret,
        body,
    )?;

    let err = validator.validate(&req).await.unwrap_err();
    assert!(
        err.to_string().contains("signature mismatch"),
        "unexpected error: {err:#}"
    );

    Ok(())
}
