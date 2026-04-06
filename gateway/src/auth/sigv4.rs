use crate::traits::{RegistryClient, SecretUnwrapper};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use axum::http::{HeaderMap, Method, Request};
use bytes::Bytes;
use common::types::{AccessKeyHash, AwsPrincipal};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

pub struct RegistryBackedSigV4Validator {
    pub registry: Arc<dyn RegistryClient>,
    pub unwrapper: Arc<dyn SecretUnwrapper>,
    pub expected_service: String,        // "s3"
    pub expected_region: Option<String>, // None = accept any region
    pub allow_unsigned_payload: bool,
}

impl RegistryBackedSigV4Validator {
    pub async fn validate(&self, req: &Request<Bytes>) -> Result<AwsPrincipal> {
        let auth = header_str(req.headers(), "authorization")?;
        let amz_date = header_str(req.headers(), "x-amz-date")?;
        let payload_hash = header_str(req.headers(), "x-amz-content-sha256")?;

        let parsed = parse_authorization(auth)?;
        if parsed.algorithm != "AWS4-HMAC-SHA256" {
            bail!("unsupported authorization algorithm");
        }

        if parsed.service != self.expected_service {
            bail!("unexpected service in credential scope");
        }

        if let Some(expected_region) = &self.expected_region {
            if &parsed.region != expected_region {
                bail!("unexpected region in credential scope");
            }
        }

        let access_key_hash = hash_access_key_id(&parsed.access_key_id);

        // Async chain auth query (non-blocking)
        let entry = self.registry.fetch_entry(access_key_hash).await?;
        if !entry.enabled {
            bail!("credential disabled");
        }

        let secret = self
            .unwrapper
            .unwrap_sigv4_secret(
                entry.key_version,
                &entry.nonce,
                &entry.encrypted_sigv4_secret,
                &access_key_hash,
            )
            .await?;

        let local_payload_hash = hex::encode(Sha256::digest(req.body()));
        let payload_ok = if payload_hash == "UNSIGNED-PAYLOAD" {
            self.allow_unsigned_payload
        } else {
            payload_hash == local_payload_hash
        };

        if !payload_ok {
            bail!("payload hash mismatch");
        }

        let canonical_request = build_canonical_request(
            req.method(),
            req.uri().path(),
            req.uri().query().unwrap_or(""),
            req.headers(),
            &parsed.signed_headers,
            payload_hash,
        )?;

        let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date, parsed.credential_scope, canonical_request_hash
        );

        let secret_str = std::str::from_utf8(&secret).context("SigV4 secret is not valid UTF-8")?;
        let signing_key =
            derive_signing_key(secret_str, &parsed.date, &parsed.region, &parsed.service)?;

        let expected_sig = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

        if !constant_time_eq(expected_sig.as_bytes(), parsed.signature.as_bytes()) {
            bail!("signature mismatch");
        }

        Ok(AwsPrincipal {
            access_key_id: parsed.access_key_id,
            owner: entry.owner,
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedAuthorization {
    algorithm: String,
    access_key_id: String,
    date: String,
    region: String,
    service: String,
    credential_scope: String,
    signed_headers: Vec<String>,
    signature: String,
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    headers
        .get(name)
        .ok_or_else(|| anyhow!("missing required header: {name}"))?
        .to_str()
        .context("invalid header value")
}

fn parse_authorization(auth: &str) -> Result<ParsedAuthorization> {
    // AWS4-HMAC-SHA256 Credential=AKIA.../YYYYMMDD/REGION/s3/aws4_request, SignedHeaders=..., Signature=...
    let (algorithm, rest) = auth
        .split_once(' ')
        .ok_or_else(|| anyhow!("malformed authorization header"))?;

    let mut credential = None::<String>;
    let mut signed_headers = None::<Vec<String>>;
    let mut signature = None::<String>;

    for part in rest.split(',') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix("Credential=") {
            credential = Some(v.to_string());
        } else if let Some(v) = p.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v.split(';').map(|s| s.to_ascii_lowercase()).collect());
        } else if let Some(v) = p.strip_prefix("Signature=") {
            signature = Some(v.to_string());
        }
    }

    let credential = credential.ok_or_else(|| anyhow!("missing Credential in authorization"))?;
    let signed_headers =
        signed_headers.ok_or_else(|| anyhow!("missing SignedHeaders in authorization"))?;
    let signature = signature.ok_or_else(|| anyhow!("missing Signature in authorization"))?;

    let mut parts = credential.split('/');
    let access_key_id = parts
        .next()
        .ok_or_else(|| anyhow!("bad credential scope"))?
        .to_string();
    let date = parts
        .next()
        .ok_or_else(|| anyhow!("bad credential scope"))?
        .to_string();
    let region = parts
        .next()
        .ok_or_else(|| anyhow!("bad credential scope"))?
        .to_string();
    let service = parts
        .next()
        .ok_or_else(|| anyhow!("bad credential scope"))?
        .to_string();
    let terminal = parts
        .next()
        .ok_or_else(|| anyhow!("bad credential scope"))?;

    if terminal != "aws4_request" {
        bail!("bad terminal credential scope");
    }

    let credential_scope = format!("{date}/{region}/{service}/aws4_request");

    Ok(ParsedAuthorization {
        algorithm: algorithm.to_string(),
        access_key_id,
        date,
        region,
        service,
        credential_scope,
        signed_headers,
        signature,
    })
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
            .context("invalid signed header value")?
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

fn canonical_uri(path: &str) -> String {
    // Minimal RFC3986-compatible path normalization for S3-style endpoints.
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
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

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).context("failed to initialize HMAC")?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Result<Vec<u8>> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    hmac_sha256(&k_service, b"aws4_request")
}

fn hash_access_key_id(access_key_id: &str) -> AccessKeyHash {
    let digest = Sha256::digest(access_key_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::unwrap::EnvKeyUnwrapper;
    use crate::traits::{RegistryClient, SecretUnwrapper};
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use axum::http::{HeaderValue, Method, Request, Uri};
    use bytes::Bytes;
    use common::types::{ChainRegistryEntry, SubstrateAddress32};
    use std::sync::Arc;
    use zeroize::Zeroizing;

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

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn encrypt_sigv4_secret(
        master_key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext_secret: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(master_key)?;
        let ciphertext = cipher.encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext_secret,
                aad,
            },
        )?;
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
        // ------------------------------------------------------------------
        // 1. Setup: known plaintext secret + known master key
        // ------------------------------------------------------------------
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
            nonce: nonce.to_vec(),
            key_version: 1,
            enabled: true,
        };

        // ------------------------------------------------------------------
        // 2. Fetch: mock registry client
        // ------------------------------------------------------------------
        let registry = Arc::new(MockRegistryClient {
            expected_hash: access_key_hash,
            entry: registry_entry,
        });

        // ------------------------------------------------------------------
        // 3. Unwrap: use EnvKeyUnwrapper with test master key
        // ------------------------------------------------------------------
        let unwrapper: Arc<dyn SecretUnwrapper> =
            Arc::new(EnvKeyUnwrapper::new(Zeroizing::new(master_key)));

        let validator = RegistryBackedSigV4Validator {
            registry,
            unwrapper,
            expected_service: "s3".to_string(),
            expected_region: Some("us-east-1".to_string()),
            allow_unsigned_payload: false,
        };

        // ------------------------------------------------------------------
        // 4. Validate: build a dummy request with a valid SigV4 signature
        // ------------------------------------------------------------------
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

        // ------------------------------------------------------------------
        // 5. Requirement: principal resolves and owner matches
        // ------------------------------------------------------------------
        assert_eq!(principal.access_key_id, access_key_id);
        assert_eq!(principal.owner, owner);

        Ok(())
    }
}
