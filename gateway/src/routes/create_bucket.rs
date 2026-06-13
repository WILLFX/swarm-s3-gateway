use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use common::types::AwsPrincipal;

use crate::{
    app_state::AppState,
    crypto::bucket_name_hash,
    idempotency::{
        begin_from_headers, persist_stored_success, replay_http_response, request_digest_hex,
        s3_idempotency_error_response, s3_idempotency_persist_error_response, s3_record_failure,
        stored_empty_response, stored_header_response, DigestPart, IdempotencyDecision,
        IdempotencyReservation, StoredHeader,
    },
    manifest::{read_owner_catalog_manifest, write_owner_catalog_manifest},
    s3_response::{chain_error_response, create_bucket_response, S3ErrorKind, S3ErrorResponse},
};
use sha2::{Digest, Sha256};

const OWNER_SIGNATURE_HEADER: &str = "x-s3gw-owner-signature";
const BUCKET_VISIBILITY_HEADER: &str = "x-s3gw-bucket-visibility";
const BUCKET_TYPE_HEADER: &str = "x-s3gw-bucket-type";
const TRUSTLESS_BUCKET_ID_HEADER: &str = "x-s3w-bucket-id";
const EXPECTED_OWNER_CATALOG_ROOT_HEADER: &str = "x-s3gw-expected-owner-catalog-root";
const OWNER_CATALOG_ROOT_HEADER: &str = "x-s3gw-owner-catalog-root";

pub async fn handle(
    Path(bucket): Path<String>,
    Extension(principal): Extension<AwsPrincipal>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(message) = validate_bucket_name(&bucket) {
        return S3ErrorResponse::new(S3ErrorKind::InvalidBucketName)
            .with_message(message)
            .with_resource(format!("/{bucket}"))
            .into_response();
    }

    let owner_signature = match parse_owner_signature(&headers) {
        Ok(signature) => signature,
        Err(message) => {
            return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                .with_message(message)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
    };

    let mode = match parse_bucket_create_mode(&headers) {
        Ok(value) => value,
        Err(message) => {
            return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                .with_message(message)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
    };

    let bucket_id = match bucket_id_for_create_mode(&headers, &mode, &principal.owner, &bucket) {
        Ok(value) => value,
        Err(message) => {
            return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                .with_message(message)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
    };

    let trustless_roots = match mode {
        CreateBucketMode::TrustlessPrivate => match parse_trustless_owner_catalog_roots(&headers) {
            Ok(roots) => Some(roots),
            Err(message) => {
                return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                    .with_message(message)
                    .with_resource(format!("/{bucket}"))
                    .into_response();
            }
        },
        CreateBucketMode::Legacy { .. } => None,
    };

    let idempotency = match begin_create_bucket_idempotency(
        &state,
        &headers,
        &principal,
        bucket_id,
        &bucket,
        owner_signature,
        mode,
        trustless_roots.as_ref(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };

    match state.registry_client.fetch_bucket(bucket_id).await {
        Ok(Some(_)) => {
            s3_record_failure(idempotency, "create bucket found existing bucket").await;
            return S3ErrorResponse::new(S3ErrorKind::BucketAlreadyOwnedByYou)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
        Ok(None) => {}
        Err(err) => {
            s3_record_failure(idempotency, format!("create bucket fetch failed: {err}")).await;
            return chain_error_response(err);
        }
    }

    match mode {
        CreateBucketMode::Legacy { is_private } => {
            let (expected_owner_catalog_root, owner_catalog_root) =
                match write_owner_catalog_with_bucket(&state, principal.owner, &bucket).await {
                    Ok(roots) => roots,
                    Err(err) => {
                        let message = format!("failed to write owner bucket catalog: {err}");
                        s3_record_failure(idempotency, message.clone()).await;
                        return S3ErrorResponse::new(S3ErrorKind::InternalError)
                            .with_message(message)
                            .with_resource(format!("/{bucket}"))
                            .into_response();
                    }
                };

            match state
                .anchor_client
                .create_bucket_anchor(
                    principal.owner,
                    bucket_id,
                    is_private,
                    owner_signature,
                    expected_owner_catalog_root,
                    owner_catalog_root,
                )
                .await
            {
                Ok(_) => complete_create_bucket_idempotency(idempotency, &bucket, mode).await,
                Err(err) => {
                    s3_record_failure(idempotency, format!("create bucket anchor failed: {err}"))
                        .await;
                    chain_error_response(err)
                }
            }
        }
        CreateBucketMode::TrustlessPrivate => {
            let roots = trustless_roots
                .expect("trustless owner catalog roots are parsed before idempotency reservation");

            match state
                .anchor_client
                .create_trustless_bucket_anchor(
                    principal.owner,
                    bucket_id,
                    owner_signature,
                    roots.expected_owner_catalog_root,
                    roots.owner_catalog_root,
                )
                .await
            {
                Ok(_) => complete_create_bucket_idempotency(idempotency, &bucket, mode).await,
                Err(err) => {
                    s3_record_failure(
                        idempotency,
                        format!("create trustless bucket anchor failed: {err}"),
                    )
                    .await;
                    chain_error_response(err)
                }
            }
        }
    }
}

async fn complete_create_bucket_idempotency(
    idempotency: Option<IdempotencyReservation>,
    bucket: &str,
    mode: CreateBucketMode,
) -> Response {
    let stored = match mode {
        CreateBucketMode::TrustlessPrivate => stored_empty_response(StatusCode::OK),
        CreateBucketMode::Legacy { .. } => {
            let location = format!("/{bucket}");
            stored_header_response(
                StatusCode::OK,
                vec![StoredHeader {
                    name: "location".to_string(),
                    value: location,
                }],
            )
        }
    };
    if let Err(err) = persist_stored_success(idempotency, stored).await {
        return s3_idempotency_persist_error_response(err, format!("/{bucket}"));
    }

    create_bucket_response(bucket)
}

#[derive(Debug, Clone, Copy)]
enum CreateBucketMode {
    Legacy { is_private: bool },
    TrustlessPrivate,
}

async fn begin_create_bucket_idempotency(
    state: &AppState,
    headers: &HeaderMap,
    principal: &AwsPrincipal,
    bucket_id: [u8; 32],
    bucket: &str,
    owner_signature: [u8; 64],
    mode: CreateBucketMode,
    trustless_roots: Option<&TrustlessOwnerCatalogRoots>,
) -> Result<Option<IdempotencyReservation>, Response> {
    let bucket_name_hash = sha256_32(bucket.as_bytes());
    let (mode_name, is_private) = match mode {
        CreateBucketMode::Legacy { is_private } if is_private => ("trusted-gateway-private", true),
        CreateBucketMode::Legacy { .. } => ("public", false),
        CreateBucketMode::TrustlessPrivate => ("trustless-private", true),
    };
    let digest = request_digest_hex(
        "s3gw/idempotency/v1/create-bucket",
        &[
            DigestPart::Bytes(&principal.owner),
            DigestPart::Bytes(&bucket_id),
            DigestPart::Bytes(&bucket_name_hash),
            DigestPart::String(mode_name),
            DigestPart::Bool(is_private),
            DigestPart::Bytes(&owner_signature),
            DigestPart::OptionalString(
                trustless_roots.map(|roots| roots.expected_owner_catalog_root.as_str()),
            ),
            DigestPart::OptionalString(
                trustless_roots.map(|roots| roots.owner_catalog_root.as_str()),
            ),
        ],
    );

    match begin_from_headers(state.idempotency_store.as_ref(), headers, digest).await {
        Ok(Some(IdempotencyDecision::Fresh(reservation))) => Ok(Some(reservation)),
        Ok(Some(IdempotencyDecision::Replay(stored))) => Err(replay_http_response(stored)),
        Ok(None) => Ok(None),
        Err(err) => Err(s3_idempotency_error_response(err, format!("/{bucket}"))),
    }
}

fn bucket_id_for_create_mode(
    headers: &HeaderMap,
    mode: &CreateBucketMode,
    owner: &common::types::SubstrateAddress32,
    bucket: &str,
) -> Result<[u8; 32], String> {
    match mode {
        CreateBucketMode::Legacy { .. } => Ok(bucket_name_hash(owner, bucket)),
        CreateBucketMode::TrustlessPrivate => parse_trustless_bucket_id_header(headers),
    }
}

fn parse_trustless_bucket_id_header(headers: &HeaderMap) -> Result<[u8; 32], String> {
    let value = headers
        .get(TRUSTLESS_BUCKET_ID_HEADER)
        .ok_or_else(|| format!("missing required header: {TRUSTLESS_BUCKET_ID_HEADER}"))?
        .to_str()
        .map_err(|_| format!("{TRUSTLESS_BUCKET_ID_HEADER} must be valid ASCII hex"))?
        .trim();

    if value.is_empty() {
        return Err(format!(
            "{TRUSTLESS_BUCKET_ID_HEADER} must be a 32-byte hex bucket id"
        ));
    }

    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|err| format!("{TRUSTLESS_BUCKET_ID_HEADER} must be hex: {err}"))?;

    if bytes.len() != 32 {
        return Err(format!(
            "{TRUSTLESS_BUCKET_ID_HEADER} must decode to exactly 32 bytes, got {}",
            bytes.len()
        ));
    }

    bytes
        .try_into()
        .map_err(|_| format!("{TRUSTLESS_BUCKET_ID_HEADER} must be a 32-byte hex bucket id"))
}

struct TrustlessOwnerCatalogRoots {
    expected_owner_catalog_root: String,
    owner_catalog_root: String,
}

fn parse_bucket_create_mode(headers: &HeaderMap) -> Result<CreateBucketMode, String> {
    let Some(value) = headers.get(BUCKET_TYPE_HEADER) else {
        return Ok(CreateBucketMode::Legacy {
            is_private: parse_bucket_visibility(headers)?,
        });
    };

    let value = value
        .to_str()
        .map_err(|_| format!("{BUCKET_TYPE_HEADER} must be valid ASCII"))?
        .trim()
        .to_ascii_lowercase();

    match value.as_str() {
        "public" => Ok(CreateBucketMode::Legacy { is_private: false }),
        "private" | "trusted-gateway-private" | "trusted_gateway_private" => {
            Ok(CreateBucketMode::Legacy { is_private: true })
        }
        "trustless-private" | "trustless_private" => Ok(CreateBucketMode::TrustlessPrivate),
        _ => Err(format!(
            "{BUCKET_TYPE_HEADER} must be one of 'public', 'trusted-gateway-private', or 'trustless-private'"
        )),
    }
}

fn parse_trustless_owner_catalog_roots(
    headers: &HeaderMap,
) -> Result<TrustlessOwnerCatalogRoots, String> {
    Ok(TrustlessOwnerCatalogRoots {
        expected_owner_catalog_root: parse_catalog_root_header(
            headers,
            EXPECTED_OWNER_CATALOG_ROOT_HEADER,
            true,
        )?,
        owner_catalog_root: parse_catalog_root_header(headers, OWNER_CATALOG_ROOT_HEADER, false)?,
    })
}

fn parse_catalog_root_header(
    headers: &HeaderMap,
    name: &'static str,
    allow_empty: bool,
) -> Result<String, String> {
    let value = headers
        .get(name)
        .ok_or_else(|| format!("missing required header: {name}"))?
        .to_str()
        .map_err(|_| format!("{name} must be valid ASCII hex"))?
        .trim();

    if value.is_empty() || value.eq_ignore_ascii_case("empty") {
        if allow_empty {
            return Ok(String::new());
        }

        return Err(format!("{name} must be a 32-byte hex Swarm reference"));
    }

    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| format!("{name} must be hex: {err}"))?;

    if bytes.len() != 32 {
        return Err(format!(
            "{name} must decode to exactly 32 bytes, got {}",
            bytes.len()
        ));
    }

    Ok(hex::encode(bytes))
}

fn parse_owner_signature(headers: &HeaderMap) -> Result<[u8; 64], String> {
    let value = headers
        .get(OWNER_SIGNATURE_HEADER)
        .ok_or_else(|| format!("missing required header: {OWNER_SIGNATURE_HEADER}"))?
        .to_str()
        .map_err(|_| format!("{OWNER_SIGNATURE_HEADER} must be valid ASCII hex"))?;

    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|err| format!("{OWNER_SIGNATURE_HEADER} must be hex: {err}"))?;

    bytes
        .try_into()
        .map_err(|_| format!("{OWNER_SIGNATURE_HEADER} must decode to exactly 64 bytes"))
}

fn parse_bucket_visibility(headers: &HeaderMap) -> Result<bool, String> {
    let Some(value) = headers.get(BUCKET_VISIBILITY_HEADER) else {
        return Ok(false);
    };

    let value = value
        .to_str()
        .map_err(|_| format!("{BUCKET_VISIBILITY_HEADER} must be valid ASCII"))?
        .trim()
        .to_ascii_lowercase();

    match value.as_str() {
        "private" => Ok(true),
        "public" => Ok(false),
        _ => Err(format!(
            "{BUCKET_VISIBILITY_HEADER} must be either 'private' or 'public'"
        )),
    }
}

fn validate_bucket_name(bucket: &str) -> Result<(), String> {
    if bucket.len() < 3 || bucket.len() > 63 {
        return Err("bucket name must be between 3 and 63 characters".to_string());
    }

    if bucket.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err("bucket name must not be formatted as an IP address".to_string());
    }

    let bytes = bucket.as_bytes();

    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err("bucket name must start with a lowercase letter or digit".to_string());
    }

    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return Err("bucket name must end with a lowercase letter or digit".to_string());
    }

    if bucket.contains("..") {
        return Err("bucket name must not contain consecutive periods".to_string());
    }

    for ch in bucket.chars() {
        let ok = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-';
        if !ok {
            return Err(
                "bucket name may contain only lowercase letters, digits, dots, and hyphens"
                    .to_string(),
            );
        }
    }

    Ok(())
}

async fn write_owner_catalog_with_bucket(
    state: &AppState,
    owner: common::types::SubstrateAddress32,
    bucket: &str,
) -> anyhow::Result<(String, String)> {
    let root = state
        .registry_client
        .fetch_owner_catalog_root(owner)
        .await?;

    let mut catalog = read_owner_catalog_manifest(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &owner,
        &root,
    )
    .await?;

    catalog.buckets.insert(bucket.to_string(), String::new());

    let record = write_owner_catalog_manifest(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &owner,
        &catalog,
    )
    .await?;

    Ok((hex::encode(root), record.manifest_reference))
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
