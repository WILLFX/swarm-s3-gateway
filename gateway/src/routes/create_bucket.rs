use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::Response,
};
use common::types::AwsPrincipal;

use crate::{
    app_state::AppState,
    crypto::bucket_name_hash,
    manifest::{read_owner_catalog_manifest, write_owner_catalog_manifest},
    s3_response::{S3ErrorKind, S3ErrorResponse, chain_error_response, create_bucket_response},
};

const OWNER_SIGNATURE_HEADER: &str = "x-s3gw-owner-signature";
const BUCKET_VISIBILITY_HEADER: &str = "x-s3gw-bucket-visibility";
const BUCKET_TYPE_HEADER: &str = "x-s3gw-bucket-type";
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

    let bucket_id = bucket_name_hash(&principal.owner, &bucket);

    match state.registry_client.fetch_bucket(bucket_id).await {
        Ok(Some(_)) => {
            return S3ErrorResponse::new(S3ErrorKind::BucketAlreadyOwnedByYou)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
        Ok(None) => {}
        Err(err) => return chain_error_response(err),
    }

    let mode = match parse_bucket_create_mode(&headers) {
        Ok(value) => value,
        Err(message) => {
            return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                .with_message(message)
                .with_resource(format!("/{bucket}"))
                .into_response();
        }
    };

    match mode {
        CreateBucketMode::Legacy { is_private } => {
            let (expected_owner_catalog_root, owner_catalog_root) =
                match write_owner_catalog_with_bucket(&state, principal.owner, &bucket).await {
                    Ok(roots) => roots,
                    Err(err) => {
                        return S3ErrorResponse::new(S3ErrorKind::InternalError)
                            .with_message(format!("failed to write owner bucket catalog: {err}"))
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
                Ok(_) => create_bucket_response(&bucket),
                Err(err) => chain_error_response(err),
            }
        }
        CreateBucketMode::TrustlessPrivate => {
            let roots = match parse_trustless_owner_catalog_roots(&headers) {
                Ok(roots) => roots,
                Err(message) => {
                    return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                        .with_message(message)
                        .with_resource(format!("/{bucket}"))
                        .into_response();
                }
            };

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
                Ok(_) => create_bucket_response(&bucket),
                Err(err) => chain_error_response(err),
            }
        }
    }
}

enum CreateBucketMode {
    Legacy { is_private: bool },
    TrustlessPrivate,
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
