use anyhow::Result;
use axum::{
    extract::{Extension, State},
    response::Response,
};
use common::types::AwsPrincipal;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    app_state::AppState,
    crypto::bucket_name_hash,
    manifest::read_owner_catalog_manifest,
    s3_response::{BucketSummary, S3ErrorKind, S3ErrorResponse, list_buckets_response},
};

pub async fn handle(
    Extension(principal): Extension<AwsPrincipal>,
    State(state): State<AppState>,
) -> Response {
    let buckets = match load_owner_buckets(&state, &principal).await {
        Ok(buckets) => buckets,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InternalError)
                .with_message(format!("failed to load owner bucket catalog: {err}"))
                .into_response();
        }
    };

    let owner = hex::encode(principal.owner);
    list_buckets_response(&owner, &owner, &buckets)
}

async fn load_owner_buckets(
    state: &AppState,
    principal: &AwsPrincipal,
) -> Result<Vec<BucketSummary>> {
    let root = state
        .registry_client
        .fetch_owner_catalog_root(principal.owner)
        .await?;

    let catalog = read_owner_catalog_manifest(
        state.bee_client.as_ref(),
        &state.master_service_key,
        &principal.owner,
        &root,
    )
    .await?;

    let mut buckets = Vec::new();

    for bucket_name in catalog.buckets.keys() {
        let bucket_id = bucket_name_hash(&principal.owner, bucket_name);

        if let Some(record) = state.registry_client.fetch_bucket(bucket_id).await? {
            buckets.push(BucketSummary {
                name: bucket_name.clone(),
                creation_date: format_creation_date(record.creation_date),
            });
        }
    }

    buckets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(buckets)
}

fn format_creation_date(timestamp: u64) -> String {
    let seconds = if timestamp > 10_000_000_000 {
        timestamp / 1000
    } else {
        timestamp
    };

    match OffsetDateTime::from_unix_timestamp(seconds as i64) {
        Ok(dt) => dt
            .format(&Rfc3339)
            .unwrap_or_else(|_| timestamp.to_string()),
        Err(_) => timestamp.to_string(),
    }
}
