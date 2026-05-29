use anyhow::Result;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post, put},
};
use gateway::{
    app_state::build_production_state, auth, request_limits::max_request_body_bytes_from_env,
    routes,
};
use std::{env, net::SocketAddr};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "gateway=info".into()),
        )
        .init();

    let state = build_production_state().await?;
    let max_request_body_bytes = max_request_body_bytes_from_env()?;

    tracing::info!(
        max_request_body_bytes,
        "configured gateway request body limit"
    );

    let authenticated_routes = Router::new()
        .route(
            "/trustless/v1/ciphertext-gateway",
            post(routes::trustless_ciphertext_gateway::handle),
        )
        .route("/", get(routes::list_bucket::handle))
        .route(
            "/{bucket}",
            put(routes::create_bucket::handle)
                .get(routes::list_objects_v2::handle)
                .delete(routes::delete_bucket::handle),
        )
        .route(
            "/{bucket}/{*key}",
            put(routes::put_object::handle)
                .get(routes::get_object::handle)
                .head(routes::head_object::handle)
                .delete(routes::delete_object::handle),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::sigv4_auth_middleware,
        ));

    let app = Router::new()
        .merge(authenticated_routes)
        .layer(DefaultBodyLimit::max(max_request_body_bytes))
        .with_state(state);

    let bind_addr = env::var("S3GW_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8000".to_string())
        .parse::<SocketAddr>()?;

    let listener = TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
