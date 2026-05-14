use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};

use crate::{
    app_state::AppState,
    s3_response::{S3ErrorKind, S3ErrorResponse},
};

pub async fn sigv4_auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();

    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return S3ErrorResponse::new(S3ErrorKind::InvalidRequest)
                .with_message(format!("failed to read request body: {err}"))
                .into_response();
        }
    };

    let req_for_validation = Request::from_parts(parts, body_bytes.clone());

    let principal = match state.sigv4_validator.validate(&req_for_validation).await {
        Ok(principal) => principal,
        Err(err) => {
            let msg = err.to_string().to_ascii_lowercase();
            let kind = if msg.contains("signature mismatch") {
                S3ErrorKind::SignatureDoesNotMatch
            } else if msg.contains("access key id") {
                S3ErrorKind::InvalidAccessKeyId
            } else {
                S3ErrorKind::AccessDenied
            };

            return S3ErrorResponse::new(kind)
                .with_message(err.to_string())
                .into_response();
        }
    };

    let (mut parts, _) = req_for_validation.into_parts();
    parts.extensions.insert(principal);

    let req = Request::from_parts(parts, Body::from(body_bytes));
    next.run(req).await
}
