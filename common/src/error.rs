use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("internal: {0}")]
    Internal(String),
}// common crate error definitions
