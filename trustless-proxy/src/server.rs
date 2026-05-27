use thiserror::Error;

use crate::http_handler::{
    LocalTrustlessHttpHandler, LocalTrustlessHttpHandlerCompletion, LocalTrustlessHttpHandlerError,
    LocalTrustlessHttpHandlerPreparedResponse,
};
use crate::http_mapping::{
    LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext, LocalTrustlessHttpResponse,
};
use crate::runtime::LocalTrustlessRuntimePreparedResponse;
use crate::s3_surface::LocalS3Operation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessServerConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub max_request_body_bytes: u64,
    pub remote_gateway_url: Option<String>,
    pub network_bind_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessServerPreparedResponse {
    pub operation: LocalS3Operation,
    pub handler_prepared_response: LocalTrustlessHttpHandlerPreparedResponse,
    pub http_response: LocalTrustlessHttpResponse,
    pub config: LocalTrustlessServerConfig,
    pub pending_response: bool,
    pub network_bind_performed: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessServerCompletion {
    pub operation: LocalS3Operation,
    pub handler_completion: LocalTrustlessHttpHandlerCompletion,
    pub http_response: LocalTrustlessHttpResponse,
    pub config: LocalTrustlessServerConfig,
    pub network_bind_performed: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessServerError {
    #[error("local trustless server listen host is required")]
    MissingListenHost,

    #[error("local trustless server listen port must be greater than zero")]
    InvalidListenPort,

    #[error("local trustless server request body limit must be greater than zero")]
    InvalidRequestBodyLimit,

    #[error("local trustless server scaffold must not perform network binding yet")]
    NetworkBindNotImplemented,

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error(transparent)]
    HttpHandler(LocalTrustlessHttpHandlerError),
}

impl From<LocalTrustlessHttpHandlerError> for LocalTrustlessServerError {
    fn from(error: LocalTrustlessHttpHandlerError) -> Self {
        Self::HttpHandler(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessServer {
    config: LocalTrustlessServerConfig,
}

impl LocalTrustlessServer {
    pub fn new(config: LocalTrustlessServerConfig) -> Result<Self, LocalTrustlessServerError> {
        validate_config(&config)?;

        if config.network_bind_enabled {
            return Err(LocalTrustlessServerError::NetworkBindNotImplemented);
        }

        Ok(Self { config })
    }

    pub fn config(&self) -> &LocalTrustlessServerConfig {
        &self.config
    }

    pub fn prepare_http_request(
        &self,
        request: LocalTrustlessHttpRequest,
        context: LocalTrustlessHttpRequestContext,
    ) -> Result<LocalTrustlessServerPreparedResponse, LocalTrustlessServerError> {
        let handler_prepared_response =
            LocalTrustlessHttpHandler::prepare_http_request(request, context)?;

        if handler_prepared_response.gateway_plaintext_access
            || handler_prepared_response
                .http_response
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessServerError::GatewayPlaintextAccessRejected);
        }

        let operation = handler_prepared_response.operation;
        let http_response = handler_prepared_response.http_response.clone();

        Ok(LocalTrustlessServerPreparedResponse {
            operation,
            handler_prepared_response,
            http_response,
            config: self.config.clone(),
            pending_response: true,
            network_bind_performed: false,
            gateway_plaintext_access: false,
        })
    }

    pub fn complete_get_with_plaintext(
        &self,
        prepared: LocalTrustlessRuntimePreparedResponse,
        plaintext: Vec<u8>,
    ) -> Result<LocalTrustlessServerCompletion, LocalTrustlessServerError> {
        let handler_completion =
            LocalTrustlessHttpHandler::complete_get_with_plaintext(prepared, plaintext)?;

        if handler_completion.gateway_plaintext_access
            || handler_completion.http_response.gateway_plaintext_access
        {
            return Err(LocalTrustlessServerError::GatewayPlaintextAccessRejected);
        }

        let operation = handler_completion.operation;
        let http_response = handler_completion.http_response.clone();

        Ok(LocalTrustlessServerCompletion {
            operation,
            handler_completion,
            http_response,
            config: self.config.clone(),
            network_bind_performed: false,
            gateway_plaintext_access: false,
        })
    }
}

fn validate_config(config: &LocalTrustlessServerConfig) -> Result<(), LocalTrustlessServerError> {
    if config.listen_host.trim().is_empty() {
        return Err(LocalTrustlessServerError::MissingListenHost);
    }

    if config.listen_port == 0 {
        return Err(LocalTrustlessServerError::InvalidListenPort);
    }

    if config.max_request_body_bytes == 0 {
        return Err(LocalTrustlessServerError::InvalidRequestBodyLimit);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_mapping::{LocalTrustlessHttpMethod, LocalTrustlessHttpRequest};
    use crate::response_adapter::LocalTrustlessResponseState;
    use crate::service::TrustlessLocalServiceNextAction;

    fn config() -> LocalTrustlessServerConfig {
        LocalTrustlessServerConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            max_request_body_bytes: 10 * 1024 * 1024,
            remote_gateway_url: Some("http://127.0.0.1:3000".to_owned()),
            network_bind_enabled: false,
        }
    }

    fn context() -> LocalTrustlessHttpRequestContext {
        LocalTrustlessHttpRequestContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: Some(hex::encode([2u8; 32])),
            policy_version: 1,
            local_account: "alice".to_owned(),
            local_key_type: "aws-esdk-rust-recipient-key".to_owned(),
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    fn request(
        method: LocalTrustlessHttpMethod,
        path: &str,
        query: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> LocalTrustlessHttpRequest {
        LocalTrustlessHttpRequest {
            method,
            path: path.to_owned(),
            query: query.map(str::to_owned),
            body,
        }
    }

    #[test]
    fn server_accepts_non_binding_local_config() {
        let server = LocalTrustlessServer::new(config()).unwrap();

        assert_eq!(server.config().listen_host, "127.0.0.1");
        assert_eq!(server.config().listen_port, 9090);
        assert!(!server.config().network_bind_enabled);
    }

    #[test]
    fn server_rejects_network_binding_in_scaffold() {
        let err = LocalTrustlessServer::new(LocalTrustlessServerConfig {
            network_bind_enabled: true,
            ..config()
        })
        .unwrap_err();

        assert_eq!(err, LocalTrustlessServerError::NetworkBindNotImplemented);
    }

    #[test]
    fn server_rejects_invalid_config() {
        assert_eq!(
            LocalTrustlessServer::new(LocalTrustlessServerConfig {
                listen_host: " ".to_owned(),
                ..config()
            })
            .unwrap_err(),
            LocalTrustlessServerError::MissingListenHost
        );

        assert_eq!(
            LocalTrustlessServer::new(LocalTrustlessServerConfig {
                listen_port: 0,
                ..config()
            })
            .unwrap_err(),
            LocalTrustlessServerError::InvalidListenPort
        );

        assert_eq!(
            LocalTrustlessServer::new(LocalTrustlessServerConfig {
                max_request_body_bytes: 0,
                ..config()
            })
            .unwrap_err(),
            LocalTrustlessServerError::InvalidRequestBodyLimit
        );
    }

    #[test]
    fn server_prepares_put_http_request_without_binding_network_socket() {
        let server = LocalTrustlessServer::new(config()).unwrap();

        let prepared = server
            .prepare_http_request(
                request(
                    LocalTrustlessHttpMethod::Put,
                    "/bucket/secret.txt",
                    None,
                    Some(b"secret".to_vec()),
                ),
                context(),
            )
            .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::PutObject);
        assert_eq!(prepared.http_response.status_code, 202);
        assert!(prepared.pending_response);
        assert!(!prepared.network_bind_performed);
        assert_eq!(
            prepared
                .handler_prepared_response
                .runtime_prepared_response
                .response_envelope
                .state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert_eq!(
            prepared
                .handler_prepared_response
                .runtime_prepared_response
                .response_envelope
                .next_action,
            Some(TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest)
        );
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn server_prepares_get_http_request_as_pending_local_decrypt() {
        let server = LocalTrustlessServer::new(config()).unwrap();

        let prepared = server
            .prepare_http_request(
                request(
                    LocalTrustlessHttpMethod::Get,
                    "/bucket/secret.txt",
                    None,
                    None,
                ),
                context(),
            )
            .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::GetObject);
        assert_eq!(prepared.http_response.status_code, 202);
        assert!(!prepared.network_bind_performed);
        assert_eq!(
            prepared
                .handler_prepared_response
                .runtime_prepared_response
                .response_envelope
                .state,
            LocalTrustlessResponseState::PendingLocalDecrypt
        );
        assert_eq!(
            prepared
                .handler_prepared_response
                .runtime_prepared_response
                .response_envelope
                .next_action,
            Some(TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally)
        );
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn server_completes_get_with_local_plaintext_http_response() {
        let server = LocalTrustlessServer::new(config()).unwrap();

        let prepared = server
            .prepare_http_request(
                request(
                    LocalTrustlessHttpMethod::Get,
                    "/bucket/secret.txt",
                    None,
                    None,
                ),
                context(),
            )
            .unwrap();

        let completion = server
            .complete_get_with_plaintext(
                prepared.handler_prepared_response.runtime_prepared_response,
                b"secret".to_vec(),
            )
            .unwrap();

        assert_eq!(completion.operation, LocalS3Operation::GetObject);
        assert_eq!(completion.http_response.status_code, 200);
        assert_eq!(completion.http_response.body, Some(b"secret".to_vec()));
        assert!(completion.http_response.plaintext_returned_locally);
        assert!(!completion.network_bind_performed);
        assert!(!completion.gateway_plaintext_access);
    }

    #[test]
    fn server_prepares_trustless_bucket_create_without_remote_gateway() {
        let server = LocalTrustlessServer::new(config()).unwrap();

        let prepared = server
            .prepare_http_request(
                request(
                    LocalTrustlessHttpMethod::Put,
                    "/bucket",
                    Some("x-s3w-bucket-type=trustless-private"),
                    None,
                ),
                context(),
            )
            .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::CreateTrustlessBucket);
        assert_eq!(prepared.http_response.status_code, 202);
        assert!(!prepared.network_bind_performed);
        assert!(
            !prepared
                .handler_prepared_response
                .runtime_prepared_response
                .remote_gateway_required
        );
        assert_eq!(
            prepared
                .handler_prepared_response
                .runtime_prepared_response
                .response_envelope
                .state,
            LocalTrustlessResponseState::PendingTrustlessBucketAnchor
        );
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn server_rejects_plaintext_body_outside_put_boundary() {
        let server = LocalTrustlessServer::new(config()).unwrap();

        let err = server
            .prepare_http_request(
                request(
                    LocalTrustlessHttpMethod::Get,
                    "/bucket/secret.txt",
                    None,
                    Some(b"bad".to_vec()),
                ),
                context(),
            )
            .unwrap_err();

        assert!(matches!(err, LocalTrustlessServerError::HttpHandler(_)));
    }
}
