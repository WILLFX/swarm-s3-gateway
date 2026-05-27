use thiserror::Error;

use crate::http_mapping::{
    LocalTrustlessHttpMapper, LocalTrustlessHttpMappingError, LocalTrustlessHttpRequest,
    LocalTrustlessHttpRequestContext, LocalTrustlessHttpResponse,
};
use crate::runtime::{
    LocalTrustlessRuntime, LocalTrustlessRuntimeCompletion, LocalTrustlessRuntimeError,
    LocalTrustlessRuntimePreparedResponse,
};
use crate::s3_surface::LocalS3Operation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessHttpHandlerPreparedResponse {
    pub operation: LocalS3Operation,
    pub runtime_prepared_response: LocalTrustlessRuntimePreparedResponse,
    pub http_response: LocalTrustlessHttpResponse,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessHttpHandlerCompletion {
    pub operation: LocalS3Operation,
    pub runtime_completion: LocalTrustlessRuntimeCompletion,
    pub http_response: LocalTrustlessHttpResponse,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessHttpHandlerError {
    #[error(transparent)]
    HttpMapping(LocalTrustlessHttpMappingError),

    #[error(transparent)]
    Runtime(LocalTrustlessRuntimeError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,
}

impl From<LocalTrustlessHttpMappingError> for LocalTrustlessHttpHandlerError {
    fn from(error: LocalTrustlessHttpMappingError) -> Self {
        Self::HttpMapping(error)
    }
}

impl From<LocalTrustlessRuntimeError> for LocalTrustlessHttpHandlerError {
    fn from(error: LocalTrustlessRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

pub struct LocalTrustlessHttpHandler;

impl LocalTrustlessHttpHandler {
    pub fn prepare_http_request(
        request: LocalTrustlessHttpRequest,
        context: LocalTrustlessHttpRequestContext,
    ) -> Result<LocalTrustlessHttpHandlerPreparedResponse, LocalTrustlessHttpHandlerError> {
        let local_input = LocalTrustlessHttpMapper::request_to_local_input(request, context)?;
        let runtime_prepared_response = LocalTrustlessRuntime::prepare_request(local_input)?;

        if runtime_prepared_response.gateway_plaintext_access
            || runtime_prepared_response
                .response_envelope
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessHttpHandlerError::GatewayPlaintextAccessRejected);
        }

        let operation = runtime_prepared_response.operation;
        let http_response = LocalTrustlessHttpMapper::response_from_envelope(
            runtime_prepared_response.response_envelope.clone(),
        )?;

        if http_response.gateway_plaintext_access {
            return Err(LocalTrustlessHttpHandlerError::GatewayPlaintextAccessRejected);
        }

        Ok(LocalTrustlessHttpHandlerPreparedResponse {
            operation,
            runtime_prepared_response,
            http_response,
            gateway_plaintext_access: false,
        })
    }

    pub fn complete_get_with_plaintext(
        prepared: LocalTrustlessRuntimePreparedResponse,
        plaintext: Vec<u8>,
    ) -> Result<LocalTrustlessHttpHandlerCompletion, LocalTrustlessHttpHandlerError> {
        let runtime_completion =
            LocalTrustlessRuntime::complete_get_with_plaintext(prepared, plaintext)?;

        if runtime_completion.gateway_plaintext_access
            || runtime_completion
                .response_envelope
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessHttpHandlerError::GatewayPlaintextAccessRejected);
        }

        let operation = runtime_completion.operation;
        let http_response = LocalTrustlessHttpMapper::response_from_envelope(
            runtime_completion.response_envelope.clone(),
        )?;

        if http_response.gateway_plaintext_access {
            return Err(LocalTrustlessHttpHandlerError::GatewayPlaintextAccessRejected);
        }

        Ok(LocalTrustlessHttpHandlerCompletion {
            operation,
            runtime_completion,
            http_response,
            gateway_plaintext_access: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_mapping::{LocalTrustlessHttpMethod, LocalTrustlessHttpRequest};
    use crate::response_adapter::LocalTrustlessResponseState;
    use crate::service::TrustlessLocalServiceNextAction;

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
    fn http_handler_prepares_put_as_pending_ciphertext_remote_http_response() {
        let prepared = LocalTrustlessHttpHandler::prepare_http_request(
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
        assert!(prepared.http_response.body.is_none());
        assert!(prepared.http_response.headers.contains(&(
            "x-s3w-gateway-plaintext-access".to_owned(),
            "false".to_owned()
        )));
        assert_eq!(
            prepared.runtime_prepared_response.response_envelope.state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert_eq!(
            prepared
                .runtime_prepared_response
                .response_envelope
                .next_action,
            Some(TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest)
        );
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn http_handler_prepares_get_as_pending_local_decrypt_http_response() {
        let prepared = LocalTrustlessHttpHandler::prepare_http_request(
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
        assert!(prepared.http_response.body.is_none());
        assert_eq!(
            prepared.runtime_prepared_response.response_envelope.state,
            LocalTrustlessResponseState::PendingLocalDecrypt
        );
        assert_eq!(
            prepared
                .runtime_prepared_response
                .response_envelope
                .next_action,
            Some(TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally)
        );
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn http_handler_completes_get_as_local_plaintext_http_response() {
        let prepared = LocalTrustlessHttpHandler::prepare_http_request(
            request(
                LocalTrustlessHttpMethod::Get,
                "/bucket/secret.txt",
                None,
                None,
            ),
            context(),
        )
        .unwrap();

        let completion = LocalTrustlessHttpHandler::complete_get_with_plaintext(
            prepared.runtime_prepared_response,
            b"secret".to_vec(),
        )
        .unwrap();

        assert_eq!(completion.operation, LocalS3Operation::GetObject);
        assert_eq!(completion.http_response.status_code, 200);
        assert_eq!(completion.http_response.body, Some(b"secret".to_vec()));
        assert!(completion.http_response.plaintext_returned_locally);
        assert_eq!(
            completion.runtime_completion.response_envelope.state,
            LocalTrustlessResponseState::ReadyLocalPlaintext
        );
        assert!(!completion.gateway_plaintext_access);
    }

    #[test]
    fn http_handler_prepares_head_delete_and_list_pending_responses() {
        for (method, path, query, operation) in [
            (
                LocalTrustlessHttpMethod::Head,
                "/bucket/secret.txt",
                None,
                LocalS3Operation::HeadObject,
            ),
            (
                LocalTrustlessHttpMethod::Delete,
                "/bucket/secret.txt",
                None,
                LocalS3Operation::DeleteObject,
            ),
            (
                LocalTrustlessHttpMethod::Get,
                "/bucket",
                Some("list-type=2&prefix=docs/"),
                LocalS3Operation::ListObjectsV2,
            ),
        ] {
            let prepared = LocalTrustlessHttpHandler::prepare_http_request(
                request(method, path, query, None),
                context(),
            )
            .unwrap();

            assert_eq!(prepared.operation, operation);
            assert_eq!(prepared.http_response.status_code, 202);
            assert_eq!(
                prepared.runtime_prepared_response.response_envelope.state,
                LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
            );
            assert!(!prepared.gateway_plaintext_access);
        }
    }

    #[test]
    fn http_handler_prepares_trustless_bucket_create_pending_anchor_response() {
        let prepared = LocalTrustlessHttpHandler::prepare_http_request(
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
        assert_eq!(
            prepared.runtime_prepared_response.response_envelope.state,
            LocalTrustlessResponseState::PendingTrustlessBucketAnchor
        );
        assert_eq!(
            prepared
                .runtime_prepared_response
                .response_envelope
                .next_action,
            Some(TrustlessLocalServiceNextAction::CreateTrustlessBucketAnchor)
        );
        assert!(!prepared.runtime_prepared_response.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn http_handler_rejects_plaintext_body_outside_put_object() {
        let err = LocalTrustlessHttpHandler::prepare_http_request(
            request(
                LocalTrustlessHttpMethod::Get,
                "/bucket/secret.txt",
                None,
                Some(b"bad".to_vec()),
            ),
            context(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessHttpHandlerError::HttpMapping(_)
        ));
    }

    #[test]
    fn http_handler_rejects_unsupported_post_method() {
        let err = LocalTrustlessHttpHandler::prepare_http_request(
            request(
                LocalTrustlessHttpMethod::Post,
                "/bucket/secret.txt",
                None,
                None,
            ),
            context(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessHttpHandlerError::HttpMapping(_)
        ));
    }

    #[test]
    fn http_handler_rejects_completing_non_get_as_plaintext() {
        let prepared = LocalTrustlessHttpHandler::prepare_http_request(
            request(
                LocalTrustlessHttpMethod::Put,
                "/bucket/secret.txt",
                None,
                Some(b"secret".to_vec()),
            ),
            context(),
        )
        .unwrap();

        let err = LocalTrustlessHttpHandler::complete_get_with_plaintext(
            prepared.runtime_prepared_response,
            b"secret".to_vec(),
        )
        .unwrap_err();

        assert!(matches!(err, LocalTrustlessHttpHandlerError::Runtime(_)));
    }
}
