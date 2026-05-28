use thiserror::Error;

use crate::gateway_boundary::{
    CiphertextGatewayBoundary, CiphertextGatewayBoundaryError, CiphertextGatewayRequest,
    CiphertextGatewayResponse,
};
use crate::planner::RemoteGatewayAction;

pub trait TrustlessRemoteGatewayClient {
    fn execute_ciphertext_request(
        &self,
        request: CiphertextGatewayRequest,
    ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteGatewayClientError {
    #[error("plaintext payload must never be sent to the remote gateway")]
    PlaintextPayloadRejected,

    #[error("ciphertext payload is required for PUT ciphertext object")]
    MissingPutCiphertextPayload,

    #[error("encrypted manifest payload is required for DELETE ciphertext object")]
    MissingDeleteEncryptedManifestPayload,

    #[error("request action does not allow ciphertext payload: {0:?}")]
    UnexpectedCiphertextPayload(RemoteGatewayAction),

    #[error("request action does not allow encrypted manifest payload: {0:?}")]
    UnexpectedEncryptedManifestPayload(RemoteGatewayAction),

    #[error("remote gateway response claimed plaintext access")]
    GatewayPlaintextAccessRejected,

    #[error("remote gateway HTTP client failed: {0}")]
    Http(String),

    #[error(transparent)]
    Boundary(CiphertextGatewayBoundaryError),
}

impl From<CiphertextGatewayBoundaryError> for RemoteGatewayClientError {
    fn from(error: CiphertextGatewayBoundaryError) -> Self {
        Self::Boundary(error)
    }
}

pub struct TrustlessRemoteGatewayExecutor<C> {
    client: C,
}

impl<C> TrustlessRemoteGatewayExecutor<C>
where
    C: TrustlessRemoteGatewayClient,
{
    pub fn new(client: C) -> Self {
        Self { client }
    }

    pub fn execute(
        &self,
        request: CiphertextGatewayRequest,
    ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
        validate_request(&request)?;

        let response = self.client.execute_ciphertext_request(request)?;
        let response = CiphertextGatewayBoundary::validate_response(response)?;

        if response.gateway_plaintext_access {
            return Err(RemoteGatewayClientError::GatewayPlaintextAccessRejected);
        }

        Ok(response)
    }
}

fn validate_request(request: &CiphertextGatewayRequest) -> Result<(), RemoteGatewayClientError> {
    if request.plaintext_payload_present {
        return Err(RemoteGatewayClientError::PlaintextPayloadRejected);
    }

    match request.action {
        RemoteGatewayAction::PutCiphertextObject => {
            let Some(ciphertext) = &request.ciphertext_payload else {
                return Err(RemoteGatewayClientError::MissingPutCiphertextPayload);
            };

            if ciphertext.is_empty() {
                return Err(RemoteGatewayClientError::MissingPutCiphertextPayload);
            }

            if request.encrypted_manifest_payload.is_some() {
                return Err(
                    RemoteGatewayClientError::UnexpectedEncryptedManifestPayload(request.action),
                );
            }
        }
        RemoteGatewayAction::DeleteCiphertextObject => {
            let Some(encrypted_manifest) = &request.encrypted_manifest_payload else {
                return Err(RemoteGatewayClientError::MissingDeleteEncryptedManifestPayload);
            };

            if encrypted_manifest.is_empty() {
                return Err(RemoteGatewayClientError::MissingDeleteEncryptedManifestPayload);
            }

            if request.ciphertext_payload.is_some() {
                return Err(RemoteGatewayClientError::UnexpectedCiphertextPayload(
                    request.action,
                ));
            }
        }
        RemoteGatewayAction::GetCiphertextObject
        | RemoteGatewayAction::HeadCiphertextObject
        | RemoteGatewayAction::ListCiphertextManifest => {
            if request.ciphertext_payload.is_some() {
                return Err(RemoteGatewayClientError::UnexpectedCiphertextPayload(
                    request.action,
                ));
            }

            if request.encrypted_manifest_payload.is_some() {
                return Err(
                    RemoteGatewayClientError::UnexpectedEncryptedManifestPayload(request.action),
                );
            }
        }
        RemoteGatewayAction::CreateTrustlessBucket => {
            if request.ciphertext_payload.is_some() {
                return Err(RemoteGatewayClientError::UnexpectedCiphertextPayload(
                    request.action,
                ));
            }

            if request.encrypted_manifest_payload.is_some() {
                return Err(
                    RemoteGatewayClientError::UnexpectedEncryptedManifestPayload(request.action),
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Debug)]
    struct MockRemoteGatewayClient {
        response: CiphertextGatewayResponse,
        seen_request: RefCell<Option<CiphertextGatewayRequest>>,
    }

    impl MockRemoteGatewayClient {
        fn new(response: CiphertextGatewayResponse) -> Self {
            Self {
                response,
                seen_request: RefCell::new(None),
            }
        }

        fn seen_request(&self) -> Option<CiphertextGatewayRequest> {
            self.seen_request.borrow().clone()
        }
    }

    impl TrustlessRemoteGatewayClient for MockRemoteGatewayClient {
        fn execute_ciphertext_request(
            &self,
            request: CiphertextGatewayRequest,
        ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
            *self.seen_request.borrow_mut() = Some(request);
            Ok(self.response.clone())
        }
    }

    fn request(action: RemoteGatewayAction) -> CiphertextGatewayRequest {
        CiphertextGatewayRequest {
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            action,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            plaintext_payload_present: false,
        }
    }

    fn response(action: RemoteGatewayAction) -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            metadata_only: false,
            gateway_plaintext_access: false,
        }
    }

    #[test]
    fn executor_forwards_put_ciphertext_request_without_plaintext() {
        let mut request = request(RemoteGatewayAction::PutCiphertextObject);
        request.ciphertext_payload = Some(b"ciphertext".to_vec());

        let client =
            MockRemoteGatewayClient::new(response(RemoteGatewayAction::PutCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let response = executor.execute(request).unwrap();

        assert_eq!(response.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(!response.gateway_plaintext_access);
        assert_eq!(
            executor.client.seen_request().unwrap().ciphertext_payload,
            Some(b"ciphertext".to_vec())
        );
        assert!(
            !executor
                .client
                .seen_request()
                .unwrap()
                .plaintext_payload_present
        );
    }

    #[test]
    fn executor_forwards_get_request_without_payloads() {
        let request = request(RemoteGatewayAction::GetCiphertextObject);

        let client = MockRemoteGatewayClient::new(CiphertextGatewayResponse {
            ciphertext_payload: Some(b"ciphertext".to_vec()),
            ..response(RemoteGatewayAction::GetCiphertextObject)
        });
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let response = executor.execute(request).unwrap();

        assert_eq!(response.action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(response.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(!response.gateway_plaintext_access);
    }

    #[test]
    fn executor_forwards_delete_with_encrypted_manifest_only() {
        let mut request = request(RemoteGatewayAction::DeleteCiphertextObject);
        request.encrypted_manifest_payload = Some(b"encrypted-manifest".to_vec());

        let client =
            MockRemoteGatewayClient::new(response(RemoteGatewayAction::DeleteCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let response = executor.execute(request).unwrap();

        assert_eq!(response.action, RemoteGatewayAction::DeleteCiphertextObject);
        assert!(!response.gateway_plaintext_access);
        assert_eq!(
            executor
                .client
                .seen_request()
                .unwrap()
                .encrypted_manifest_payload,
            Some(b"encrypted-manifest".to_vec())
        );
        assert!(
            executor
                .client
                .seen_request()
                .unwrap()
                .ciphertext_payload
                .is_none()
        );
    }

    #[test]
    fn executor_rejects_plaintext_payload_flag_before_client_call() {
        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.plaintext_payload_present = true;

        let client =
            MockRemoteGatewayClient::new(response(RemoteGatewayAction::GetCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let err = executor.execute(request).unwrap_err();

        assert_eq!(err, RemoteGatewayClientError::PlaintextPayloadRejected);
        assert!(executor.client.seen_request().is_none());
    }

    #[test]
    fn executor_requires_put_ciphertext_payload() {
        let request = request(RemoteGatewayAction::PutCiphertextObject);

        let client =
            MockRemoteGatewayClient::new(response(RemoteGatewayAction::PutCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let err = executor.execute(request).unwrap_err();

        assert_eq!(err, RemoteGatewayClientError::MissingPutCiphertextPayload);
        assert!(executor.client.seen_request().is_none());
    }

    #[test]
    fn executor_requires_delete_encrypted_manifest_payload() {
        let request = request(RemoteGatewayAction::DeleteCiphertextObject);

        let client =
            MockRemoteGatewayClient::new(response(RemoteGatewayAction::DeleteCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let err = executor.execute(request).unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayClientError::MissingDeleteEncryptedManifestPayload
        );
        assert!(executor.client.seen_request().is_none());
    }

    #[test]
    fn executor_rejects_unexpected_payloads_for_read_requests() {
        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.ciphertext_payload = Some(b"ciphertext".to_vec());

        let client =
            MockRemoteGatewayClient::new(response(RemoteGatewayAction::GetCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let err = executor.execute(request).unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayClientError::UnexpectedCiphertextPayload(
                RemoteGatewayAction::GetCiphertextObject
            )
        );
        assert!(executor.client.seen_request().is_none());
    }

    #[test]
    fn executor_rejects_gateway_plaintext_response() {
        let request = request(RemoteGatewayAction::GetCiphertextObject);

        let client = MockRemoteGatewayClient::new(CiphertextGatewayResponse {
            gateway_plaintext_access: true,
            ..response(RemoteGatewayAction::GetCiphertextObject)
        });
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let err = executor.execute(request).unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayClientError::Boundary(
                CiphertextGatewayBoundaryError::GatewayPlaintextAccessRejected
            )
        );
    }
}
