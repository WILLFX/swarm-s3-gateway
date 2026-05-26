use thiserror::Error;

use crate::request_adapter::LocalTrustlessRequestInput;
use crate::response_adapter::LocalTrustlessResponseEnvelope;
use crate::s3_surface::LocalS3Operation;
use crate::types::SubstrateAccountId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTrustlessHttpMethod {
    Put,
    Get,
    Head,
    Delete,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessHttpRequest {
    pub method: LocalTrustlessHttpMethod,
    pub path: String,
    pub query: Option<String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessHttpRequestContext {
    pub bucket_id: String,
    pub object_key_id: Option<String>,
    pub policy_version: u32,
    pub local_account: SubstrateAccountId,
    pub local_key_type: String,
    pub recipients: Vec<SubstrateAccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessHttpResponse {
    pub status_code: u16,
    pub body: Option<Vec<u8>>,
    pub headers: Vec<(String, String)>,
    pub metadata_only: bool,
    pub plaintext_returned_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessHttpMappingError {
    #[error("unsupported HTTP method for local trustless proxy: {0:?}")]
    UnsupportedMethod(LocalTrustlessHttpMethod),

    #[error("HTTP path must start with /")]
    InvalidPath,

    #[error("bucket name is required in HTTP path")]
    MissingBucket,

    #[error("object key is required in HTTP path")]
    MissingObjectKey,

    #[error("object key id is required for object operation")]
    MissingObjectKeyId,

    #[error("PUT object requires a local plaintext body")]
    MissingPutPlaintextBody,

    #[error("plaintext body is only allowed for local PUT object mapping")]
    UnexpectedPlaintextBody,

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,
}

pub struct LocalTrustlessHttpMapper;

impl LocalTrustlessHttpMapper {
    pub fn request_to_local_input(
        request: LocalTrustlessHttpRequest,
        context: LocalTrustlessHttpRequestContext,
    ) -> Result<LocalTrustlessRequestInput, LocalTrustlessHttpMappingError> {
        let operation = classify_operation(&request)?;
        let target = parse_target(&request.path, request.query.as_deref(), operation)?;

        let plaintext_body = match operation {
            LocalS3Operation::PutObject => {
                let Some(body) = request.body else {
                    return Err(LocalTrustlessHttpMappingError::MissingPutPlaintextBody);
                };

                if body.is_empty() {
                    return Err(LocalTrustlessHttpMappingError::MissingPutPlaintextBody);
                }

                Some(body)
            }
            _ => {
                if request.body.is_some() {
                    return Err(LocalTrustlessHttpMappingError::UnexpectedPlaintextBody);
                }

                None
            }
        };

        let LocalTrustlessHttpRequestContext {
            bucket_id,
            object_key_id,
            policy_version,
            local_account,
            local_key_type,
            recipients,
        } = context;

        let object_key_id = object_key_id_for_operation(object_key_id, operation)?;

        Ok(LocalTrustlessRequestInput {
            operation,
            bucket: target.bucket,
            key: target.key,
            prefix: target.prefix,
            plaintext_body,
            bucket_id,
            object_key_id,
            policy_version,
            local_account,
            local_key_type,
            recipients,
        })
    }

    pub fn response_from_envelope(
        envelope: LocalTrustlessResponseEnvelope,
    ) -> Result<LocalTrustlessHttpResponse, LocalTrustlessHttpMappingError> {
        if envelope.gateway_plaintext_access {
            return Err(LocalTrustlessHttpMappingError::GatewayPlaintextAccessRejected);
        }

        let mut headers = vec![
            (
                "x-s3w-trustless-state".to_owned(),
                format!("{:?}", envelope.state),
            ),
            (
                "x-s3w-remote-gateway-required".to_owned(),
                envelope.remote_gateway_required.to_string(),
            ),
            (
                "x-s3w-gateway-plaintext-access".to_owned(),
                "false".to_owned(),
            ),
        ];

        if let Some(next_action) = envelope.next_action {
            headers.push(("x-s3w-next-action".to_owned(), format!("{:?}", next_action)));
        }

        Ok(LocalTrustlessHttpResponse {
            status_code: envelope.status_code,
            body: envelope.body,
            headers,
            metadata_only: envelope.metadata_only,
            plaintext_returned_locally: envelope.plaintext_returned_locally,
            gateway_plaintext_access: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHttpTarget {
    bucket: String,
    key: Option<String>,
    prefix: Option<String>,
}

fn classify_operation(
    request: &LocalTrustlessHttpRequest,
) -> Result<LocalS3Operation, LocalTrustlessHttpMappingError> {
    match request.method {
        LocalTrustlessHttpMethod::Put => {
            if query_contains(
                request.query.as_deref(),
                "x-s3w-bucket-type",
                "trustless-private",
            ) || query_contains(request.query.as_deref(), "create-trustless-bucket", "1")
            {
                Ok(LocalS3Operation::CreateTrustlessBucket)
            } else {
                Ok(LocalS3Operation::PutObject)
            }
        }
        LocalTrustlessHttpMethod::Get => {
            if query_contains(request.query.as_deref(), "list-type", "2") {
                Ok(LocalS3Operation::ListObjectsV2)
            } else {
                Ok(LocalS3Operation::GetObject)
            }
        }
        LocalTrustlessHttpMethod::Head => Ok(LocalS3Operation::HeadObject),
        LocalTrustlessHttpMethod::Delete => Ok(LocalS3Operation::DeleteObject),
        LocalTrustlessHttpMethod::Post => Err(LocalTrustlessHttpMappingError::UnsupportedMethod(
            request.method,
        )),
    }
}

fn parse_target(
    path: &str,
    query: Option<&str>,
    operation: LocalS3Operation,
) -> Result<ParsedHttpTarget, LocalTrustlessHttpMappingError> {
    let path = path.trim();

    if !path.starts_with('/') {
        return Err(LocalTrustlessHttpMappingError::InvalidPath);
    }

    let path = path.trim_start_matches('/').trim_end_matches('/');

    if path.trim().is_empty() {
        return Err(LocalTrustlessHttpMappingError::MissingBucket);
    }

    let mut parts = path.split('/');
    let bucket = parts
        .next()
        .map(str::trim)
        .filter(|bucket| !bucket.is_empty())
        .ok_or(LocalTrustlessHttpMappingError::MissingBucket)?
        .to_owned();

    let key = {
        let remaining: Vec<&str> = parts.collect();
        let joined = remaining.join("/").trim().to_owned();

        if joined.is_empty() {
            None
        } else {
            Some(joined)
        }
    };

    match operation {
        LocalS3Operation::PutObject
        | LocalS3Operation::GetObject
        | LocalS3Operation::HeadObject
        | LocalS3Operation::DeleteObject => {
            if key.is_none() {
                return Err(LocalTrustlessHttpMappingError::MissingObjectKey);
            }

            Ok(ParsedHttpTarget {
                bucket,
                key,
                prefix: None,
            })
        }
        LocalS3Operation::ListObjectsV2 => Ok(ParsedHttpTarget {
            bucket,
            key: None,
            prefix: query_value(query, "prefix"),
        }),
        LocalS3Operation::CreateTrustlessBucket => Ok(ParsedHttpTarget {
            bucket,
            key: None,
            prefix: None,
        }),
    }
}

fn object_key_id_for_operation(
    object_key_id: Option<String>,
    operation: LocalS3Operation,
) -> Result<Option<String>, LocalTrustlessHttpMappingError> {
    match operation {
        LocalS3Operation::PutObject
        | LocalS3Operation::GetObject
        | LocalS3Operation::HeadObject
        | LocalS3Operation::DeleteObject => {
            let Some(object_key_id) = object_key_id else {
                return Err(LocalTrustlessHttpMappingError::MissingObjectKeyId);
            };

            let object_key_id = object_key_id.trim().to_owned();

            if object_key_id.is_empty() {
                return Err(LocalTrustlessHttpMappingError::MissingObjectKeyId);
            }

            Ok(Some(object_key_id))
        }
        LocalS3Operation::ListObjectsV2 | LocalS3Operation::CreateTrustlessBucket => Ok(None),
    }
}

fn query_contains(query: Option<&str>, key: &str, expected: &str) -> bool {
    query_value(query, key)
        .map(|value| value == expected)
        .unwrap_or(false)
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(left, right)| {
            if left == key {
                Some(right.trim().to_owned())
            } else {
                None
            }
        })
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response_adapter::{LocalTrustlessResponseEnvelope, LocalTrustlessResponseState};
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

    fn envelope(
        operation: LocalS3Operation,
        state: LocalTrustlessResponseState,
        status_code: u16,
        body: Option<Vec<u8>>,
    ) -> LocalTrustlessResponseEnvelope {
        LocalTrustlessResponseEnvelope {
            operation,
            state,
            status_code,
            body,
            metadata_only: state == LocalTrustlessResponseState::ReadyMetadataOnly,
            plaintext_returned_locally: state == LocalTrustlessResponseState::ReadyLocalPlaintext,
            remote_gateway_required: true,
            next_action: Some(TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest),
            gateway_plaintext_access: false,
        }
    }

    #[test]
    fn http_mapper_maps_put_object_to_local_trustless_input() {
        let input = LocalTrustlessHttpMapper::request_to_local_input(
            request(
                LocalTrustlessHttpMethod::Put,
                "/bucket/secret.txt",
                None,
                Some(b"secret".to_vec()),
            ),
            context(),
        )
        .unwrap();

        assert_eq!(input.operation, LocalS3Operation::PutObject);
        assert_eq!(input.bucket, "bucket");
        assert_eq!(input.key, Some("secret.txt".to_owned()));
        assert_eq!(input.plaintext_body, Some(b"secret".to_vec()));
        assert!(input.object_key_id.is_some());
    }

    #[test]
    fn http_mapper_maps_get_head_and_delete_object_inputs() {
        for (method, operation) in [
            (LocalTrustlessHttpMethod::Get, LocalS3Operation::GetObject),
            (LocalTrustlessHttpMethod::Head, LocalS3Operation::HeadObject),
            (
                LocalTrustlessHttpMethod::Delete,
                LocalS3Operation::DeleteObject,
            ),
        ] {
            let input = LocalTrustlessHttpMapper::request_to_local_input(
                request(method, "/bucket/secret.txt", None, None),
                context(),
            )
            .unwrap();

            assert_eq!(input.operation, operation);
            assert_eq!(input.bucket, "bucket");
            assert_eq!(input.key, Some("secret.txt".to_owned()));
            assert!(input.plaintext_body.is_none());
            assert!(input.object_key_id.is_some());
        }
    }

    #[test]
    fn http_mapper_maps_list_objects_v2_without_object_key_id() {
        let input = LocalTrustlessHttpMapper::request_to_local_input(
            request(
                LocalTrustlessHttpMethod::Get,
                "/bucket",
                Some("list-type=2&prefix=docs/"),
                None,
            ),
            context(),
        )
        .unwrap();

        assert_eq!(input.operation, LocalS3Operation::ListObjectsV2);
        assert_eq!(input.bucket, "bucket");
        assert!(input.key.is_none());
        assert_eq!(input.prefix, Some("docs/".to_owned()));
        assert!(input.object_key_id.is_none());
    }

    #[test]
    fn http_mapper_maps_trustless_bucket_create_without_remote_object_key() {
        let input = LocalTrustlessHttpMapper::request_to_local_input(
            request(
                LocalTrustlessHttpMethod::Put,
                "/bucket",
                Some("x-s3w-bucket-type=trustless-private"),
                None,
            ),
            context(),
        )
        .unwrap();

        assert_eq!(input.operation, LocalS3Operation::CreateTrustlessBucket);
        assert_eq!(input.bucket, "bucket");
        assert!(input.key.is_none());
        assert!(input.object_key_id.is_none());
    }

    #[test]
    fn http_mapper_rejects_plaintext_body_outside_put_object() {
        let err = LocalTrustlessHttpMapper::request_to_local_input(
            request(
                LocalTrustlessHttpMethod::Get,
                "/bucket/secret.txt",
                None,
                Some(b"bad".to_vec()),
            ),
            context(),
        )
        .unwrap_err();

        assert_eq!(err, LocalTrustlessHttpMappingError::UnexpectedPlaintextBody);
    }

    #[test]
    fn http_mapper_rejects_missing_object_key_for_object_operation() {
        let err = LocalTrustlessHttpMapper::request_to_local_input(
            request(LocalTrustlessHttpMethod::Get, "/bucket", None, None),
            context(),
        )
        .unwrap_err();

        assert_eq!(err, LocalTrustlessHttpMappingError::MissingObjectKey);
    }

    #[test]
    fn http_mapper_rejects_unsupported_post_method() {
        let err = LocalTrustlessHttpMapper::request_to_local_input(
            request(
                LocalTrustlessHttpMethod::Post,
                "/bucket/secret.txt",
                None,
                None,
            ),
            context(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessHttpMappingError::UnsupportedMethod(LocalTrustlessHttpMethod::Post)
        );
    }

    #[test]
    fn http_mapper_maps_response_envelope_to_http_response() {
        let response = LocalTrustlessHttpMapper::response_from_envelope(envelope(
            LocalS3Operation::PutObject,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest,
            202,
            None,
        ))
        .unwrap();

        assert_eq!(response.status_code, 202);
        assert!(response.body.is_none());
        assert!(response.headers.contains(&(
            "x-s3w-gateway-plaintext-access".to_owned(),
            "false".to_owned()
        )));
        assert!(!response.gateway_plaintext_access);
    }

    #[test]
    fn http_mapper_maps_local_plaintext_get_envelope_to_http_body() {
        let mut get_envelope = envelope(
            LocalS3Operation::GetObject,
            LocalTrustlessResponseState::ReadyLocalPlaintext,
            200,
            Some(b"secret".to_vec()),
        );
        get_envelope.next_action = None;

        let response = LocalTrustlessHttpMapper::response_from_envelope(get_envelope).unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, Some(b"secret".to_vec()));
        assert!(response.plaintext_returned_locally);
        assert!(!response.gateway_plaintext_access);
    }

    #[test]
    fn http_mapper_rejects_gateway_plaintext_response_envelope() {
        let mut response_envelope = envelope(
            LocalS3Operation::GetObject,
            LocalTrustlessResponseState::PendingLocalDecrypt,
            202,
            None,
        );
        response_envelope.gateway_plaintext_access = true;

        let err = LocalTrustlessHttpMapper::response_from_envelope(response_envelope).unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessHttpMappingError::GatewayPlaintextAccessRejected
        );
    }
}
