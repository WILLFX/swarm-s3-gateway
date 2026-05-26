use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalS3Operation {
    PutObject,
    GetObject,
    HeadObject,
    ListObjectsV2,
    DeleteObject,
    CreateTrustlessBucket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalS3Request {
    pub operation: LocalS3Operation,
    pub bucket: String,
    pub key: Option<String>,
    pub prefix: Option<String>,
    pub plaintext_body: Option<Vec<u8>>,
    pub plaintext_body_allowed_locally: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalS3Response {
    pub operation: LocalS3Operation,
    pub plaintext_body: Option<Vec<u8>>,
    pub metadata_only: bool,
    pub plaintext_returned_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalS3RouteIntent {
    pub operation: LocalS3Operation,
    pub bucket: String,
    pub key: Option<String>,
    pub prefix: Option<String>,
    pub plaintext_body: Option<Vec<u8>>,
    pub plaintext_body_allowed_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalS3SurfaceError {
    #[error("bucket name is required")]
    MissingBucket,

    #[error("object key is required")]
    MissingObjectKey,

    #[error("PUT object requires a local plaintext body")]
    MissingPutPlaintextBody,

    #[error("plaintext body is only allowed at the local S3 proxy boundary for PUT")]
    UnexpectedPlaintextBody,

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,
}

pub struct LocalS3Surface;

impl LocalS3Surface {
    pub fn classify_request(
        request: LocalS3Request,
    ) -> Result<LocalS3RouteIntent, LocalS3SurfaceError> {
        let bucket = require_non_empty(request.bucket, LocalS3SurfaceError::MissingBucket)?;

        match request.operation {
            LocalS3Operation::PutObject => {
                let key = require_key(request.key)?;
                let plaintext_body = require_put_body(request.plaintext_body)?;

                Ok(LocalS3RouteIntent {
                    operation: request.operation,
                    bucket,
                    key: Some(key),
                    prefix: None,
                    plaintext_body: Some(plaintext_body),
                    plaintext_body_allowed_locally: true,
                    gateway_plaintext_access: false,
                })
            }
            LocalS3Operation::GetObject
            | LocalS3Operation::HeadObject
            | LocalS3Operation::DeleteObject => {
                let key = require_key(request.key)?;

                reject_plaintext_body(request.plaintext_body)?;

                Ok(LocalS3RouteIntent {
                    operation: request.operation,
                    bucket,
                    key: Some(key),
                    prefix: None,
                    plaintext_body: None,
                    plaintext_body_allowed_locally: false,
                    gateway_plaintext_access: false,
                })
            }
            LocalS3Operation::ListObjectsV2 | LocalS3Operation::CreateTrustlessBucket => {
                reject_plaintext_body(request.plaintext_body)?;

                Ok(LocalS3RouteIntent {
                    operation: request.operation,
                    bucket,
                    key: None,
                    prefix: normalize_optional(request.prefix),
                    plaintext_body: None,
                    plaintext_body_allowed_locally: false,
                    gateway_plaintext_access: false,
                })
            }
        }
    }

    pub fn local_plaintext_response(
        operation: LocalS3Operation,
        plaintext_body: Vec<u8>,
    ) -> Result<LocalS3Response, LocalS3SurfaceError> {
        if plaintext_body.is_empty() {
            return Err(LocalS3SurfaceError::UnexpectedPlaintextBody);
        }

        match operation {
            LocalS3Operation::GetObject => Ok(LocalS3Response {
                operation,
                plaintext_body: Some(plaintext_body),
                metadata_only: false,
                plaintext_returned_locally: true,
                gateway_plaintext_access: false,
            }),
            _ => Err(LocalS3SurfaceError::UnexpectedPlaintextBody),
        }
    }

    pub fn metadata_only_response(
        operation: LocalS3Operation,
    ) -> Result<LocalS3Response, LocalS3SurfaceError> {
        match operation {
            LocalS3Operation::HeadObject
            | LocalS3Operation::ListObjectsV2
            | LocalS3Operation::PutObject
            | LocalS3Operation::DeleteObject
            | LocalS3Operation::CreateTrustlessBucket => Ok(LocalS3Response {
                operation,
                plaintext_body: None,
                metadata_only: true,
                plaintext_returned_locally: false,
                gateway_plaintext_access: false,
            }),
            LocalS3Operation::GetObject => Err(LocalS3SurfaceError::UnexpectedPlaintextBody),
        }
    }

    pub fn validate_no_gateway_plaintext(
        response: &LocalS3Response,
    ) -> Result<(), LocalS3SurfaceError> {
        if response.gateway_plaintext_access {
            return Err(LocalS3SurfaceError::GatewayPlaintextAccessRejected);
        }

        Ok(())
    }
}

fn require_non_empty(
    value: String,
    error: LocalS3SurfaceError,
) -> Result<String, LocalS3SurfaceError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

fn require_key(key: Option<String>) -> Result<String, LocalS3SurfaceError> {
    let Some(key) = key else {
        return Err(LocalS3SurfaceError::MissingObjectKey);
    };

    require_non_empty(key, LocalS3SurfaceError::MissingObjectKey)
}

fn require_put_body(body: Option<Vec<u8>>) -> Result<Vec<u8>, LocalS3SurfaceError> {
    let Some(body) = body else {
        return Err(LocalS3SurfaceError::MissingPutPlaintextBody);
    };

    if body.is_empty() {
        return Err(LocalS3SurfaceError::MissingPutPlaintextBody);
    }

    Ok(body)
}

fn reject_plaintext_body(body: Option<Vec<u8>>) -> Result<(), LocalS3SurfaceError> {
    if body.is_some() {
        return Err(LocalS3SurfaceError::UnexpectedPlaintextBody);
    }

    Ok(())
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: LocalS3Operation) -> LocalS3Request {
        LocalS3Request {
            operation,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            prefix: None,
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
        }
    }

    #[test]
    fn put_request_accepts_plaintext_only_at_local_boundary() {
        let intent = LocalS3Surface::classify_request(LocalS3Request {
            plaintext_body: Some(b"secret".to_vec()),
            plaintext_body_allowed_locally: true,
            ..request(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(intent.operation, LocalS3Operation::PutObject);
        assert_eq!(intent.plaintext_body, Some(b"secret".to_vec()));
        assert!(intent.plaintext_body_allowed_locally);
        assert!(!intent.gateway_plaintext_access);
    }

    #[test]
    fn get_head_delete_requests_reject_plaintext_bodies() {
        for operation in [
            LocalS3Operation::GetObject,
            LocalS3Operation::HeadObject,
            LocalS3Operation::DeleteObject,
        ] {
            let err = LocalS3Surface::classify_request(LocalS3Request {
                plaintext_body: Some(b"not-allowed".to_vec()),
                ..request(operation)
            })
            .unwrap_err();

            assert_eq!(err, LocalS3SurfaceError::UnexpectedPlaintextBody);
        }
    }

    #[test]
    fn list_request_uses_prefix_without_plaintext_body() {
        let intent = LocalS3Surface::classify_request(LocalS3Request {
            operation: LocalS3Operation::ListObjectsV2,
            bucket: "bucket".to_owned(),
            key: None,
            prefix: Some(" docs/ ".to_owned()),
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
        })
        .unwrap();

        assert_eq!(intent.operation, LocalS3Operation::ListObjectsV2);
        assert_eq!(intent.prefix, Some("docs/".to_owned()));
        assert!(intent.key.is_none());
        assert!(!intent.gateway_plaintext_access);
    }

    #[test]
    fn create_trustless_bucket_has_no_object_key_or_plaintext_body() {
        let intent = LocalS3Surface::classify_request(LocalS3Request {
            operation: LocalS3Operation::CreateTrustlessBucket,
            bucket: "bucket".to_owned(),
            key: None,
            prefix: None,
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
        })
        .unwrap();

        assert_eq!(intent.operation, LocalS3Operation::CreateTrustlessBucket);
        assert!(intent.key.is_none());
        assert!(intent.plaintext_body.is_none());
        assert!(!intent.gateway_plaintext_access);
    }

    #[test]
    fn surface_rejects_missing_bucket_key_or_put_body() {
        assert_eq!(
            LocalS3Surface::classify_request(LocalS3Request {
                bucket: " ".to_owned(),
                ..request(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            LocalS3SurfaceError::MissingBucket
        );

        assert_eq!(
            LocalS3Surface::classify_request(LocalS3Request {
                key: None,
                ..request(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            LocalS3SurfaceError::MissingObjectKey
        );

        assert_eq!(
            LocalS3Surface::classify_request(request(LocalS3Operation::PutObject)).unwrap_err(),
            LocalS3SurfaceError::MissingPutPlaintextBody
        );
    }

    #[test]
    fn get_response_returns_plaintext_locally_only() {
        let response = LocalS3Surface::local_plaintext_response(
            LocalS3Operation::GetObject,
            b"secret".to_vec(),
        )
        .unwrap();

        assert_eq!(response.plaintext_body, Some(b"secret".to_vec()));
        assert!(response.plaintext_returned_locally);
        assert!(!response.gateway_plaintext_access);
    }

    #[test]
    fn metadata_response_never_contains_plaintext_body() {
        for operation in [
            LocalS3Operation::HeadObject,
            LocalS3Operation::ListObjectsV2,
            LocalS3Operation::PutObject,
            LocalS3Operation::DeleteObject,
            LocalS3Operation::CreateTrustlessBucket,
        ] {
            let response = LocalS3Surface::metadata_only_response(operation).unwrap();

            assert!(response.metadata_only);
            assert!(response.plaintext_body.is_none());
            assert!(!response.plaintext_returned_locally);
            assert!(!response.gateway_plaintext_access);
        }
    }

    #[test]
    fn surface_rejects_gateway_plaintext_response_flag() {
        let response = LocalS3Response {
            operation: LocalS3Operation::GetObject,
            plaintext_body: Some(b"secret".to_vec()),
            metadata_only: false,
            plaintext_returned_locally: true,
            gateway_plaintext_access: true,
        };

        assert_eq!(
            LocalS3Surface::validate_no_gateway_plaintext(&response).unwrap_err(),
            LocalS3SurfaceError::GatewayPlaintextAccessRejected
        );
    }
}
