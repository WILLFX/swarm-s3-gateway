use thiserror::Error;

use crate::preflight::TrustlessPreflightRequest;
use crate::s3_surface::{LocalS3Operation, LocalS3RouteIntent};
use crate::types::SubstrateAccountId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessRequestContextInput {
    pub route_intent: LocalS3RouteIntent,
    pub bucket_id: String,
    pub object_key_id: Option<String>,
    pub policy_version: u32,
    pub local_account: SubstrateAccountId,
    pub local_key_type: String,
    pub recipients: Vec<SubstrateAccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessRequestContext {
    pub preflight_request: TrustlessPreflightRequest,
    pub local_operation: LocalS3Operation,
    pub plaintext_body: Option<Vec<u8>>,
    pub plaintext_body_allowed_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessRequestContextError {
    #[error("bucket id is required")]
    MissingBucketId,

    #[error("object key id is required for object operation")]
    MissingObjectKeyId,

    #[error("local account is required")]
    MissingLocalAccount,

    #[error("local key type is required")]
    MissingLocalKeyType,

    #[error("at least one recipient is required")]
    MissingRecipients,

    #[error("plaintext body is required for local PUT")]
    MissingPutPlaintextBody,

    #[error("plaintext body is only allowed at local PUT boundary")]
    UnexpectedPlaintextBody,

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,
}

pub struct TrustlessRequestContextBuilder;

impl TrustlessRequestContextBuilder {
    pub fn build(
        input: TrustlessRequestContextInput,
    ) -> Result<TrustlessRequestContext, TrustlessRequestContextError> {
        if input.route_intent.gateway_plaintext_access {
            return Err(TrustlessRequestContextError::GatewayPlaintextAccessRejected);
        }

        let bucket_id = require_non_empty(
            input.bucket_id,
            TrustlessRequestContextError::MissingBucketId,
        )?;
        let local_account = require_non_empty(
            input.local_account,
            TrustlessRequestContextError::MissingLocalAccount,
        )?;
        let local_key_type = require_non_empty(
            input.local_key_type,
            TrustlessRequestContextError::MissingLocalKeyType,
        )?;
        let recipients = normalize_recipients(input.recipients)?;

        let object_key_id = match input.route_intent.operation {
            LocalS3Operation::PutObject
            | LocalS3Operation::GetObject
            | LocalS3Operation::HeadObject
            | LocalS3Operation::DeleteObject => Some(require_non_empty(
                input.object_key_id.unwrap_or_default(),
                TrustlessRequestContextError::MissingObjectKeyId,
            )?),
            LocalS3Operation::ListObjectsV2 | LocalS3Operation::CreateTrustlessBucket => None,
        };

        validate_plaintext_body(&input.route_intent)?;

        Ok(TrustlessRequestContext {
            preflight_request: TrustlessPreflightRequest {
                bucket: input.route_intent.bucket,
                key: input.route_intent.key,
                bucket_id,
                object_key_id,
                policy_version: input.policy_version,
                local_account,
                local_key_type,
                recipients,
            },
            local_operation: input.route_intent.operation,
            plaintext_body: input.route_intent.plaintext_body,
            plaintext_body_allowed_locally: input.route_intent.plaintext_body_allowed_locally,
            gateway_plaintext_access: false,
        })
    }
}

fn validate_plaintext_body(
    route_intent: &LocalS3RouteIntent,
) -> Result<(), TrustlessRequestContextError> {
    match route_intent.operation {
        LocalS3Operation::PutObject => {
            if route_intent
                .plaintext_body
                .as_ref()
                .map(|body| body.is_empty())
                .unwrap_or(true)
            {
                return Err(TrustlessRequestContextError::MissingPutPlaintextBody);
            }

            if !route_intent.plaintext_body_allowed_locally {
                return Err(TrustlessRequestContextError::UnexpectedPlaintextBody);
            }
        }
        LocalS3Operation::GetObject
        | LocalS3Operation::HeadObject
        | LocalS3Operation::ListObjectsV2
        | LocalS3Operation::DeleteObject
        | LocalS3Operation::CreateTrustlessBucket => {
            if route_intent.plaintext_body.is_some() || route_intent.plaintext_body_allowed_locally
            {
                return Err(TrustlessRequestContextError::UnexpectedPlaintextBody);
            }
        }
    }

    Ok(())
}

fn require_non_empty(
    value: String,
    error: TrustlessRequestContextError,
) -> Result<String, TrustlessRequestContextError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

fn normalize_recipients(
    recipients: Vec<SubstrateAccountId>,
) -> Result<Vec<SubstrateAccountId>, TrustlessRequestContextError> {
    let mut recipients = recipients
        .into_iter()
        .map(|recipient| recipient.trim().to_owned())
        .filter(|recipient| !recipient.is_empty())
        .collect::<Vec<_>>();

    recipients.sort();
    recipients.dedup();

    if recipients.is_empty() {
        return Err(TrustlessRequestContextError::MissingRecipients);
    }

    Ok(recipients)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_surface::{LocalS3RouteIntent, LocalS3Surface};

    fn route_intent(operation: LocalS3Operation) -> LocalS3RouteIntent {
        LocalS3RouteIntent {
            operation,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            prefix: None,
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
            gateway_plaintext_access: false,
        }
    }

    fn input(operation: LocalS3Operation) -> TrustlessRequestContextInput {
        TrustlessRequestContextInput {
            route_intent: route_intent(operation),
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: Some(hex::encode([2u8; 32])),
            policy_version: 1,
            local_account: "alice".to_owned(),
            local_key_type: "aws-esdk-rust-recipient-key".to_owned(),
            recipients: vec!["bob".to_owned(), "alice".to_owned(), "bob".to_owned()],
        }
    }

    #[test]
    fn put_context_preserves_plaintext_only_at_local_boundary() {
        let context = TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
            route_intent: LocalS3RouteIntent {
                plaintext_body: Some(b"secret".to_vec()),
                plaintext_body_allowed_locally: true,
                ..route_intent(LocalS3Operation::PutObject)
            },
            ..input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(context.local_operation, LocalS3Operation::PutObject);
        assert_eq!(context.plaintext_body, Some(b"secret".to_vec()));
        assert!(context.plaintext_body_allowed_locally);
        assert!(!context.gateway_plaintext_access);
        assert_eq!(
            context.preflight_request.object_key_id,
            Some(hex::encode([2u8; 32]))
        );
        assert_eq!(context.preflight_request.recipients, vec!["alice", "bob"]);
    }

    #[test]
    fn get_head_delete_contexts_require_object_key_id_without_plaintext() {
        for operation in [
            LocalS3Operation::GetObject,
            LocalS3Operation::HeadObject,
            LocalS3Operation::DeleteObject,
        ] {
            let context = TrustlessRequestContextBuilder::build(input(operation)).unwrap();

            assert_eq!(context.local_operation, operation);
            assert!(context.plaintext_body.is_none());
            assert!(!context.plaintext_body_allowed_locally);
            assert_eq!(
                context.preflight_request.object_key_id,
                Some(hex::encode([2u8; 32]))
            );
            assert!(!context.gateway_plaintext_access);
        }
    }

    #[test]
    fn list_and_create_contexts_do_not_require_object_key_id() {
        for operation in [
            LocalS3Operation::ListObjectsV2,
            LocalS3Operation::CreateTrustlessBucket,
        ] {
            let mut input = input(operation);
            input.route_intent.key = None;
            input.object_key_id = None;

            let context = TrustlessRequestContextBuilder::build(input).unwrap();

            assert_eq!(context.local_operation, operation);
            assert!(context.preflight_request.object_key_id.is_none());
            assert!(context.preflight_request.key.is_none());
            assert!(!context.gateway_plaintext_access);
        }
    }

    #[test]
    fn context_builder_rejects_missing_required_identity_fields() {
        assert_eq!(
            TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
                bucket_id: " ".to_owned(),
                ..input(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            TrustlessRequestContextError::MissingBucketId
        );

        assert_eq!(
            TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
                local_account: " ".to_owned(),
                ..input(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            TrustlessRequestContextError::MissingLocalAccount
        );

        assert_eq!(
            TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
                local_key_type: " ".to_owned(),
                ..input(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            TrustlessRequestContextError::MissingLocalKeyType
        );
    }

    #[test]
    fn context_builder_rejects_missing_object_key_id_for_object_operations() {
        assert_eq!(
            TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
                object_key_id: None,
                ..input(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            TrustlessRequestContextError::MissingObjectKeyId
        );
    }

    #[test]
    fn context_builder_rejects_missing_recipients() {
        assert_eq!(
            TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
                recipients: vec![" ".to_owned()],
                ..input(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            TrustlessRequestContextError::MissingRecipients
        );
    }

    #[test]
    fn context_builder_rejects_plaintext_outside_put_boundary() {
        assert_eq!(
            TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
                route_intent: LocalS3RouteIntent {
                    plaintext_body: Some(b"bad".to_vec()),
                    ..route_intent(LocalS3Operation::GetObject)
                },
                ..input(LocalS3Operation::GetObject)
            })
            .unwrap_err(),
            TrustlessRequestContextError::UnexpectedPlaintextBody
        );
    }

    #[test]
    fn context_builder_accepts_real_local_s3_put_intent() {
        let route_intent = LocalS3Surface::classify_request(crate::s3_surface::LocalS3Request {
            operation: LocalS3Operation::PutObject,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            prefix: None,
            plaintext_body: Some(b"secret".to_vec()),
            plaintext_body_allowed_locally: true,
        })
        .unwrap();

        let context = TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
            route_intent,
            ..input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(context.plaintext_body, Some(b"secret".to_vec()));
        assert!(context.plaintext_body_allowed_locally);
        assert!(!context.gateway_plaintext_access);
    }
}
