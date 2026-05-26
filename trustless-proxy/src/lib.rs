pub mod aws_esdk;
pub mod config;
pub mod encryption;
pub mod gateway_boundary;
pub mod keyring;
pub mod local_keystore;
pub mod manifest;
pub mod operations;
pub mod planner;
pub mod preflight;
pub mod recipient_keys;
pub mod types;

pub use aws_esdk::{
    AwsEsdkKeyringConfig, AwsEsdkRecipientEnvelopeDescriptor, AwsEsdkRecipientEnvelopePlan,
    AwsEsdkTrustlessRecipientKeyring,
};
pub use config::{ConfigError, TrustlessProxyConfig};
pub use encryption::{
    TrustlessDecryptRequest, TrustlessDecryptResult, TrustlessEncryptRequest,
    TrustlessEncryptResult, TrustlessEncryptionBoundary, TrustlessEncryptionError,
};
pub use gateway_boundary::{
    CiphertextGatewayBoundary, CiphertextGatewayBoundaryError, CiphertextGatewayRequest,
    CiphertextGatewayResponse,
};
pub use keyring::{
    KeyringError, TrustlessRecipientKeyring, UnimplementedTrustlessRecipientKeyring,
};
pub use local_keystore::{
    LocalKeyRequest, LocalKeystoreError, LocalKeystoreRecord, LocalKeystoreResolver,
    LocalPrivateKeySelection, LocalPrivateKeySelector,
};
pub use manifest::{
    EncryptedTrustlessManifest, TrustlessManifest, TrustlessManifestBoundary,
    TrustlessManifestCipher, TrustlessManifestEntry, TrustlessManifestError,
    TrustlessManifestListResult, TrustlessManifestMutation, TrustlessManifestRead,
    TrustlessManifestWrite,
};
pub use operations::{
    TrustlessDeleteOperationInput, TrustlessDeleteOperationPlan, TrustlessOperationAssembler,
    TrustlessOperationError, TrustlessPutOperationInput, TrustlessPutOperationPlan,
};
pub use planner::{
    LocalTrustlessStep, PlannerError, RemoteGatewayAction, TrustlessProxyOperation,
    TrustlessRoutePlan, TrustlessRoutePlanner,
};
pub use preflight::{
    PreflightError, TrustlessLocalDecryptPreflight, TrustlessOperationPreflightBuilder,
    TrustlessPreflightRequest, TrustlessPutPreflight,
};
pub use recipient_keys::{
    RecipientEnvelopeBuilder, RecipientKeyError, RecipientKeyRecord, RecipientKeyRequest,
    RecipientKeyResolver,
};
pub use types::{
    Hex32, RecipientEncryptionKey, RecipientEnvelopeContext, SubstrateAccountId,
    TrustlessBucketType, TrustlessGetPlan, TrustlessPutPlan,
};
