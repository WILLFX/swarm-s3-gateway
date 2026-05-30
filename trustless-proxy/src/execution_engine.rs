use thiserror::Error;

use crate::config::TrustlessProxyConfig;
use crate::gateway_boundary::{CiphertextGatewayBoundary, CiphertextGatewayBoundaryError};
use crate::http_mapping::{
    LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext, LocalTrustlessHttpResponse,
};
use crate::local_keystore::LocalKeystoreResolver;
use crate::manifest::{
    EncryptedTrustlessManifest, TrustlessManifestBoundary, TrustlessManifestCipher,
    TrustlessManifestEntry, TrustlessManifestError,
};
use crate::planner::{PlannerError, RemoteGatewayAction, TrustlessRoutePlanner};
use crate::preflight::TrustlessOperationPreflightBuilder;
use crate::recipient_keys::RecipientKeyResolver;
use crate::remote_gateway::{
    RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
};
use crate::runtime::{
    LocalTrustlessRuntime, LocalTrustlessRuntimeError, LocalTrustlessRuntimePreparedResponse,
    LocalTrustlessRuntimeRemotePayload,
};
use crate::s3_surface::LocalS3Operation;
use crate::server::{LocalTrustlessServer, LocalTrustlessServerError};
use crate::types::RecipientEnvelopeContext;

pub struct LocalTrustlessExecutionEngine<C, RK, LK, G> {
    server: LocalTrustlessServer,
    proxy_config: TrustlessProxyConfig,
    preflight_builder: TrustlessOperationPreflightBuilder<RK, LK>,
    manifest_cipher: C,
    remote_gateway_executor: TrustlessRemoteGatewayExecutor<G>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessExecutionInput {
    pub http_request: LocalTrustlessHttpRequest,
    pub http_context: LocalTrustlessHttpRequestContext,
    pub manifest_entry: TrustlessManifestEntry,
    pub envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessExecutionEngineError {
    #[error(transparent)]
    Server(LocalTrustlessServerError),

    #[error(transparent)]
    Runtime(LocalTrustlessRuntimeError),

    #[error(transparent)]
    RemoteGateway(RemoteGatewayClientError),

    #[error(transparent)]
    GatewayBoundary(CiphertextGatewayBoundaryError),

    #[error(transparent)]
    Planner(PlannerError),

    #[error(transparent)]
    Manifest(TrustlessManifestError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("remote gateway returned unexpected action: expected {expected:?}, got {actual:?}")]
    UnexpectedRemoteResponseAction {
        expected: RemoteGatewayAction,
        actual: RemoteGatewayAction,
    },

    #[error("execution engine does not support operation yet: {0:?}")]
    UnsupportedOperation(LocalS3Operation),
}

impl From<LocalTrustlessServerError> for LocalTrustlessExecutionEngineError {
    fn from(error: LocalTrustlessServerError) -> Self {
        Self::Server(error)
    }
}

impl From<LocalTrustlessRuntimeError> for LocalTrustlessExecutionEngineError {
    fn from(error: LocalTrustlessRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RemoteGatewayClientError> for LocalTrustlessExecutionEngineError {
    fn from(error: RemoteGatewayClientError) -> Self {
        Self::RemoteGateway(error)
    }
}

impl From<CiphertextGatewayBoundaryError> for LocalTrustlessExecutionEngineError {
    fn from(error: CiphertextGatewayBoundaryError) -> Self {
        Self::GatewayBoundary(error)
    }
}

impl From<PlannerError> for LocalTrustlessExecutionEngineError {
    fn from(error: PlannerError) -> Self {
        Self::Planner(error)
    }
}

impl From<TrustlessManifestError> for LocalTrustlessExecutionEngineError {
    fn from(error: TrustlessManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl<C, RK, LK, G> LocalTrustlessExecutionEngine<C, RK, LK, G>
where
    C: TrustlessManifestCipher + Clone,
    RK: RecipientKeyResolver,
    LK: LocalKeystoreResolver,
    G: TrustlessRemoteGatewayClient,
{
    pub fn new(
        server: LocalTrustlessServer,
        proxy_config: TrustlessProxyConfig,
        preflight_builder: TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
        remote_gateway_executor: TrustlessRemoteGatewayExecutor<G>,
    ) -> Self {
        Self {
            server,
            proxy_config,
            preflight_builder,
            manifest_cipher,
            remote_gateway_executor,
        }
    }

    pub fn execute_http_request(
        &self,
        input: LocalTrustlessExecutionInput,
    ) -> Result<LocalTrustlessHttpResponse, LocalTrustlessExecutionEngineError> {
        let prepared = self
            .server
            .prepare_http_request(input.http_request, input.http_context)?;

        if prepared.gateway_plaintext_access || prepared.http_response.gateway_plaintext_access {
            return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
        }

        match prepared.operation {
            LocalS3Operation::PutObject => {
                let runtime_prepared =
                    &prepared.handler_prepared_response.runtime_prepared_response;

                let current_manifest = self.fetch_and_decrypt_current_manifest(
                    runtime_prepared,
                    &input.envelope_context,
                )?;

                let plan =
                    LocalTrustlessRuntime::build_prepared_put_operation_plan_with_configured_aws_esdk(
                        runtime_prepared,
                        current_manifest,
                        input.manifest_entry,
                        input.envelope_context.clone(),
                        &self.proxy_config,
                        &self.preflight_builder,
                        self.manifest_cipher.clone(),
                    )?;

                if plan.gateway_plaintext_access
                    || plan.encrypted_manifest.gateway_plaintext_access
                    || plan.object_request.plaintext_payload_present
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                let object_request =
                    LocalTrustlessRuntime::build_prepared_put_operation_remote_request(
                        runtime_prepared,
                        plan.clone(),
                    )?;

                let object_response = LocalTrustlessRuntime::execute_prepared_remote_request(
                    runtime_prepared,
                    object_request,
                    &self.remote_gateway_executor,
                )?;

                self.require_response_action(
                    &object_response,
                    RemoteGatewayAction::PutCiphertextObject,
                )?;

                if object_response.gateway_plaintext_access
                    || prepared.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                let manifest_request = CiphertextGatewayBoundary::put_encrypted_manifest_request(
                    runtime_prepared_bucket(runtime_prepared),
                    plan.encrypted_manifest.ciphertext,
                )?;

                let manifest_response = self.remote_gateway_executor.execute(manifest_request)?;

                self.require_response_action(
                    &manifest_response,
                    RemoteGatewayAction::PutEncryptedManifest,
                )?;

                if manifest_response.gateway_plaintext_access {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                Ok(prepared.http_response)
            }
            LocalS3Operation::GetObject => {
                let runtime_prepared =
                    &prepared.handler_prepared_response.runtime_prepared_response;

                let request = LocalTrustlessRuntime::build_prepared_remote_request(
                    runtime_prepared,
                    LocalTrustlessRuntimeRemotePayload::None,
                )?;

                let gateway_response = LocalTrustlessRuntime::execute_prepared_remote_request(
                    runtime_prepared,
                    request,
                    &self.remote_gateway_executor,
                )?;

                let completion = self.server.complete_prepared_get_with_configured_aws_esdk(
                    prepared,
                    gateway_response,
                    input.envelope_context,
                    &self.proxy_config,
                    &self.preflight_builder,
                    self.manifest_cipher.clone(),
                )?;

                if completion.gateway_plaintext_access
                    || completion.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                Ok(completion.http_response)
            }
            operation => Err(LocalTrustlessExecutionEngineError::UnsupportedOperation(
                operation,
            )),
        }
    }

    fn fetch_and_decrypt_current_manifest(
        &self,
        runtime_prepared: &LocalTrustlessRuntimePreparedResponse,
        envelope_context: &RecipientEnvelopeContext,
    ) -> Result<crate::manifest::TrustlessManifest, LocalTrustlessExecutionEngineError> {
        let bucket = runtime_prepared_bucket(runtime_prepared);
        let route_plan = TrustlessRoutePlanner::plan_list_objects_v2(bucket)?;
        let list_request = CiphertextGatewayBoundary::list_encrypted_manifest_request(&route_plan)?;

        let list_response = self.remote_gateway_executor.execute(list_request)?;

        self.require_response_action(&list_response, RemoteGatewayAction::ListCiphertextManifest)?;

        if list_response.gateway_plaintext_access {
            return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
        }

        let Some(ciphertext) = list_response.encrypted_manifest_payload else {
            return Err(LocalTrustlessExecutionEngineError::Manifest(
                TrustlessManifestError::MissingEncryptedManifest,
            ));
        };

        let read = TrustlessManifestBoundary::new(self.manifest_cipher.clone())
            .decrypt_manifest_locally(EncryptedTrustlessManifest {
                ciphertext,
                envelope_context: envelope_context.clone(),
                gateway_plaintext_access: false,
            })?;

        if read.gateway_plaintext_access {
            return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
        }

        Ok(read.manifest)
    }

    fn require_response_action(
        &self,
        response: &crate::gateway_boundary::CiphertextGatewayResponse,
        expected: RemoteGatewayAction,
    ) -> Result<(), LocalTrustlessExecutionEngineError> {
        if response.action != expected {
            return Err(
                LocalTrustlessExecutionEngineError::UnexpectedRemoteResponseAction {
                    expected,
                    actual: response.action,
                },
            );
        }

        Ok(())
    }
}

fn runtime_prepared_bucket(prepared: &LocalTrustlessRuntimePreparedResponse) -> String {
    prepared
        .handler_response
        .request_preparation
        .prepared_operation
        .pipeline_plan
        .request_context
        .preflight_request
        .bucket
        .clone()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::*;
    use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
    use crate::http_mapping::{
        LocalTrustlessHttpMethod, LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext,
    };
    use crate::keyring::TrustlessRecipientKeyring;
    use crate::local_keystore::{
        LocalKeystoreError, LocalKeystoreRecord, LocalPrivateKeySelection,
    };
    use crate::manifest::{TrustlessManifest, TrustlessManifestError};
    use crate::planner::RemoteGatewayAction;
    use crate::recipient_keys::{RecipientKeyError, RecipientKeyRecord};
    use crate::remote_gateway::{RemoteGatewayClientError, TrustlessRemoteGatewayClient};
    use crate::server::LocalTrustlessServerConfig;
    use crate::types::{RecipientEncryptionKey, SubstrateAccountId};

    #[derive(Debug, Default)]
    struct EngineMockRecipientKeyResolver {
        records: BTreeMap<SubstrateAccountId, RecipientKeyRecord>,
    }

    impl EngineMockRecipientKeyResolver {
        fn with_record(mut self, record: RecipientKeyRecord) -> Self {
            self.records.insert(record.account.clone(), record);
            self
        }
    }

    impl RecipientKeyResolver for EngineMockRecipientKeyResolver {
        fn resolve_recipient_key(
            &self,
            account: &SubstrateAccountId,
        ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
            Ok(self.records.get(account).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct EngineMockLocalKeystoreResolver {
        records: BTreeMap<(SubstrateAccountId, String), Vec<LocalKeystoreRecord>>,
    }

    impl EngineMockLocalKeystoreResolver {
        fn with_record(mut self, record: LocalKeystoreRecord) -> Self {
            self.records
                .entry((record.account.clone(), record.key_type.clone()))
                .or_default()
                .push(record);
            self
        }
    }

    impl LocalKeystoreResolver for EngineMockLocalKeystoreResolver {
        fn list_local_private_keys(
            &self,
            account: &SubstrateAccountId,
            key_type: &str,
        ) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreError> {
            Ok(self
                .records
                .get(&(account.clone(), key_type.to_owned()))
                .cloned()
                .unwrap_or_default())
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct EngineMockManifestCipher;

    impl TrustlessManifestCipher for EngineMockManifestCipher {
        fn decrypt_manifest(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<TrustlessManifest, TrustlessManifestError> {
            if ciphertext != b"engine-encrypted-manifest" {
                return Err(TrustlessManifestError::Cipher(
                    "unexpected engine encrypted manifest".to_owned(),
                ));
            }

            Ok(engine_manifest())
        }

        fn encrypt_manifest(
            &self,
            manifest: &TrustlessManifest,
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, TrustlessManifestError> {
            Ok(format!(
                "engine-encrypted-manifest:{}:{}",
                manifest.bucket_id, manifest.manifest_version
            )
            .into_bytes())
        }
    }

    #[derive(Debug, Clone)]
    struct EngineMockRemoteGatewayClient {
        responses: Rc<RefCell<Vec<CiphertextGatewayResponse>>>,
        seen_requests: Rc<RefCell<Vec<CiphertextGatewayRequest>>>,
    }

    impl TrustlessRemoteGatewayClient for EngineMockRemoteGatewayClient {
        fn execute_ciphertext_request(
            &self,
            request: CiphertextGatewayRequest,
        ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
            self.seen_requests.borrow_mut().push(request);

            if self.responses.borrow().is_empty() {
                return Err(RemoteGatewayClientError::Http(
                    "engine mock remote gateway response queue is empty".to_owned(),
                ));
            }

            Ok(self.responses.borrow_mut().remove(0))
        }
    }

    type TestEngine = LocalTrustlessExecutionEngine<
        EngineMockManifestCipher,
        EngineMockRecipientKeyResolver,
        EngineMockLocalKeystoreResolver,
        EngineMockRemoteGatewayClient,
    >;

    fn run_openssl(args: &[&str], cwd: &std::path::Path) {
        let output = std::process::Command::new("openssl")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("failed to invoke openssl for engine AWS ESDK Raw RSA test keys");

        assert!(
            output.status.success(),
            "openssl {:?} failed\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn generate_test_rsa_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().expect("failed to create temp dir for RSA test keys");
        let private_key = dir.path().join("private.pem");
        let public_key = dir.path().join("public.pem");

        run_openssl(
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                private_key.file_name().unwrap().to_str().unwrap(),
            ],
            dir.path(),
        );

        run_openssl(
            &[
                "rsa",
                "-in",
                private_key.file_name().unwrap().to_str().unwrap(),
                "-pubout",
                "-out",
                public_key.file_name().unwrap().to_str().unwrap(),
            ],
            dir.path(),
        );

        (
            std::fs::read(private_key).unwrap(),
            std::fs::read(public_key).unwrap(),
        )
    }

    fn server() -> LocalTrustlessServer {
        LocalTrustlessServer::new(LocalTrustlessServerConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            max_request_body_bytes: 1024 * 1024,
            remote_gateway_url: Some("http://127.0.0.1:3000".to_owned()),
            network_bind_enabled: false,
        })
        .unwrap()
    }

    fn proxy_config() -> TrustlessProxyConfig {
        TrustlessProxyConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            remote_gateway_url: "http://127.0.0.1:3000".to_owned(),
            chain_rpc_url: "ws://127.0.0.1:9944".to_owned(),
            local_account: "alice".to_owned(),
            keystore_path: std::path::PathBuf::from("./keystore.json"),
            local_private_key_unlock_key: [44u8; 32],
            aws_esdk_key_namespace: "engine-test-namespace".to_owned(),
        }
    }

    fn local_private_key_selection(blob: Vec<u8>) -> LocalPrivateKeySelection {
        LocalPrivateKeySelection {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            encrypted_private_key_blob: blob,
            storage_label: "local-keystore/alice/1".to_owned(),
        }
    }

    fn recipient_record(account: &str, public_key_pem: &[u8]) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn recipient_encryption_key(account: &str, public_key_pem: &[u8]) -> RecipientEncryptionKey {
        RecipientEncryptionKey {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn local_record(config: &TrustlessProxyConfig, private_key_pem: &[u8]) -> LocalKeystoreRecord {
        let selection = local_private_key_selection(b"placeholder".to_vec());
        let encrypted_private_key_blob = config
            .local_private_key_unlocker()
            .seal_private_key_for_storage(&selection, private_key_pem)
            .unwrap();

        LocalKeystoreRecord {
            account: selection.account,
            key_type: selection.key_type,
            key_version: selection.key_version,
            encrypted_private_key_blob,
            enabled: true,
            storage_label: selection.storage_label,
        }
    }

    fn preflight_builder(
        config: &TrustlessProxyConfig,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> TrustlessOperationPreflightBuilder<
        EngineMockRecipientKeyResolver,
        EngineMockLocalKeystoreResolver,
    > {
        TrustlessOperationPreflightBuilder::new(
            EngineMockRecipientKeyResolver::default()
                .with_record(recipient_record("alice", public_key_pem))
                .with_record(recipient_record("bob", public_key_pem)),
            EngineMockLocalKeystoreResolver::default()
                .with_record(local_record(config, private_key_pem)),
        )
    }

    fn envelope_context(public_key_pem: &[u8]) -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: vec![
                recipient_encryption_key("alice", public_key_pem),
                recipient_encryption_key("bob", public_key_pem),
            ],
        }
    }

    fn http_request(
        method: LocalTrustlessHttpMethod,
        body: Option<Vec<u8>>,
    ) -> LocalTrustlessHttpRequest {
        LocalTrustlessHttpRequest {
            method,
            path: "/bucket/secret.txt".to_owned(),
            query: None,
            body,
        }
    }

    fn http_context() -> LocalTrustlessHttpRequestContext {
        LocalTrustlessHttpRequestContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: Some(hex::encode([2u8; 32])),
            policy_version: 1,
            local_account: "alice".to_owned(),
            local_key_type: "aws-esdk-rust-recipient-key".to_owned(),
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    fn engine_manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([1u8; 32]),
            manifest_version: 1,
            entries: Vec::new(),
        }
    }

    fn engine_manifest_entry() -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key: "secret.txt".to_owned(),
            object_key_id: hex::encode([2u8; 32]),
            ciphertext_ref: "bee://engine-ciphertext-ref".to_owned(),
            ciphertext_size: 64,
            content_type: Some("text/plain".to_owned()),
            etag: Some("engine-etag".to_owned()),
        }
    }

    fn execution_input(
        method: LocalTrustlessHttpMethod,
        body: Option<Vec<u8>>,
        public_key_pem: &[u8],
    ) -> LocalTrustlessExecutionInput {
        LocalTrustlessExecutionInput {
            http_request: http_request(method, body),
            http_context: http_context(),
            manifest_entry: engine_manifest_entry(),
            envelope_context: envelope_context(public_key_pem),
        }
    }

    fn test_engine(
        responses: Vec<CiphertextGatewayResponse>,
        seen_requests: Rc<RefCell<Vec<CiphertextGatewayRequest>>>,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> TestEngine {
        let config = proxy_config();

        LocalTrustlessExecutionEngine::new(
            server(),
            config.clone(),
            preflight_builder(&config, private_key_pem, public_key_pem),
            EngineMockManifestCipher,
            TrustlessRemoteGatewayExecutor::new(EngineMockRemoteGatewayClient {
                responses: Rc::new(RefCell::new(responses)),
                seen_requests,
            }),
        )
    }

    fn list_manifest_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::ListCiphertextManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: Some(b"engine-encrypted-manifest".to_vec()),
            metadata_only: false,
            gateway_plaintext_access: false,
        }
    }

    fn put_object_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::PutCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            metadata_only: true,
            gateway_plaintext_access: false,
        }
    }

    fn put_manifest_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::PutEncryptedManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            metadata_only: true,
            gateway_plaintext_access: false,
        }
    }

    fn encrypt_get_fixture(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let config = proxy_config();
        let encrypted_private_key_blob = config
            .local_private_key_unlocker()
            .seal_private_key_for_storage(
                &local_private_key_selection(b"placeholder".to_vec()),
                private_key_pem,
            )
            .unwrap();

        let keyring = LocalTrustlessRuntime::build_aws_esdk_raw_rsa_keyring_from_local_selection(
            &config,
            local_private_key_selection(encrypted_private_key_blob),
        )
        .unwrap();

        keyring
            .encrypt_with_recipient_envelopes(plaintext, &envelope_context(public_key_pem))
            .unwrap()
    }

    #[test]
    fn engine_executes_put_as_ciphertext_only_remote_request() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                put_object_response(),
                put_manifest_response(),
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let plaintext = b"engine PUT plaintext must not leave local boundary".to_vec();

        let response = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(plaintext.clone()),
                &public_key_pem,
            ))
            .unwrap();

        assert!(!response.gateway_plaintext_access);

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 3);

        assert_eq!(
            requests[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert!(requests[0].ciphertext_payload.is_none());
        assert!(requests[0].encrypted_manifest_payload.is_none());
        assert!(!requests[0].plaintext_payload_present);

        assert_eq!(requests[1].action, RemoteGatewayAction::PutCiphertextObject);
        assert!(!requests[1].plaintext_payload_present);
        assert!(requests[1].encrypted_manifest_payload.is_none());

        let ciphertext = requests[1].ciphertext_payload.clone().unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);
        assert!(
            !String::from_utf8_lossy(&ciphertext)
                .contains("engine PUT plaintext must not leave local boundary")
        );

        assert_eq!(
            requests[2].action,
            RemoteGatewayAction::PutEncryptedManifest
        );
        assert!(requests[2].ciphertext_payload.is_none());
        assert!(!requests[2].plaintext_payload_present);

        let encrypted_manifest = requests[2].encrypted_manifest_payload.clone().unwrap();
        assert_eq!(
            encrypted_manifest,
            format!("engine-encrypted-manifest:{}:2", hex::encode([1u8; 32])).into_bytes()
        );
    }

    #[test]
    fn engine_fetches_decrypts_updates_and_persists_manifest_for_put() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                put_object_response(),
                put_manifest_response(),
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(b"manifest orchestration plaintext".to_vec()),
                &public_key_pem,
            ))
            .unwrap();

        let requests = seen_requests.borrow();
        let actions = requests
            .iter()
            .map(|request| request.action)
            .collect::<Vec<_>>();

        assert_eq!(
            actions,
            vec![
                RemoteGatewayAction::ListCiphertextManifest,
                RemoteGatewayAction::PutCiphertextObject,
                RemoteGatewayAction::PutEncryptedManifest,
            ]
        );

        assert_eq!(requests[0].bucket, "bucket");
        assert_eq!(requests[0].key, None);
        assert_eq!(requests[2].bucket, "bucket");
        assert_eq!(requests[2].key, None);
        assert!(requests[2].encrypted_manifest_payload.is_some());
    }

    #[test]
    fn engine_executes_get_as_local_plaintext_response() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let plaintext = b"engine GET plaintext returns only locally".to_vec();
        let ciphertext = encrypt_get_fixture(&private_key_pem, &public_key_pem, &plaintext);

        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![CiphertextGatewayResponse {
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: Some(ciphertext),
                encrypted_manifest_payload: None,
                metadata_only: false,
                gateway_plaintext_access: false,
            }],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let response = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Get,
                None,
                &public_key_pem,
            ))
            .unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, Some(plaintext));
        assert!(response.plaintext_returned_locally);
        assert!(!response.gateway_plaintext_access);

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].action, RemoteGatewayAction::GetCiphertextObject);
        assert!(requests[0].ciphertext_payload.is_none());
        assert!(requests[0].encrypted_manifest_payload.is_none());
        assert!(!requests[0].plaintext_payload_present);
    }

    #[test]
    fn engine_rejects_or_fails_closed_if_remote_claims_gateway_plaintext_access() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![CiphertextGatewayResponse {
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: Some(b"ciphertext".to_vec()),
                encrypted_manifest_payload: None,
                metadata_only: false,
                gateway_plaintext_access: true,
            }],
            seen_requests,
            &private_key_pem,
            &public_key_pem,
        );

        let err = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Get,
                None,
                &public_key_pem,
            ))
            .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessExecutionEngineError::Runtime(_)
        ));
    }

    #[test]
    fn engine_does_not_send_plaintext_payload_to_remote_gateway() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                put_object_response(),
                put_manifest_response(),
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let plaintext = b"do not send this plaintext remotely".to_vec();

        engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(plaintext.clone()),
                &public_key_pem,
            ))
            .unwrap();

        let requests = seen_requests.borrow();

        for request in requests.iter() {
            assert!(!request.plaintext_payload_present);
        }

        assert!(requests[0].ciphertext_payload.is_none());
        assert!(requests[0].encrypted_manifest_payload.is_none());

        let ciphertext = requests[1].ciphertext_payload.clone().unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(
            !String::from_utf8_lossy(&ciphertext).contains("do not send this plaintext remotely")
        );

        assert!(requests[2].ciphertext_payload.is_none());
        assert!(requests[2].encrypted_manifest_payload.is_some());
    }

    #[test]
    fn engine_fails_closed_when_manifest_fetch_claims_gateway_plaintext_access() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![CiphertextGatewayResponse {
                action: RemoteGatewayAction::ListCiphertextManifest,
                ciphertext_payload: None,
                encrypted_manifest_payload: Some(b"engine-encrypted-manifest".to_vec()),
                metadata_only: false,
                gateway_plaintext_access: true,
            }],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let err = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(b"secret".to_vec()),
                &public_key_pem,
            ))
            .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessExecutionEngineError::RemoteGateway(_)
        ));
        assert_eq!(seen_requests.borrow().len(), 1);
        assert_eq!(
            seen_requests.borrow()[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
    }

    #[test]
    fn engine_fails_closed_when_manifest_fetch_missing_encrypted_payload() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![CiphertextGatewayResponse {
                action: RemoteGatewayAction::ListCiphertextManifest,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: false,
                gateway_plaintext_access: false,
            }],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let err = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(b"secret".to_vec()),
                &public_key_pem,
            ))
            .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessExecutionEngineError::Manifest(
                TrustlessManifestError::MissingEncryptedManifest
            )
        );
        assert_eq!(seen_requests.borrow().len(), 1);
    }
}
