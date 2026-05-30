use thiserror::Error;

use crate::config::TrustlessProxyConfig;
use crate::http_mapping::{
    LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext, LocalTrustlessHttpResponse,
};
use crate::local_keystore::LocalKeystoreResolver;
use crate::manifest::{TrustlessManifest, TrustlessManifestCipher, TrustlessManifestEntry};
use crate::preflight::TrustlessOperationPreflightBuilder;
use crate::recipient_keys::RecipientKeyResolver;
use crate::remote_gateway::{TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor};
use crate::runtime::{
    LocalTrustlessRuntime, LocalTrustlessRuntimeError, LocalTrustlessRuntimeRemotePayload,
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
    pub current_manifest: TrustlessManifest,
    pub manifest_entry: TrustlessManifestEntry,
    pub envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessExecutionEngineError {
    #[error(transparent)]
    Server(LocalTrustlessServerError),

    #[error(transparent)]
    Runtime(LocalTrustlessRuntimeError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

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
                let execution = self.server.execute_prepared_put_with_configured_aws_esdk(
                    &prepared,
                    input.current_manifest,
                    input.manifest_entry,
                    input.envelope_context,
                    &self.proxy_config,
                    &self.preflight_builder,
                    self.manifest_cipher.clone(),
                    &self.remote_gateway_executor,
                )?;

                if execution.gateway_plaintext_access
                    || execution.gateway_response.gateway_plaintext_access
                    || execution.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                Ok(execution.http_response)
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
    use crate::manifest::TrustlessManifestError;
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
        response: CiphertextGatewayResponse,
        seen_request: Rc<RefCell<Option<CiphertextGatewayRequest>>>,
    }

    impl TrustlessRemoteGatewayClient for EngineMockRemoteGatewayClient {
        fn execute_ciphertext_request(
            &self,
            request: CiphertextGatewayRequest,
        ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
            *self.seen_request.borrow_mut() = Some(request);
            Ok(self.response.clone())
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
            current_manifest: engine_manifest(),
            manifest_entry: engine_manifest_entry(),
            envelope_context: envelope_context(public_key_pem),
        }
    }

    fn test_engine(
        response: CiphertextGatewayResponse,
        seen_request: Rc<RefCell<Option<CiphertextGatewayRequest>>>,
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
                response,
                seen_request,
            }),
        )
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
        let seen_request = Rc::new(RefCell::new(None));
        let engine = test_engine(
            CiphertextGatewayResponse {
                action: RemoteGatewayAction::PutCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: true,
                gateway_plaintext_access: false,
            },
            seen_request.clone(),
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

        let remote_request = seen_request.borrow().clone().unwrap();
        assert_eq!(
            remote_request.action,
            RemoteGatewayAction::PutCiphertextObject
        );
        assert!(!remote_request.plaintext_payload_present);
        assert!(remote_request.encrypted_manifest_payload.is_none());

        let ciphertext = remote_request.ciphertext_payload.unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);
        assert!(
            !String::from_utf8_lossy(&ciphertext)
                .contains("engine PUT plaintext must not leave local boundary")
        );
    }

    #[test]
    fn engine_executes_get_as_local_plaintext_response() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let plaintext = b"engine GET plaintext returns only locally".to_vec();
        let ciphertext = encrypt_get_fixture(&private_key_pem, &public_key_pem, &plaintext);

        let seen_request = Rc::new(RefCell::new(None));
        let engine = test_engine(
            CiphertextGatewayResponse {
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: Some(ciphertext),
                encrypted_manifest_payload: None,
                metadata_only: false,
                gateway_plaintext_access: false,
            },
            seen_request.clone(),
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

        let remote_request = seen_request.borrow().clone().unwrap();
        assert_eq!(
            remote_request.action,
            RemoteGatewayAction::GetCiphertextObject
        );
        assert!(remote_request.ciphertext_payload.is_none());
        assert!(remote_request.encrypted_manifest_payload.is_none());
        assert!(!remote_request.plaintext_payload_present);
    }

    #[test]
    fn engine_rejects_or_fails_closed_if_remote_claims_gateway_plaintext_access() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_request = Rc::new(RefCell::new(None));
        let engine = test_engine(
            CiphertextGatewayResponse {
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: Some(b"ciphertext".to_vec()),
                encrypted_manifest_payload: None,
                metadata_only: false,
                gateway_plaintext_access: true,
            },
            seen_request,
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
        let seen_request = Rc::new(RefCell::new(None));
        let engine = test_engine(
            CiphertextGatewayResponse {
                action: RemoteGatewayAction::PutCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: true,
                gateway_plaintext_access: false,
            },
            seen_request.clone(),
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

        let remote_request = seen_request.borrow().clone().unwrap();
        assert!(!remote_request.plaintext_payload_present);

        let ciphertext = remote_request.ciphertext_payload.unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(
            !String::from_utf8_lossy(&ciphertext).contains("do not send this plaintext remotely")
        );
    }
}
