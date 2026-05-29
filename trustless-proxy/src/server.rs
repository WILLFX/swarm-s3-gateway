use thiserror::Error;

use crate::config::TrustlessProxyConfig;
use crate::gateway_boundary::CiphertextGatewayResponse;
use crate::http_handler::{
    LocalTrustlessHttpHandler, LocalTrustlessHttpHandlerCompletion, LocalTrustlessHttpHandlerError,
    LocalTrustlessHttpHandlerPreparedResponse,
};
use crate::http_mapping::{
    LocalTrustlessHttpMapper, LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext,
    LocalTrustlessHttpResponse,
};
use crate::local_keystore::LocalKeystoreResolver;
use crate::manifest::{TrustlessManifest, TrustlessManifestCipher, TrustlessManifestEntry};
use crate::preflight::TrustlessOperationPreflightBuilder;
use crate::recipient_keys::RecipientKeyResolver;
use crate::remote_gateway::{TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor};
use crate::runtime::{
    LocalTrustlessRuntime, LocalTrustlessRuntimeError, LocalTrustlessRuntimePreparedResponse,
};
use crate::s3_surface::LocalS3Operation;
use crate::types::RecipientEnvelopeContext;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessServerRemoteExecution {
    pub operation: LocalS3Operation,
    pub gateway_response: CiphertextGatewayResponse,
    pub http_response: LocalTrustlessHttpResponse,
    pub config: LocalTrustlessServerConfig,
    pub remote_gateway_executed: bool,
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

    #[error(transparent)]
    Runtime(LocalTrustlessRuntimeError),
}

impl From<LocalTrustlessHttpHandlerError> for LocalTrustlessServerError {
    fn from(error: LocalTrustlessHttpHandlerError) -> Self {
        Self::HttpHandler(error)
    }
}

impl From<LocalTrustlessRuntimeError> for LocalTrustlessServerError {
    fn from(error: LocalTrustlessRuntimeError) -> Self {
        Self::Runtime(error)
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

    pub fn execute_prepared_put_with_configured_aws_esdk<C, RK, LK, G>(
        &self,
        prepared: &LocalTrustlessServerPreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_entry: TrustlessManifestEntry,
        manifest_envelope_context: RecipientEnvelopeContext,
        proxy_config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
        executor: &TrustlessRemoteGatewayExecutor<G>,
    ) -> Result<LocalTrustlessServerRemoteExecution, LocalTrustlessServerError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
        G: TrustlessRemoteGatewayClient,
    {
        validate_prepared_server_execution(prepared)?;

        let gateway_response =
            LocalTrustlessRuntime::execute_prepared_put_operation_with_configured_aws_esdk(
                &prepared.handler_prepared_response.runtime_prepared_response,
                current_manifest,
                manifest_entry,
                manifest_envelope_context,
                proxy_config,
                preflight_builder,
                manifest_cipher,
                executor,
            )?;

        if gateway_response.gateway_plaintext_access {
            return Err(LocalTrustlessServerError::GatewayPlaintextAccessRejected);
        }

        Ok(LocalTrustlessServerRemoteExecution {
            operation: prepared.operation,
            gateway_response,
            http_response: prepared.http_response.clone(),
            config: self.config.clone(),
            remote_gateway_executed: true,
            network_bind_performed: false,
            gateway_plaintext_access: false,
        })
    }

    pub fn execute_prepared_delete_with_configured_aws_esdk<C, RK, LK, G>(
        &self,
        prepared: &LocalTrustlessServerPreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_envelope_context: RecipientEnvelopeContext,
        proxy_config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
        executor: &TrustlessRemoteGatewayExecutor<G>,
    ) -> Result<LocalTrustlessServerRemoteExecution, LocalTrustlessServerError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
        G: TrustlessRemoteGatewayClient,
    {
        validate_prepared_server_execution(prepared)?;

        let gateway_response =
            LocalTrustlessRuntime::execute_prepared_delete_operation_with_configured_aws_esdk(
                &prepared.handler_prepared_response.runtime_prepared_response,
                current_manifest,
                manifest_envelope_context,
                proxy_config,
                preflight_builder,
                manifest_cipher,
                executor,
            )?;

        if gateway_response.gateway_plaintext_access {
            return Err(LocalTrustlessServerError::GatewayPlaintextAccessRejected);
        }

        Ok(LocalTrustlessServerRemoteExecution {
            operation: prepared.operation,
            gateway_response,
            http_response: prepared.http_response.clone(),
            config: self.config.clone(),
            remote_gateway_executed: true,
            network_bind_performed: false,
            gateway_plaintext_access: false,
        })
    }

    pub fn complete_prepared_get_with_configured_aws_esdk<C, RK, LK>(
        &self,
        prepared: LocalTrustlessServerPreparedResponse,
        gateway_response: CiphertextGatewayResponse,
        envelope_context: RecipientEnvelopeContext,
        proxy_config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
    ) -> Result<LocalTrustlessServerCompletion, LocalTrustlessServerError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
    {
        validate_prepared_server_execution(&prepared)?;

        let runtime_completion =
            LocalTrustlessRuntime::complete_prepared_get_response_with_configured_aws_esdk(
                prepared.handler_prepared_response.runtime_prepared_response,
                gateway_response,
                envelope_context,
                proxy_config,
                preflight_builder,
                manifest_cipher,
            )?;

        if runtime_completion.gateway_plaintext_access
            || runtime_completion
                .response_envelope
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessServerError::GatewayPlaintextAccessRejected);
        }

        let operation = runtime_completion.operation;
        let http_response = LocalTrustlessHttpMapper::response_from_envelope(
            runtime_completion.response_envelope.clone(),
        )
        .map_err(LocalTrustlessHttpHandlerError::from)?;

        if http_response.gateway_plaintext_access {
            return Err(LocalTrustlessServerError::GatewayPlaintextAccessRejected);
        }

        let handler_completion = LocalTrustlessHttpHandlerCompletion {
            operation,
            runtime_completion,
            http_response: http_response.clone(),
            gateway_plaintext_access: false,
        };

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

fn validate_prepared_server_execution(
    prepared: &LocalTrustlessServerPreparedResponse,
) -> Result<(), LocalTrustlessServerError> {
    if prepared.gateway_plaintext_access
        || prepared.handler_prepared_response.gateway_plaintext_access
        || prepared
            .handler_prepared_response
            .http_response
            .gateway_plaintext_access
        || prepared.http_response.gateway_plaintext_access
    {
        return Err(LocalTrustlessServerError::GatewayPlaintextAccessRejected);
    }

    Ok(())
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
    use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
    use crate::http_mapping::{LocalTrustlessHttpMethod, LocalTrustlessHttpRequest};
    use crate::keyring::TrustlessRecipientKeyring;
    use crate::local_keystore::{
        LocalKeystoreError, LocalKeystoreRecord, LocalKeystoreResolver, LocalPrivateKeySelection,
    };
    use crate::manifest::{
        TrustlessManifest, TrustlessManifestCipher, TrustlessManifestEntry, TrustlessManifestError,
    };
    use crate::planner::RemoteGatewayAction;
    use crate::preflight::TrustlessOperationPreflightBuilder;
    use crate::recipient_keys::{RecipientKeyError, RecipientKeyRecord, RecipientKeyResolver};
    use crate::remote_gateway::{
        RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
    };
    use crate::response_adapter::LocalTrustlessResponseState;
    use crate::runtime::LocalTrustlessRuntime;
    use crate::service::TrustlessLocalServiceNextAction;
    use crate::types::{RecipientEncryptionKey, RecipientEnvelopeContext, SubstrateAccountId};

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

    #[derive(Debug, Default)]
    struct ServerRealEsdkMockRecipientKeyResolver {
        records: std::collections::BTreeMap<SubstrateAccountId, RecipientKeyRecord>,
    }

    impl ServerRealEsdkMockRecipientKeyResolver {
        fn with_record(mut self, record: RecipientKeyRecord) -> Self {
            self.records.insert(record.account.clone(), record);
            self
        }
    }

    impl RecipientKeyResolver for ServerRealEsdkMockRecipientKeyResolver {
        fn resolve_recipient_key(
            &self,
            account: &SubstrateAccountId,
        ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
            Ok(self.records.get(account).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct ServerRealEsdkMockLocalKeystoreResolver {
        records: std::collections::BTreeMap<(SubstrateAccountId, String), Vec<LocalKeystoreRecord>>,
    }

    impl ServerRealEsdkMockLocalKeystoreResolver {
        fn with_record(mut self, record: LocalKeystoreRecord) -> Self {
            self.records
                .entry((record.account.clone(), record.key_type.clone()))
                .or_default()
                .push(record);
            self
        }
    }

    impl LocalKeystoreResolver for ServerRealEsdkMockLocalKeystoreResolver {
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
    struct ServerRealEsdkMockManifestCipher;

    impl TrustlessManifestCipher for ServerRealEsdkMockManifestCipher {
        fn decrypt_manifest(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<TrustlessManifest, TrustlessManifestError> {
            if ciphertext != b"server-encrypted-manifest" {
                return Err(TrustlessManifestError::Cipher(
                    "unexpected server encrypted manifest".to_owned(),
                ));
            }

            Ok(server_real_esdk_manifest())
        }

        fn encrypt_manifest(
            &self,
            manifest: &TrustlessManifest,
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, TrustlessManifestError> {
            Ok(format!(
                "server-encrypted-manifest:{}:{}",
                manifest.bucket_id, manifest.manifest_version
            )
            .into_bytes())
        }
    }

    #[derive(Debug, Clone)]
    struct ServerRealEsdkMockRemoteGatewayClient {
        response: CiphertextGatewayResponse,
        seen_request: std::rc::Rc<std::cell::RefCell<Option<CiphertextGatewayRequest>>>,
    }

    impl TrustlessRemoteGatewayClient for ServerRealEsdkMockRemoteGatewayClient {
        fn execute_ciphertext_request(
            &self,
            request: CiphertextGatewayRequest,
        ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
            *self.seen_request.borrow_mut() = Some(request);
            Ok(self.response.clone())
        }
    }

    fn server_real_esdk_run_openssl(args: &[&str], cwd: &std::path::Path) {
        let output = std::process::Command::new("openssl")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("failed to invoke openssl for server AWS ESDK Raw RSA test keys");

        assert!(
            output.status.success(),
            "openssl {:?} failed\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn server_real_esdk_generate_test_rsa_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().expect("failed to create temp dir for RSA test keys");
        let private_key = dir.path().join("private.pem");
        let public_key = dir.path().join("public.pem");

        server_real_esdk_run_openssl(
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

        server_real_esdk_run_openssl(
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

    fn server_real_esdk_proxy_config() -> TrustlessProxyConfig {
        TrustlessProxyConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            remote_gateway_url: "http://127.0.0.1:3000".to_owned(),
            chain_rpc_url: "ws://127.0.0.1:9944".to_owned(),
            local_account: "alice".to_owned(),
            keystore_path: std::path::PathBuf::from("./keystore.json"),
            local_private_key_unlock_key: [21u8; 32],
            aws_esdk_key_namespace: "server-config-namespace".to_owned(),
        }
    }

    fn server_real_esdk_local_private_key_selection(blob: Vec<u8>) -> LocalPrivateKeySelection {
        LocalPrivateKeySelection {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            encrypted_private_key_blob: blob,
            storage_label: "local-keystore/alice/1".to_owned(),
        }
    }

    fn server_real_esdk_recipient_record(
        account: &str,
        public_key_pem: &[u8],
    ) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn server_real_esdk_recipient_encryption_key(
        account: &str,
        public_key_pem: &[u8],
    ) -> RecipientEncryptionKey {
        RecipientEncryptionKey {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn server_real_esdk_local_record(
        proxy_config: &TrustlessProxyConfig,
        private_key_pem: &[u8],
    ) -> LocalKeystoreRecord {
        let selection = server_real_esdk_local_private_key_selection(b"placeholder".to_vec());
        let encrypted_private_key_blob = proxy_config
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

    fn server_real_esdk_preflight_builder(
        proxy_config: &TrustlessProxyConfig,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> TrustlessOperationPreflightBuilder<
        ServerRealEsdkMockRecipientKeyResolver,
        ServerRealEsdkMockLocalKeystoreResolver,
    > {
        TrustlessOperationPreflightBuilder::new(
            ServerRealEsdkMockRecipientKeyResolver::default()
                .with_record(server_real_esdk_recipient_record("alice", public_key_pem))
                .with_record(server_real_esdk_recipient_record("bob", public_key_pem)),
            ServerRealEsdkMockLocalKeystoreResolver::default()
                .with_record(server_real_esdk_local_record(proxy_config, private_key_pem)),
        )
    }

    fn server_real_esdk_envelope_context(public_key_pem: &[u8]) -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: vec![
                server_real_esdk_recipient_encryption_key("alice", public_key_pem),
                server_real_esdk_recipient_encryption_key("bob", public_key_pem),
            ],
        }
    }

    fn server_real_esdk_manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([1u8; 32]),
            manifest_version: 1,
            entries: Vec::new(),
        }
    }

    fn server_real_esdk_manifest_entry() -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key: "secret.txt".to_owned(),
            object_key_id: hex::encode([2u8; 32]),
            ciphertext_ref: "bee://server-ciphertext-ref".to_owned(),
            ciphertext_size: 64,
            content_type: Some("text/plain".to_owned()),
            etag: Some("server-etag".to_owned()),
        }
    }

    #[test]
    fn server_executes_prepared_put_with_configured_aws_esdk_without_network_bind() {
        let (private_key_pem, public_key_pem) = server_real_esdk_generate_test_rsa_pem_pair();
        let proxy_config = server_real_esdk_proxy_config();
        let preflight_builder =
            server_real_esdk_preflight_builder(&proxy_config, &private_key_pem, &public_key_pem);
        let server = LocalTrustlessServer::new(config()).unwrap();

        let prepared = server
            .prepare_http_request(
                request(
                    LocalTrustlessHttpMethod::Put,
                    "/bucket/secret.txt",
                    None,
                    Some(b"server real AWS ESDK plaintext".to_vec()),
                ),
                context(),
            )
            .unwrap();

        let seen_request = std::rc::Rc::new(std::cell::RefCell::new(None));
        let executor = TrustlessRemoteGatewayExecutor::new(ServerRealEsdkMockRemoteGatewayClient {
            response: CiphertextGatewayResponse {
                action: RemoteGatewayAction::PutCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: true,
                gateway_plaintext_access: false,
            },
            seen_request: seen_request.clone(),
        });

        let execution = server
            .execute_prepared_put_with_configured_aws_esdk(
                &prepared,
                server_real_esdk_manifest(),
                server_real_esdk_manifest_entry(),
                server_real_esdk_envelope_context(&public_key_pem),
                &proxy_config,
                &preflight_builder,
                ServerRealEsdkMockManifestCipher,
                &executor,
            )
            .unwrap();

        assert_eq!(execution.operation, LocalS3Operation::PutObject);
        assert!(execution.remote_gateway_executed);
        assert!(!execution.network_bind_performed);
        assert!(!execution.gateway_plaintext_access);
        assert_eq!(
            execution.gateway_response.action,
            RemoteGatewayAction::PutCiphertextObject
        );

        let request = seen_request.borrow().clone().unwrap();
        assert_eq!(request.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(!request.plaintext_payload_present);
        assert!(request.encrypted_manifest_payload.is_none());

        let ciphertext = request.ciphertext_payload.unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, b"server real AWS ESDK plaintext".to_vec());
        assert!(!String::from_utf8_lossy(&ciphertext).contains("server real AWS ESDK plaintext"));
    }

    #[test]
    fn server_completes_prepared_get_with_configured_aws_esdk_as_local_plaintext() {
        let (private_key_pem, public_key_pem) = server_real_esdk_generate_test_rsa_pem_pair();
        let proxy_config = server_real_esdk_proxy_config();
        let preflight_builder =
            server_real_esdk_preflight_builder(&proxy_config, &private_key_pem, &public_key_pem);
        let server = LocalTrustlessServer::new(config()).unwrap();

        let encrypted_private_key_blob = proxy_config
            .local_private_key_unlocker()
            .seal_private_key_for_storage(
                &server_real_esdk_local_private_key_selection(b"placeholder".to_vec()),
                &private_key_pem,
            )
            .unwrap();

        let keyring = LocalTrustlessRuntime::build_aws_esdk_raw_rsa_keyring_from_local_selection(
            &proxy_config,
            server_real_esdk_local_private_key_selection(encrypted_private_key_blob),
        )
        .unwrap();

        let envelope_context = server_real_esdk_envelope_context(&public_key_pem);
        let plaintext = b"server configured GET plaintext stays local".to_vec();

        let ciphertext = keyring
            .encrypt_with_recipient_envelopes(&plaintext, &envelope_context)
            .unwrap();

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
            .complete_prepared_get_with_configured_aws_esdk(
                prepared,
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::GetCiphertextObject,
                    ciphertext_payload: Some(ciphertext),
                    encrypted_manifest_payload: None,
                    metadata_only: false,
                    gateway_plaintext_access: false,
                },
                envelope_context,
                &proxy_config,
                &preflight_builder,
                ServerRealEsdkMockManifestCipher,
            )
            .unwrap();

        assert_eq!(completion.operation, LocalS3Operation::GetObject);
        assert_eq!(completion.http_response.status_code, 200);
        assert_eq!(completion.http_response.body, Some(plaintext));
        assert!(completion.http_response.plaintext_returned_locally);
        assert!(!completion.network_bind_performed);
        assert!(!completion.gateway_plaintext_access);
    }

    #[test]
    fn server_executes_prepared_delete_with_configured_aws_esdk_without_plaintext_remote() {
        let (private_key_pem, public_key_pem) = server_real_esdk_generate_test_rsa_pem_pair();
        let proxy_config = server_real_esdk_proxy_config();
        let preflight_builder =
            server_real_esdk_preflight_builder(&proxy_config, &private_key_pem, &public_key_pem);
        let server = LocalTrustlessServer::new(config()).unwrap();

        let prepared = server
            .prepare_http_request(
                request(
                    LocalTrustlessHttpMethod::Delete,
                    "/bucket/secret.txt",
                    None,
                    None,
                ),
                context(),
            )
            .unwrap();

        let seen_request = std::rc::Rc::new(std::cell::RefCell::new(None));
        let executor = TrustlessRemoteGatewayExecutor::new(ServerRealEsdkMockRemoteGatewayClient {
            response: CiphertextGatewayResponse {
                action: RemoteGatewayAction::DeleteCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: true,
                gateway_plaintext_access: false,
            },
            seen_request: seen_request.clone(),
        });

        let execution = server
            .execute_prepared_delete_with_configured_aws_esdk(
                &prepared,
                TrustlessManifest {
                    entries: vec![server_real_esdk_manifest_entry()],
                    ..server_real_esdk_manifest()
                },
                server_real_esdk_envelope_context(&public_key_pem),
                &proxy_config,
                &preflight_builder,
                ServerRealEsdkMockManifestCipher,
                &executor,
            )
            .unwrap();

        assert_eq!(execution.operation, LocalS3Operation::DeleteObject);
        assert!(execution.remote_gateway_executed);
        assert!(!execution.network_bind_performed);
        assert!(!execution.gateway_plaintext_access);
        assert_eq!(
            execution.gateway_response.action,
            RemoteGatewayAction::DeleteCiphertextObject
        );

        let request = seen_request.borrow().clone().unwrap();
        assert_eq!(request.action, RemoteGatewayAction::DeleteCiphertextObject);
        assert!(request.ciphertext_payload.is_none());
        assert!(!request.plaintext_payload_present);

        let encrypted_manifest = request.encrypted_manifest_payload.unwrap();
        assert!(!encrypted_manifest.is_empty());
        assert!(!String::from_utf8_lossy(&encrypted_manifest).contains("secret.txt"));
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
