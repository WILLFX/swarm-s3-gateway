use thiserror::Error;

use crate::config::TrustlessProxyConfig;
use crate::local_keystore::{LocalKeystoreError, LocalKeystoreRecord, LocalKeystoreResolver};
use crate::local_keystore_file::LocalKeystoreFile;
use crate::preflight::TrustlessOperationPreflightBuilder;
use crate::recipient_keys::{RecipientKeyError, RecipientKeyRecord, RecipientKeyResolver};
use crate::remote_gateway::TrustlessRemoteGatewayExecutor;
use crate::remote_gateway_http::RemoteGatewayHttpClient;
use crate::server::{LocalTrustlessServer, LocalTrustlessServerConfig, LocalTrustlessServerError};
use crate::types::SubstrateAccountId;

const DEFAULT_LISTEN_HOST: &str = "127.0.0.1";
const DEFAULT_LISTEN_PORT: u16 = 9090;
const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTrustlessCliCommand {
    LocalProxyConfig,
    LocalProxyStartScaffold,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessCliInput {
    pub command: LocalTrustlessCliCommand,
    pub listen_host: String,
    pub listen_port: u16,
    pub max_request_body_bytes: u64,
    pub remote_gateway_url: Option<String>,
    pub network_bind_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessCliPreparedCommand {
    pub command: LocalTrustlessCliCommand,
    pub server_config: LocalTrustlessServerConfig,
    pub server_initialized: bool,
    pub network_bind_performed: bool,
    pub gateway_plaintext_access: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessStartupDependencyPlan {
    pub command: LocalTrustlessCliCommand,
    pub proxy_config: TrustlessProxyConfig,
    pub server_config: LocalTrustlessServerConfig,
    pub server_initialized: bool,
    pub local_keystore_record_count: usize,
    pub selected_local_key_account: String,
    pub selected_local_key_type: String,
    pub selected_local_key_version: u32,
    pub selected_local_key_storage_label: String,
    pub local_keystore_resolver_prepared: bool,
    pub recipient_key_resolver_boundary_prepared: bool,
    pub preflight_builder_prepared: bool,
    pub remote_gateway_client_prepared: bool,
    pub remote_gateway_endpoint_url: String,
    pub remote_gateway_executor_prepared: bool,
    pub network_bind_performed: bool,
    pub gateway_plaintext_access: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessStartupLocalKeystoreResolver {
    records: Vec<LocalKeystoreRecord>,
}

impl LocalTrustlessStartupLocalKeystoreResolver {
    pub fn new(records: Vec<LocalKeystoreRecord>) -> Self {
        Self { records }
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl LocalKeystoreResolver for LocalTrustlessStartupLocalKeystoreResolver {
    fn list_local_private_keys(
        &self,
        account: &SubstrateAccountId,
        key_type: &str,
    ) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreError> {
        Ok(self
            .records
            .iter()
            .filter(|record| record.account == *account && record.key_type == key_type)
            .cloned()
            .collect())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LocalTrustlessStartupRecipientKeyResolverBoundary;

impl RecipientKeyResolver for LocalTrustlessStartupRecipientKeyResolverBoundary {
    fn resolve_recipient_key(
        &self,
        account: &SubstrateAccountId,
    ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
        Err(RecipientKeyError::MissingEnabledRecipientKey(
            account.trim().to_owned(),
        ))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessCliError {
    #[error("missing local trustless proxy CLI command")]
    MissingCommand,

    #[error("unknown local trustless proxy CLI command: {0}")]
    UnknownCommand(String),

    #[error("missing value for CLI flag: {0}")]
    MissingFlagValue(String),

    #[error("unknown local trustless proxy CLI flag: {0}")]
    UnknownFlag(String),

    #[error("invalid listen port")]
    InvalidListenPort,

    #[error("invalid request body limit")]
    InvalidRequestBodyLimit,

    #[error("network binding is not enabled in the local proxy scaffold")]
    NetworkBindFlagRejected,

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("startup dependency construction failed: {0}")]
    StartupDependency(String),

    #[error(transparent)]
    Server(LocalTrustlessServerError),
}

impl From<LocalTrustlessServerError> for LocalTrustlessCliError {
    fn from(error: LocalTrustlessServerError) -> Self {
        Self::Server(error)
    }
}

pub struct LocalTrustlessCli;

impl LocalTrustlessCli {
    pub fn default_input(command: LocalTrustlessCliCommand) -> LocalTrustlessCliInput {
        LocalTrustlessCliInput {
            command,
            listen_host: DEFAULT_LISTEN_HOST.to_owned(),
            listen_port: DEFAULT_LISTEN_PORT,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            remote_gateway_url: None,
            network_bind_enabled: false,
        }
    }

    pub fn from_args<I, S>(args: I) -> Result<LocalTrustlessCliInput, LocalTrustlessCliError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut args = args.into_iter().map(Into::into);

        let _program = args.next();

        let Some(command) = args.next() else {
            return Err(LocalTrustlessCliError::MissingCommand);
        };

        let mut input = match command.as_str() {
            "local-proxy-config" => Self::default_input(LocalTrustlessCliCommand::LocalProxyConfig),
            "local-proxy" | "local-proxy-start" => {
                Self::default_input(LocalTrustlessCliCommand::LocalProxyStartScaffold)
            }
            unknown => return Err(LocalTrustlessCliError::UnknownCommand(unknown.to_owned())),
        };

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen-host" => {
                    input.listen_host = next_value(&flag, args.next())?;
                }
                "--listen-port" => {
                    let value = next_value(&flag, args.next())?;
                    input.listen_port = value
                        .parse::<u16>()
                        .map_err(|_| LocalTrustlessCliError::InvalidListenPort)?;

                    if input.listen_port == 0 {
                        return Err(LocalTrustlessCliError::InvalidListenPort);
                    }
                }
                "--max-request-body-bytes" => {
                    let value = next_value(&flag, args.next())?;
                    input.max_request_body_bytes = value
                        .parse::<u64>()
                        .map_err(|_| LocalTrustlessCliError::InvalidRequestBodyLimit)?;

                    if input.max_request_body_bytes == 0 {
                        return Err(LocalTrustlessCliError::InvalidRequestBodyLimit);
                    }
                }
                "--remote-gateway-url" => {
                    let value = next_value(&flag, args.next())?;
                    input.remote_gateway_url = Some(value);
                }
                "--no-network-bind" => {
                    input.network_bind_enabled = false;
                }
                "--network-bind-enabled" => {
                    return Err(LocalTrustlessCliError::NetworkBindFlagRejected);
                }
                unknown => return Err(LocalTrustlessCliError::UnknownFlag(unknown.to_owned())),
            }
        }

        Ok(input)
    }

    pub fn prepare_from_args<I, S>(
        args: I,
    ) -> Result<LocalTrustlessCliPreparedCommand, LocalTrustlessCliError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::prepare_command(Self::from_args(args)?)
    }

    pub fn prepare_startup_dependencies_from_env(
        input: LocalTrustlessCliInput,
    ) -> Result<LocalTrustlessStartupDependencyPlan, LocalTrustlessCliError> {
        let proxy_config = TrustlessProxyConfig::from_env()
            .map_err(|error| LocalTrustlessCliError::StartupDependency(error.to_string()))?;

        Self::prepare_startup_dependencies(proxy_config, input)
    }

    pub fn prepare_startup_dependencies(
        proxy_config: TrustlessProxyConfig,
        input: LocalTrustlessCliInput,
    ) -> Result<LocalTrustlessStartupDependencyPlan, LocalTrustlessCliError> {
        if input.network_bind_enabled {
            return Err(LocalTrustlessCliError::NetworkBindFlagRejected);
        }

        let server_config = server_config_from_input_and_proxy(&input, &proxy_config);
        let server = LocalTrustlessServer::new(server_config.clone())?;

        if server.config().network_bind_enabled {
            return Err(LocalTrustlessCliError::NetworkBindFlagRejected);
        }

        let records = LocalKeystoreFile::read_records(&proxy_config.keystore_path)
            .map_err(|error| LocalTrustlessCliError::StartupDependency(error.to_string()))?;

        let selected = LocalKeystoreFile::load_private_key_selection(
            &proxy_config.keystore_path,
            &proxy_config.local_account,
            "aws-esdk-rust-recipient-key",
        )
        .map_err(|error| LocalTrustlessCliError::StartupDependency(error.to_string()))?;

        let local_keystore_resolver =
            LocalTrustlessStartupLocalKeystoreResolver::new(records.clone());

        let _preflight_builder = TrustlessOperationPreflightBuilder::new(
            LocalTrustlessStartupRecipientKeyResolverBoundary,
            local_keystore_resolver.clone(),
        );

        let remote_gateway_client =
            RemoteGatewayHttpClient::new(proxy_config.remote_gateway_url.clone())
                .map_err(|error| LocalTrustlessCliError::StartupDependency(error.to_string()))?;

        let remote_gateway_endpoint_url = remote_gateway_client.endpoint_url();
        let _remote_gateway_executor = TrustlessRemoteGatewayExecutor::new(remote_gateway_client);

        let summary = format!(
            "local proxy startup dependencies prepared for {}:{} with keystore records loaded, AWS ESDK unlocker configured, remote gateway client prepared, and network binding disabled",
            server.config().listen_host,
            server.config().listen_port
        );

        Ok(LocalTrustlessStartupDependencyPlan {
            command: input.command,
            proxy_config,
            server_config,
            server_initialized: true,
            local_keystore_record_count: local_keystore_resolver.record_count(),
            selected_local_key_account: selected.account,
            selected_local_key_type: selected.key_type,
            selected_local_key_version: selected.key_version,
            selected_local_key_storage_label: selected.storage_label,
            local_keystore_resolver_prepared: true,
            recipient_key_resolver_boundary_prepared: true,
            preflight_builder_prepared: true,
            remote_gateway_client_prepared: true,
            remote_gateway_endpoint_url,
            remote_gateway_executor_prepared: true,
            network_bind_performed: false,
            gateway_plaintext_access: false,
            summary,
        })
    }

    pub fn prepare_command(
        input: LocalTrustlessCliInput,
    ) -> Result<LocalTrustlessCliPreparedCommand, LocalTrustlessCliError> {
        if input.network_bind_enabled {
            return Err(LocalTrustlessCliError::NetworkBindFlagRejected);
        }

        let server_config = LocalTrustlessServerConfig {
            listen_host: input.listen_host,
            listen_port: input.listen_port,
            max_request_body_bytes: input.max_request_body_bytes,
            remote_gateway_url: input.remote_gateway_url,
            network_bind_enabled: input.network_bind_enabled,
        };

        let server = LocalTrustlessServer::new(server_config.clone())?;

        if server.config().network_bind_enabled {
            return Err(LocalTrustlessCliError::NetworkBindFlagRejected);
        }

        let summary = match input.command {
            LocalTrustlessCliCommand::LocalProxyConfig => format!(
                "local proxy config validated for {}:{} with network binding disabled",
                server.config().listen_host,
                server.config().listen_port
            ),
            LocalTrustlessCliCommand::LocalProxyStartScaffold => format!(
                "local proxy scaffold prepared for {}:{} with network binding disabled",
                server.config().listen_host,
                server.config().listen_port
            ),
        };

        Ok(LocalTrustlessCliPreparedCommand {
            command: input.command,
            server_config,
            server_initialized: true,
            network_bind_performed: false,
            gateway_plaintext_access: false,
            summary,
        })
    }
}

fn server_config_from_input_and_proxy(
    input: &LocalTrustlessCliInput,
    proxy_config: &TrustlessProxyConfig,
) -> LocalTrustlessServerConfig {
    LocalTrustlessServerConfig {
        listen_host: input.listen_host.clone(),
        listen_port: input.listen_port,
        max_request_body_bytes: input.max_request_body_bytes,
        remote_gateway_url: input
            .remote_gateway_url
            .clone()
            .or_else(|| Some(proxy_config.remote_gateway_url.clone())),
        network_bind_enabled: input.network_bind_enabled,
    }
}

fn next_value(flag: &str, value: Option<String>) -> Result<String, LocalTrustlessCliError> {
    let Some(value) = value else {
        return Err(LocalTrustlessCliError::MissingFlagValue(flag.to_owned()));
    };

    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(LocalTrustlessCliError::MissingFlagValue(flag.to_owned()));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup_temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "s3w-trustless-startup-{}-{name}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn startup_local_record(account: &str, version: u32, enabled: bool) -> LocalKeystoreRecord {
        LocalKeystoreRecord {
            account: account.to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: version,
            encrypted_private_key_blob: vec![version as u8, version as u8 + 1, 9],
            enabled,
            storage_label: format!(
                "local-keystore/{account}/aws-esdk-rust-recipient-key/{version}"
            ),
        }
    }

    fn startup_proxy_config(keystore_path: std::path::PathBuf) -> TrustlessProxyConfig {
        TrustlessProxyConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            remote_gateway_url: "http://127.0.0.1:3000".to_owned(),
            chain_rpc_url: "ws://127.0.0.1:9944".to_owned(),
            local_account: "alice".to_owned(),
            keystore_path,
            local_private_key_unlock_key: [31u8; 32],
            aws_esdk_key_namespace: "startup-test-namespace".to_owned(),
        }
    }

    #[test]
    fn cli_prepares_startup_dependencies_without_network_bind_or_secret_leak() {
        let keystore_path = startup_temp_path("dependencies");
        LocalKeystoreFile::write_records(
            &keystore_path,
            &[
                startup_local_record("alice", 1, true),
                startup_local_record("alice", 3, false),
                startup_local_record("alice", 2, true),
                startup_local_record("bob", 9, true),
            ],
        )
        .unwrap();

        let plan = LocalTrustlessCli::prepare_startup_dependencies(
            startup_proxy_config(keystore_path.clone()),
            LocalTrustlessCliInput {
                remote_gateway_url: None,
                ..LocalTrustlessCli::default_input(
                    LocalTrustlessCliCommand::LocalProxyStartScaffold,
                )
            },
        )
        .unwrap();

        assert_eq!(
            plan.command,
            LocalTrustlessCliCommand::LocalProxyStartScaffold
        );
        assert!(plan.server_initialized);
        assert_eq!(
            plan.server_config.remote_gateway_url,
            Some("http://127.0.0.1:3000".to_owned())
        );
        assert_eq!(plan.local_keystore_record_count, 4);
        assert_eq!(plan.selected_local_key_account, "alice");
        assert_eq!(plan.selected_local_key_type, "aws-esdk-rust-recipient-key");
        assert_eq!(plan.selected_local_key_version, 2);
        assert!(
            plan.selected_local_key_storage_label
                .contains("local-keystore/alice")
        );
        assert!(plan.local_keystore_resolver_prepared);
        assert!(plan.recipient_key_resolver_boundary_prepared);
        assert!(plan.preflight_builder_prepared);
        assert!(plan.remote_gateway_client_prepared);
        assert!(
            plan.remote_gateway_endpoint_url
                .contains("/trustless/v1/ciphertext-gateway")
        );
        assert!(plan.remote_gateway_executor_prepared);
        assert!(!plan.network_bind_performed);
        assert!(!plan.gateway_plaintext_access);

        let debug = format!("{plan:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&hex::encode([31u8; 32])));
        assert!(!debug.contains("plaintext_private_key"));
        assert!(!debug.contains("raw_private_key"));
        assert!(!debug.contains("private_key_material"));

        let _ = std::fs::remove_file(keystore_path);
    }

    #[test]
    fn cli_startup_local_keystore_resolver_exposes_only_matching_records() {
        let resolver = LocalTrustlessStartupLocalKeystoreResolver::new(vec![
            startup_local_record("alice", 1, true),
            startup_local_record("bob", 1, true),
        ]);

        let records = resolver
            .list_local_private_keys(&"alice".to_owned(), "aws-esdk-rust-recipient-key")
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].account, "alice");
        assert!(!records[0].encrypted_private_key_blob.is_empty());
    }

    #[test]
    fn cli_startup_dependencies_reject_missing_local_keystore_selection() {
        let keystore_path = startup_temp_path("missing-selection");
        LocalKeystoreFile::write_records(&keystore_path, &[startup_local_record("bob", 1, true)])
            .unwrap();

        let err = LocalTrustlessCli::prepare_startup_dependencies(
            startup_proxy_config(keystore_path.clone()),
            LocalTrustlessCli::default_input(LocalTrustlessCliCommand::LocalProxyStartScaffold),
        )
        .unwrap_err();

        assert!(matches!(err, LocalTrustlessCliError::StartupDependency(_)));

        let _ = std::fs::remove_file(keystore_path);
    }

    #[test]
    fn cli_startup_dependencies_reject_network_bind() {
        let keystore_path = startup_temp_path("network-bind");
        LocalKeystoreFile::write_records(&keystore_path, &[startup_local_record("alice", 1, true)])
            .unwrap();

        let err = LocalTrustlessCli::prepare_startup_dependencies(
            startup_proxy_config(keystore_path.clone()),
            LocalTrustlessCliInput {
                network_bind_enabled: true,
                ..LocalTrustlessCli::default_input(
                    LocalTrustlessCliCommand::LocalProxyStartScaffold,
                )
            },
        )
        .unwrap_err();

        assert_eq!(err, LocalTrustlessCliError::NetworkBindFlagRejected);

        let _ = std::fs::remove_file(keystore_path);
    }

    #[test]
    fn cli_prepares_local_proxy_start_scaffold_without_network_bind() {
        let prepared = LocalTrustlessCli::prepare_command(LocalTrustlessCliInput {
            remote_gateway_url: Some("http://127.0.0.1:3000".to_owned()),
            ..LocalTrustlessCli::default_input(LocalTrustlessCliCommand::LocalProxyStartScaffold)
        })
        .unwrap();

        assert_eq!(
            prepared.command,
            LocalTrustlessCliCommand::LocalProxyStartScaffold
        );
        assert!(prepared.server_initialized);
        assert!(!prepared.network_bind_performed);
        assert!(!prepared.server_config.network_bind_enabled);
        assert_eq!(prepared.server_config.listen_host, "127.0.0.1");
        assert_eq!(prepared.server_config.listen_port, 9090);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn cli_prepares_config_view_without_network_bind() {
        let prepared = LocalTrustlessCli::prepare_command(LocalTrustlessCliInput {
            command: LocalTrustlessCliCommand::LocalProxyConfig,
            listen_host: "localhost".to_owned(),
            listen_port: 9191,
            max_request_body_bytes: 1024,
            remote_gateway_url: None,
            network_bind_enabled: false,
        })
        .unwrap();

        assert_eq!(prepared.command, LocalTrustlessCliCommand::LocalProxyConfig);
        assert_eq!(prepared.server_config.listen_host, "localhost");
        assert_eq!(prepared.server_config.listen_port, 9191);
        assert!(prepared.summary.contains("config validated"));
        assert!(!prepared.network_bind_performed);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn cli_parse_args_accepts_safe_local_proxy_flags() {
        let input = LocalTrustlessCli::from_args([
            "trustless-proxy",
            "local-proxy",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            "9091",
            "--max-request-body-bytes",
            "2048",
            "--remote-gateway-url",
            "http://127.0.0.1:3000",
            "--no-network-bind",
        ])
        .unwrap();

        assert_eq!(
            input.command,
            LocalTrustlessCliCommand::LocalProxyStartScaffold
        );
        assert_eq!(input.listen_host, "127.0.0.1");
        assert_eq!(input.listen_port, 9091);
        assert_eq!(input.max_request_body_bytes, 2048);
        assert_eq!(
            input.remote_gateway_url,
            Some("http://127.0.0.1:3000".to_owned())
        );
        assert!(!input.network_bind_enabled);
    }

    #[test]
    fn cli_prepare_from_args_builds_server_config_boundary() {
        let prepared = LocalTrustlessCli::prepare_from_args([
            "trustless-proxy",
            "local-proxy-start",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            "9092",
            "--max-request-body-bytes",
            "4096",
        ])
        .unwrap();

        assert_eq!(prepared.server_config.listen_port, 9092);
        assert_eq!(prepared.server_config.max_request_body_bytes, 4096);
        assert!(prepared.server_initialized);
        assert!(!prepared.network_bind_performed);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn cli_rejects_network_bind_flag() {
        let err = LocalTrustlessCli::from_args([
            "trustless-proxy",
            "local-proxy",
            "--network-bind-enabled",
        ])
        .unwrap_err();

        assert_eq!(err, LocalTrustlessCliError::NetworkBindFlagRejected);
    }

    #[test]
    fn cli_rejects_invalid_listen_port() {
        let err =
            LocalTrustlessCli::from_args(["trustless-proxy", "local-proxy", "--listen-port", "0"])
                .unwrap_err();

        assert_eq!(err, LocalTrustlessCliError::InvalidListenPort);

        let err = LocalTrustlessCli::from_args([
            "trustless-proxy",
            "local-proxy",
            "--listen-port",
            "not-a-port",
        ])
        .unwrap_err();

        assert_eq!(err, LocalTrustlessCliError::InvalidListenPort);
    }

    #[test]
    fn cli_rejects_invalid_request_body_limit() {
        let err = LocalTrustlessCli::from_args([
            "trustless-proxy",
            "local-proxy",
            "--max-request-body-bytes",
            "0",
        ])
        .unwrap_err();

        assert_eq!(err, LocalTrustlessCliError::InvalidRequestBodyLimit);
    }

    #[test]
    fn cli_rejects_unknown_command_and_unknown_flag() {
        let err = LocalTrustlessCli::from_args(["trustless-proxy", "serve"]).unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessCliError::UnknownCommand("serve".to_owned())
        );

        let err =
            LocalTrustlessCli::from_args(["trustless-proxy", "local-proxy", "--bind-real-network"])
                .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessCliError::UnknownFlag("--bind-real-network".to_owned())
        );
    }

    #[test]
    fn cli_rejects_missing_flag_value() {
        let err = LocalTrustlessCli::from_args(["trustless-proxy", "local-proxy", "--listen-host"])
            .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessCliError::MissingFlagValue("--listen-host".to_owned())
        );
    }
}
