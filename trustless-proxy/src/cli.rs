use thiserror::Error;

use crate::server::{LocalTrustlessServer, LocalTrustlessServerConfig, LocalTrustlessServerError};

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
