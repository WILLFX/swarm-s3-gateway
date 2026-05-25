use std::env;
use std::path::PathBuf;

use thiserror::Error;

const DEFAULT_LISTEN_HOST: &str = "127.0.0.1";
const DEFAULT_LISTEN_PORT: u16 = 9090;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessProxyConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub remote_gateway_url: String,
    pub chain_rpc_url: String,
    pub local_account: String,
    pub keystore_path: PathBuf,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingRequiredEnv(&'static str),

    #[error("TRUSTLESS_PROXY_LISTEN_PORT must be an integer from 1 to 65535")]
    InvalidListenPort,
}

impl TrustlessProxyConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_reader(|name| env::var(name).ok())
    }

    pub fn from_env_reader<F>(read_env: F) -> Result<Self, ConfigError>
    where
        F: Fn(&'static str) -> Option<String>,
    {
        Ok(Self {
            listen_host: read_env("TRUSTLESS_PROXY_LISTEN_HOST")
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_LISTEN_HOST.to_owned()),
            listen_port: parse_port(read_env("TRUSTLESS_PROXY_LISTEN_PORT"))?,
            remote_gateway_url: required_env(&read_env, "TRUSTLESS_PROXY_REMOTE_GATEWAY_URL")?,
            chain_rpc_url: required_env(&read_env, "TRUSTLESS_PROXY_CHAIN_RPC_URL")?,
            local_account: required_env(&read_env, "TRUSTLESS_PROXY_LOCAL_ACCOUNT")?,
            keystore_path: PathBuf::from(required_env(&read_env, "TRUSTLESS_PROXY_KEYSTORE_PATH")?),
        })
    }
}

fn required_env<F>(read_env: &F, name: &'static str) -> Result<String, ConfigError>
where
    F: Fn(&'static str) -> Option<String>,
{
    read_env(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::MissingRequiredEnv(name))
}

fn parse_port(value: Option<String>) -> Result<u16, ConfigError> {
    let Some(value) = value else {
        return Ok(DEFAULT_LISTEN_PORT);
    };

    let value = value.trim();

    if value.is_empty() {
        return Ok(DEFAULT_LISTEN_PORT);
    }

    let port = value
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidListenPort)?;

    if port == 0 {
        return Err(ConfigError::InvalidListenPort);
    }

    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_value(name: &'static str) -> Option<String> {
        match name {
            "TRUSTLESS_PROXY_REMOTE_GATEWAY_URL" => Some("http://127.0.0.1:3000".to_owned()),
            "TRUSTLESS_PROXY_CHAIN_RPC_URL" => Some("ws://127.0.0.1:9944".to_owned()),
            "TRUSTLESS_PROXY_LOCAL_ACCOUNT" => Some("0x1234".to_owned()),
            "TRUSTLESS_PROXY_KEYSTORE_PATH" => {
                Some("./.local/trustless-proxy-keystore.json".to_owned())
            }
            _ => None,
        }
    }

    #[test]
    fn config_applies_local_listen_defaults() {
        let config = TrustlessProxyConfig::from_env_reader(env_value).unwrap();

        assert_eq!(config.listen_host, "127.0.0.1");
        assert_eq!(config.listen_port, 9090);
        assert_eq!(config.remote_gateway_url, "http://127.0.0.1:3000");
        assert_eq!(config.chain_rpc_url, "ws://127.0.0.1:9944");
        assert_eq!(config.local_account, "0x1234");
        assert_eq!(
            config.keystore_path,
            PathBuf::from("./.local/trustless-proxy-keystore.json")
        );
    }

    #[test]
    fn config_accepts_explicit_listen_host_and_port() {
        let config = TrustlessProxyConfig::from_env_reader(|name| match name {
            "TRUSTLESS_PROXY_LISTEN_HOST" => Some("127.0.0.2".to_owned()),
            "TRUSTLESS_PROXY_LISTEN_PORT" => Some("9191".to_owned()),
            other => env_value(other),
        })
        .unwrap();

        assert_eq!(config.listen_host, "127.0.0.2");
        assert_eq!(config.listen_port, 9191);
    }

    #[test]
    fn config_rejects_missing_required_remote_gateway_url() {
        let err = TrustlessProxyConfig::from_env_reader(|name| {
            if name == "TRUSTLESS_PROXY_REMOTE_GATEWAY_URL" {
                None
            } else {
                env_value(name)
            }
        })
        .unwrap_err();

        assert_eq!(
            err,
            ConfigError::MissingRequiredEnv("TRUSTLESS_PROXY_REMOTE_GATEWAY_URL")
        );
    }

    #[test]
    fn config_rejects_invalid_listen_port() {
        let err = TrustlessProxyConfig::from_env_reader(|name| {
            if name == "TRUSTLESS_PROXY_LISTEN_PORT" {
                Some("0".to_owned())
            } else {
                env_value(name)
            }
        })
        .unwrap_err();

        assert_eq!(err, ConfigError::InvalidListenPort);
    }
}
