use std::env;
use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

use crate::local_keystore::AesGcmLocalPrivateKeyUnlocker;

const DEFAULT_LISTEN_HOST: &str = "127.0.0.1";
const DEFAULT_LISTEN_PORT: u16 = 9090;
const DEFAULT_AWS_ESDK_KEY_NAMESPACE: &str = "swarm-s3-trustless-recipient";
const LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX_ENV: &str =
    "TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX";

#[derive(Clone, PartialEq, Eq)]
pub struct TrustlessProxyConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub remote_gateway_url: String,
    pub chain_rpc_url: String,
    pub local_account: String,
    pub keystore_path: PathBuf,
    pub local_private_key_unlock_key: [u8; 32],
    pub aws_esdk_key_namespace: String,
}

impl fmt::Debug for TrustlessProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustlessProxyConfig")
            .field("listen_host", &self.listen_host)
            .field("listen_port", &self.listen_port)
            .field("remote_gateway_url", &self.remote_gateway_url)
            .field("chain_rpc_url", &self.chain_rpc_url)
            .field("local_account", &self.local_account)
            .field("keystore_path", &self.keystore_path)
            .field("local_private_key_unlock_key", &"<redacted>")
            .field("aws_esdk_key_namespace", &self.aws_esdk_key_namespace)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingRequiredEnv(&'static str),

    #[error("TRUSTLESS_PROXY_LISTEN_PORT must be an integer from 1 to 65535")]
    InvalidListenPort,

    #[error(
        "TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX must be 32 bytes encoded as 64 hex characters"
    )]
    InvalidLocalPrivateKeyUnlockKeyHex,
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
            local_private_key_unlock_key: parse_local_private_key_unlock_key_hex(required_env(
                &read_env,
                LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX_ENV,
            )?)?,
            aws_esdk_key_namespace: read_env("TRUSTLESS_PROXY_AWS_ESDK_KEY_NAMESPACE")
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_AWS_ESDK_KEY_NAMESPACE.to_owned()),
        })
    }

    pub fn local_private_key_unlocker(&self) -> AesGcmLocalPrivateKeyUnlocker {
        AesGcmLocalPrivateKeyUnlocker::new(self.local_private_key_unlock_key)
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

fn parse_local_private_key_unlock_key_hex(value: String) -> Result<[u8; 32], ConfigError> {
    let bytes =
        hex::decode(value.trim()).map_err(|_| ConfigError::InvalidLocalPrivateKeyUnlockKeyHex)?;

    bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidLocalPrivateKeyUnlockKeyHex)
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
            "TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX" => Some(hex::encode([7u8; 32])),
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
        assert_eq!(config.local_private_key_unlock_key, [7u8; 32]);
        assert_eq!(
            config.aws_esdk_key_namespace,
            "swarm-s3-trustless-recipient"
        );

        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&hex::encode([7u8; 32])));
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
    fn config_accepts_explicit_aws_esdk_key_namespace() {
        let config = TrustlessProxyConfig::from_env_reader(|name| match name {
            "TRUSTLESS_PROXY_AWS_ESDK_KEY_NAMESPACE" => {
                Some("custom-trustless-namespace".to_owned())
            }
            other => env_value(other),
        })
        .unwrap();

        assert_eq!(config.aws_esdk_key_namespace, "custom-trustless-namespace");
    }

    #[test]
    fn config_rejects_invalid_local_private_key_unlock_key_hex() {
        let err = TrustlessProxyConfig::from_env_reader(|name| {
            if name == "TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX" {
                Some("not-hex".to_owned())
            } else {
                env_value(name)
            }
        })
        .unwrap_err();

        assert_eq!(err, ConfigError::InvalidLocalPrivateKeyUnlockKeyHex);

        let err = TrustlessProxyConfig::from_env_reader(|name| {
            if name == "TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX" {
                Some(hex::encode([1u8; 31]))
            } else {
                env_value(name)
            }
        })
        .unwrap_err();

        assert_eq!(err, ConfigError::InvalidLocalPrivateKeyUnlockKeyHex);
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
