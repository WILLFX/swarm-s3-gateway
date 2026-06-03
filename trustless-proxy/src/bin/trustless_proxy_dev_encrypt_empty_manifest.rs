use std::env;
use std::path::PathBuf;

use trustless_proxy::aws_esdk::{
    AwsEsdkKeyringConfig, AwsEsdkRawRsaByteCryptoAdapterConfig, AwsEsdkTrustlessRecipientKeyring,
    RealAwsEsdkRawRsaByteCryptoAdapter,
};
use trustless_proxy::local_keystore::AesGcmLocalPrivateKeyUnlocker;
use trustless_proxy::local_keystore_file::LocalKeystoreFile;
use trustless_proxy::manifest::{TrustlessManifest, TrustlessManifestBoundary};
use trustless_proxy::manifest_codec::AwsEsdkTrustlessManifestCipher;
use trustless_proxy::recipient_key_file::LocalRecipientKeyFile;
use trustless_proxy::types::{RecipientEncryptionKey, RecipientEnvelopeContext};

const DEFAULT_KEY_TYPE: &str = "aws-esdk-rust-recipient-key";
const DEFAULT_KEY_NAMESPACE: &str = "swarm-s3-trustless-recipient";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keystore_path = PathBuf::from(required_env("TRUSTLESS_PROXY_DEV_MANIFEST_KEYSTORE_PATH")?);
    let recipient_keys_path = PathBuf::from(required_env(
        "TRUSTLESS_PROXY_DEV_MANIFEST_RECIPIENT_KEYS_PATH",
    )?);
    let unlock_key_hex = required_env("TRUSTLESS_PROXY_DEV_MANIFEST_UNLOCK_KEY_HEX")?;
    let account = required_env("TRUSTLESS_PROXY_DEV_MANIFEST_ACCOUNT")?;
    let bucket_id = required_env("TRUSTLESS_PROXY_DEV_MANIFEST_BUCKET_ID")?;
    let object_key_id = required_env("TRUSTLESS_PROXY_DEV_MANIFEST_OBJECT_KEY_ID")?;

    let key_type = env::var("TRUSTLESS_PROXY_DEV_MANIFEST_KEY_TYPE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_KEY_TYPE.to_owned());

    let policy_version = env::var("TRUSTLESS_PROXY_DEV_MANIFEST_POLICY_VERSION")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(1);

    let key_namespace = env::var("TRUSTLESS_PROXY_DEV_MANIFEST_KEY_NAMESPACE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_KEY_NAMESPACE.to_owned());

    let unlock_key = parse_unlock_key(&unlock_key_hex)?;

    let selection = LocalKeystoreFile::load_private_key_selection(
        &keystore_path,
        account.clone(),
        key_type.clone(),
    )?;

    let unlocker = AesGcmLocalPrivateKeyUnlocker::new(unlock_key);
    let adapter_config =
        AwsEsdkRawRsaByteCryptoAdapterConfig::from_local_private_key_selection_with_namespace(
            selection,
            key_namespace,
            &unlocker,
        )?;

    let keyring = AwsEsdkTrustlessRecipientKeyring::with_adapter(
        AwsEsdkKeyringConfig::default(),
        RealAwsEsdkRawRsaByteCryptoAdapter::new(adapter_config),
    );

    let cipher = AwsEsdkTrustlessManifestCipher::new(keyring);
    let boundary = TrustlessManifestBoundary::new(cipher);

    let recipient_records = LocalRecipientKeyFile::read_records(&recipient_keys_path)?;
    let mut recipients = recipient_records
        .into_iter()
        .filter(|record| record.enabled)
        .map(|record| RecipientEncryptionKey {
            account: record.account,
            public_key: record.public_key,
            key_type: record.key_type,
            key_version: record.key_version,
            enabled: record.enabled,
        })
        .collect::<Vec<_>>();

    recipients.sort_by(|left, right| left.account.cmp(&right.account));

    if recipients.is_empty() {
        return Err("recipient key file did not contain any enabled recipient keys".into());
    }

    let manifest = TrustlessManifest {
        bucket_id: bucket_id.clone(),
        manifest_version: 1,
        entries: Vec::new(),
    };

    let context = RecipientEnvelopeContext {
        bucket_id,
        object_key_id,
        policy_version,
        recipients,
    };

    let encrypted = boundary.encrypt_manifest_locally(manifest, context)?;

    println!("{}", hex::encode(encrypted.encrypted_manifest.ciphertext));

    Ok(())
}

fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)
        .map_err(|_| format!("missing required environment variable: {name}"))?
        .trim()
        .to_owned();

    if value.is_empty() {
        return Err(format!("empty required environment variable: {name}").into());
    }

    Ok(value)
}

fn parse_unlock_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(value.trim())?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "unlock key must be 32 bytes encoded as 64 hex characters")?;
    Ok(key)
}
