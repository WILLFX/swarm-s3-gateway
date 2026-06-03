use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use trustless_proxy::local_keystore::{
    AesGcmLocalPrivateKeyUnlocker, LocalKeystoreRecord, LocalPrivateKeySelection,
};
use trustless_proxy::local_keystore_file::LocalKeystoreFile;

const DEFAULT_KEY_TYPE: &str = "aws-esdk-rust-recipient-key";
const DEFAULT_KEY_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
struct RecipientKeyFileDocument {
    schema_version: u32,
    recipients: Vec<RecipientKeyFileRecord>,
}

#[derive(Debug, Serialize)]
struct RecipientKeyFileRecord {
    account: String,
    public_key: String,
    key_type: String,
    key_version: u32,
    enabled: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = env_path("TRUSTLESS_PROXY_DEV_KEY_OUTPUT_DIR")?;
    let account = required_env("TRUSTLESS_PROXY_DEV_KEY_ACCOUNT")?;
    let unlock_key_hex = required_env("TRUSTLESS_PROXY_DEV_KEY_UNLOCK_KEY_HEX")?;
    let key_type = env::var("TRUSTLESS_PROXY_DEV_KEY_TYPE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_KEY_TYPE.to_owned());

    let key_version = env::var("TRUSTLESS_PROXY_DEV_KEY_VERSION")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(DEFAULT_KEY_VERSION);

    if key_version == 0 {
        return Err("TRUSTLESS_PROXY_DEV_KEY_VERSION must be greater than zero".into());
    }

    fs::create_dir_all(&output_dir)?;

    let keystore_path = env::var("TRUSTLESS_PROXY_DEV_KEY_KEYSTORE_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| output_dir.join("local-keystore.json"));

    let recipient_keys_path = env::var("TRUSTLESS_PROXY_DEV_KEY_RECIPIENT_KEYS_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| output_dir.join("local-keystore.recipient-keys.json"));

    let private_key_path = output_dir.join("local-private-key.pem");
    let public_key_path = output_dir.join("local-public-key.pem");
    let env_path = output_dir.join("local-proxy-key-material.env");

    if private_key_path.exists()
        || public_key_path.exists()
        || keystore_path.exists()
        || recipient_keys_path.exists()
        || env_path.exists()
    {
        return Err("dev key material helper refuses to overwrite existing files".into());
    }

    run_openssl(
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            path_name(&private_key_path)?,
        ],
        &output_dir,
    )?;

    run_openssl(
        &[
            "pkey",
            "-in",
            path_name(&private_key_path)?,
            "-pubout",
            "-out",
            path_name(&public_key_path)?,
        ],
        &output_dir,
    )?;

    let private_key_pem = fs::read(&private_key_path)?;
    let public_key_pem = fs::read(&public_key_path)?;

    let unlock_key = parse_unlock_key(&unlock_key_hex)?;

    let storage_label = format!("local-keystore/{account}/{key_type}/{key_version}");
    let selection = LocalPrivateKeySelection {
        account: account.clone(),
        key_type: key_type.clone(),
        key_version,
        encrypted_private_key_blob: b"placeholder".to_vec(),
        storage_label: storage_label.clone(),
    };

    let encrypted_private_key_blob = AesGcmLocalPrivateKeyUnlocker::new(unlock_key)
        .seal_private_key_for_storage(&selection, &private_key_pem)?;

    LocalKeystoreFile::write_records(
        &keystore_path,
        &[LocalKeystoreRecord {
            account: account.clone(),
            key_type: key_type.clone(),
            key_version,
            encrypted_private_key_blob,
            enabled: true,
            storage_label,
        }],
    )?;

    let public_key = String::from_utf8(public_key_pem.clone())?;
    let recipient_document = RecipientKeyFileDocument {
        schema_version: 1,
        recipients: vec![RecipientKeyFileRecord {
            account: account.clone(),
            public_key,
            key_type: key_type.clone(),
            key_version,
            enabled: true,
        }],
    };

    fs::write(
        &recipient_keys_path,
        serde_json::to_vec_pretty(&recipient_document)?,
    )?;

    let public_key_hex = hex::encode(&public_key_pem);
    let recipient_key_header = format!("{account}|{key_type}|{key_version}|true|{public_key_hex}");

    fs::write(
        &env_path,
        format!(
            concat!(
                "export TRUSTLESS_PROXY_KEYSTORE_PATH=\"{}\"\n",
                "export TRUSTLESS_PROXY_RECIPIENT_KEYS_PATH=\"{}\"\n",
                "export TRUSTLESS_PROXY_LOCAL_PRIVATE_KEY_UNLOCK_KEY_HEX=\"{}\"\n",
                "export S3W_LOCAL_PROXY_ACCOUNT=\"{}\"\n",
                "export S3W_LOCAL_PROXY_KEY_TYPE=\"{}\"\n",
                "export S3W_LOCAL_PROXY_KEY_VERSION=\"{}\"\n",
                "export S3W_RECIPIENT_KEY_HEADER=\"{}\"\n",
                "export S3W_PUBLIC_KEY_PATH=\"{}\"\n",
                "export S3W_PRIVATE_KEY_PATH=\"{}\"\n"
            ),
            keystore_path.display(),
            recipient_keys_path.display(),
            unlock_key_hex,
            account,
            key_type,
            key_version,
            recipient_key_header,
            public_key_path.display(),
            private_key_path.display(),
        ),
    )?;

    println!("keystore_path={}", keystore_path.display());
    println!("recipient_keys_path={}", recipient_keys_path.display());
    println!("env_path={}", env_path.display());
    println!("public_key_path={}", public_key_path.display());
    println!("private_key_path={}", private_key_path.display());
    println!("recipient_key_header_ready=true");

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

fn env_path(name: &'static str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(required_env(name)?))
}

fn parse_unlock_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(value.trim())?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "unlock key must be 32 bytes encoded as 64 hex characters")?;
    Ok(key)
}

fn run_openssl(args: &[&str], cwd: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(cwd)
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "openssl failed: {}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(())
}

fn path_name(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("path has no UTF-8 file name: {}", path.display()).into())
}
