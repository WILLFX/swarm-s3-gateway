use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::local_keystore::{LocalKeystoreRecord, LocalPrivateKeySelection};
use crate::types::SubstrateAccountId;

const KEYSTORE_SCHEMA: &str = "s3w.trustless.local-keystore";
const KEYSTORE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct LocalKeystoreFile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalKeystoreFileDocument {
    pub schema: String,
    pub version: u32,
    pub records: Vec<LocalKeystoreFileRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalKeystoreFileRecord {
    pub account: SubstrateAccountId,
    pub key_type: String,
    pub key_version: u32,
    pub encrypted_private_key_hex: String,
    pub storage_label: String,
    pub enabled: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalKeystoreFileError {
    #[error("local keystore file path is required")]
    MissingPath,

    #[error("local keystore file is empty")]
    EmptyFile,

    #[error("unsupported local keystore schema {schema} version {version}")]
    UnsupportedSchemaVersion { schema: String, version: u32 },

    #[error("local keystore account is required")]
    MissingAccount,

    #[error("local keystore key type is required")]
    MissingKeyType,

    #[error("local keystore key version must be greater than zero")]
    InvalidKeyVersion,

    #[error("local keystore encrypted private key blob is required")]
    MissingEncryptedPrivateKeyBlob,

    #[error("local keystore storage label is required")]
    MissingStorageLabel,

    #[error("invalid encrypted private key hex: {0}")]
    InvalidEncryptedPrivateKeyHex(String),

    #[error("no enabled local private key found for account {account} and key type {key_type}")]
    NoEnabledLocalPrivateKey {
        account: SubstrateAccountId,
        key_type: String,
    },

    #[error("local keystore JSON encode failed: {0}")]
    Encode(String),

    #[error("local keystore JSON decode failed: {0}")]
    Decode(String),

    #[error("local keystore file IO failed: {0}")]
    Io(String),
}

impl LocalKeystoreFile {
    pub fn document_from_records(
        records: &[LocalKeystoreRecord],
    ) -> Result<LocalKeystoreFileDocument, LocalKeystoreFileError> {
        let mut records = records
            .iter()
            .map(LocalKeystoreFileRecord::from_record)
            .collect::<Result<Vec<_>, _>>()?;

        records.sort_by(|left, right| {
            left.account
                .cmp(&right.account)
                .then_with(|| left.key_type.cmp(&right.key_type))
                .then_with(|| left.key_version.cmp(&right.key_version))
                .then_with(|| left.storage_label.cmp(&right.storage_label))
        });

        Ok(LocalKeystoreFileDocument {
            schema: KEYSTORE_SCHEMA.to_owned(),
            version: KEYSTORE_SCHEMA_VERSION,
            records,
        })
    }

    pub fn records_from_document(
        document: LocalKeystoreFileDocument,
    ) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreFileError> {
        if document.schema != KEYSTORE_SCHEMA || document.version != KEYSTORE_SCHEMA_VERSION {
            return Err(LocalKeystoreFileError::UnsupportedSchemaVersion {
                schema: document.schema,
                version: document.version,
            });
        }

        document
            .records
            .into_iter()
            .map(LocalKeystoreFileRecord::into_record)
            .collect()
    }

    pub fn encode_records(
        records: &[LocalKeystoreRecord],
    ) -> Result<Vec<u8>, LocalKeystoreFileError> {
        let document = Self::document_from_records(records)?;

        serde_json::to_vec(&document)
            .map_err(|error| LocalKeystoreFileError::Encode(error.to_string()))
    }

    pub fn decode_records(json: &[u8]) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreFileError> {
        if json.is_empty() {
            return Err(LocalKeystoreFileError::EmptyFile);
        }

        let document: LocalKeystoreFileDocument = serde_json::from_slice(json)
            .map_err(|error| LocalKeystoreFileError::Decode(error.to_string()))?;

        Self::records_from_document(document)
    }

    pub fn write_records(
        path: impl AsRef<Path>,
        records: &[LocalKeystoreRecord],
    ) -> Result<(), LocalKeystoreFileError> {
        let path = require_path(path.as_ref())?;
        let bytes = Self::encode_records(records)?;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|error| LocalKeystoreFileError::Io(error.to_string()))?;
            }
        }

        fs::write(path, bytes).map_err(|error| LocalKeystoreFileError::Io(error.to_string()))
    }

    pub fn read_records(
        path: impl AsRef<Path>,
    ) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreFileError> {
        let path = require_path(path.as_ref())?;

        let bytes =
            fs::read(path).map_err(|error| LocalKeystoreFileError::Io(error.to_string()))?;

        Self::decode_records(&bytes)
    }

    pub fn load_private_key_selection(
        path: impl AsRef<Path>,
        account: impl Into<String>,
        key_type: impl Into<String>,
    ) -> Result<LocalPrivateKeySelection, LocalKeystoreFileError> {
        let account = require_non_empty(account.into(), LocalKeystoreFileError::MissingAccount)?;
        let key_type = require_non_empty(key_type.into(), LocalKeystoreFileError::MissingKeyType)?;
        let records = Self::read_records(path)?;

        let mut candidates = records
            .into_iter()
            .filter(|record| {
                record.enabled && record.account == account && record.key_type == key_type
            })
            .collect::<Vec<_>>();

        candidates.sort_by(|left, right| {
            right
                .key_version
                .cmp(&left.key_version)
                .then_with(|| left.storage_label.cmp(&right.storage_label))
        });

        let Some(record) = candidates.into_iter().next() else {
            return Err(LocalKeystoreFileError::NoEnabledLocalPrivateKey { account, key_type });
        };

        validate_record(&record)?;

        Ok(LocalPrivateKeySelection {
            account: record.account,
            key_type: record.key_type,
            key_version: record.key_version,
            encrypted_private_key_blob: record.encrypted_private_key_blob,
            storage_label: record.storage_label,
        })
    }
}

impl LocalKeystoreFileRecord {
    fn from_record(record: &LocalKeystoreRecord) -> Result<Self, LocalKeystoreFileError> {
        validate_record(record)?;

        Ok(Self {
            account: record.account.trim().to_owned(),
            key_type: record.key_type.trim().to_owned(),
            key_version: record.key_version,
            encrypted_private_key_hex: hex::encode(&record.encrypted_private_key_blob),
            storage_label: record.storage_label.trim().to_owned(),
            enabled: record.enabled,
        })
    }

    fn into_record(self) -> Result<LocalKeystoreRecord, LocalKeystoreFileError> {
        let encrypted_private_key_blob = hex::decode(self.encrypted_private_key_hex.trim())
            .map_err(|error| {
                LocalKeystoreFileError::InvalidEncryptedPrivateKeyHex(error.to_string())
            })?;

        let record = LocalKeystoreRecord {
            account: self.account.trim().to_owned(),
            key_type: self.key_type.trim().to_owned(),
            key_version: self.key_version,
            encrypted_private_key_blob,
            storage_label: self.storage_label.trim().to_owned(),
            enabled: self.enabled,
        };

        validate_record(&record)?;

        Ok(record)
    }
}

fn require_path(path: &Path) -> Result<&Path, LocalKeystoreFileError> {
    if path.as_os_str().is_empty() {
        return Err(LocalKeystoreFileError::MissingPath);
    }

    Ok(path)
}

fn require_non_empty(
    value: String,
    error: LocalKeystoreFileError,
) -> Result<String, LocalKeystoreFileError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

fn validate_record(record: &LocalKeystoreRecord) -> Result<(), LocalKeystoreFileError> {
    if record.account.trim().is_empty() {
        return Err(LocalKeystoreFileError::MissingAccount);
    }

    if record.key_type.trim().is_empty() {
        return Err(LocalKeystoreFileError::MissingKeyType);
    }

    if record.key_version == 0 {
        return Err(LocalKeystoreFileError::InvalidKeyVersion);
    }

    if record.encrypted_private_key_blob.is_empty() {
        return Err(LocalKeystoreFileError::MissingEncryptedPrivateKeyBlob);
    }

    if record.storage_label.trim().is_empty() {
        return Err(LocalKeystoreFileError::MissingStorageLabel);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(account: &str, key_type: &str, version: u32, enabled: bool) -> LocalKeystoreRecord {
        LocalKeystoreRecord {
            account: account.to_owned(),
            key_type: key_type.to_owned(),
            key_version: version,
            encrypted_private_key_blob: vec![version as u8, version as u8 + 1],
            storage_label: format!("local-keystore/{account}/{key_type}/{version}"),
            enabled,
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "s3w-trustless-keystore-{}-{name}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn local_keystore_file_encodes_encrypted_records_without_plaintext_key_fields() {
        let bytes = LocalKeystoreFile::encode_records(&[
            record("bob", "aws-esdk-rust-recipient-key", 1, true),
            record("alice", "aws-esdk-rust-recipient-key", 2, true),
        ])
        .unwrap();

        let json = String::from_utf8(bytes).unwrap();

        assert!(json.contains("\"schema\":\"s3w.trustless.local-keystore\""));
        assert!(json.contains("\"encrypted_private_key_hex\""));
        assert!(!json.contains("plaintext_private_key"));
        assert!(!json.contains("raw_private_key"));
        assert!(!json.contains("private_key_material"));

        let alice = json.find("\"account\":\"alice\"").unwrap();
        let bob = json.find("\"account\":\"bob\"").unwrap();

        assert!(alice < bob);
    }

    #[test]
    fn local_keystore_file_round_trips_records_deterministically() {
        let records = vec![
            record("bob", "aws-esdk-rust-recipient-key", 1, true),
            record("alice", "aws-esdk-rust-recipient-key", 2, true),
        ];

        let bytes = LocalKeystoreFile::encode_records(&records).unwrap();
        let decoded = LocalKeystoreFile::decode_records(&bytes).unwrap();
        let encoded_again = LocalKeystoreFile::encode_records(&decoded).unwrap();

        assert_eq!(bytes, encoded_again);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].account, "alice");
        assert_eq!(decoded[1].account, "bob");
    }

    #[test]
    fn local_keystore_file_writes_and_reads_records_from_disk() {
        let path = temp_path("round-trip");
        let records = vec![record("alice", "aws-esdk-rust-recipient-key", 1, true)];

        LocalKeystoreFile::write_records(&path, &records).unwrap();
        let decoded = LocalKeystoreFile::read_records(&path).unwrap();

        assert_eq!(decoded, records);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_keystore_file_loads_highest_enabled_private_key_selection() {
        let path = temp_path("selection");
        let records = vec![
            record("alice", "aws-esdk-rust-recipient-key", 1, true),
            record("alice", "aws-esdk-rust-recipient-key", 3, false),
            record("alice", "aws-esdk-rust-recipient-key", 2, true),
            record("bob", "aws-esdk-rust-recipient-key", 9, true),
        ];

        LocalKeystoreFile::write_records(&path, &records).unwrap();

        let selected = LocalKeystoreFile::load_private_key_selection(
            &path,
            "alice",
            "aws-esdk-rust-recipient-key",
        )
        .unwrap();

        assert_eq!(selected.account, "alice");
        assert_eq!(selected.key_type, "aws-esdk-rust-recipient-key");
        assert_eq!(selected.key_version, 2);
        assert_eq!(selected.encrypted_private_key_blob, vec![2, 3]);
        assert!(selected.storage_label.contains("alice"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_keystore_file_rejects_empty_or_malformed_file() {
        assert_eq!(
            LocalKeystoreFile::decode_records(&[]).unwrap_err(),
            LocalKeystoreFileError::EmptyFile
        );

        let err = LocalKeystoreFile::decode_records(b"not-json").unwrap_err();

        assert!(matches!(err, LocalKeystoreFileError::Decode(_)));
    }

    #[test]
    fn local_keystore_file_rejects_unsupported_schema_version() {
        let json = br#"{"schema":"s3w.trustless.local-keystore","version":99,"records":[]}"#;

        let err = LocalKeystoreFile::decode_records(json).unwrap_err();

        assert_eq!(
            err,
            LocalKeystoreFileError::UnsupportedSchemaVersion {
                schema: "s3w.trustless.local-keystore".to_owned(),
                version: 99,
            }
        );
    }

    #[test]
    fn local_keystore_file_rejects_missing_fields_or_empty_blob() {
        let mut missing_account = record("alice", "aws-esdk-rust-recipient-key", 1, true);
        missing_account.account = " ".to_owned();

        assert_eq!(
            LocalKeystoreFile::encode_records(&[missing_account]).unwrap_err(),
            LocalKeystoreFileError::MissingAccount
        );

        let mut empty_blob = record("alice", "aws-esdk-rust-recipient-key", 1, true);
        empty_blob.encrypted_private_key_blob = Vec::new();

        assert_eq!(
            LocalKeystoreFile::encode_records(&[empty_blob]).unwrap_err(),
            LocalKeystoreFileError::MissingEncryptedPrivateKeyBlob
        );
    }

    #[test]
    fn local_keystore_file_rejects_malformed_encrypted_private_key_hex() {
        let json = br#"{"schema":"s3w.trustless.local-keystore","version":1,"records":[{"account":"alice","key_type":"aws-esdk-rust-recipient-key","key_version":1,"encrypted_private_key_hex":"not-hex","storage_label":"local-keystore/alice/1","enabled":true}]}"#;

        let err = LocalKeystoreFile::decode_records(json).unwrap_err();

        assert!(matches!(
            err,
            LocalKeystoreFileError::InvalidEncryptedPrivateKeyHex(_)
        ));
    }

    #[test]
    fn local_keystore_file_rejects_missing_enabled_selection() {
        let path = temp_path("missing-selection");
        let records = vec![record("alice", "aws-esdk-rust-recipient-key", 1, false)];

        LocalKeystoreFile::write_records(&path, &records).unwrap();

        let err = LocalKeystoreFile::load_private_key_selection(
            &path,
            "alice",
            "aws-esdk-rust-recipient-key",
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalKeystoreFileError::NoEnabledLocalPrivateKey {
                account: "alice".to_owned(),
                key_type: "aws-esdk-rust-recipient-key".to_owned(),
            }
        );

        let _ = std::fs::remove_file(path);
    }
}
