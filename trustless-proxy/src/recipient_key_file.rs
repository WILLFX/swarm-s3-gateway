use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::recipient_keys::{RecipientKeyError, RecipientKeyRecord, RecipientKeyResolver};
use crate::types::SubstrateAccountId;

const RECIPIENT_KEY_FILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalRecipientKeyFileDocument {
    schema_version: u32,
    recipients: Vec<LocalRecipientKeyFileRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRecipientKeyFileRecord {
    pub account: SubstrateAccountId,
    pub public_key: String,
    pub key_type: String,
    pub key_version: u32,
    pub enabled: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalRecipientKeyFileError {
    #[error("local recipient key file is empty or malformed")]
    EmptyOrMalformedFile,

    #[error("unsupported local recipient key file schema version: {0}")]
    UnsupportedSchemaVersion(u32),

    #[error("local recipient key file must contain at least one recipient")]
    MissingRecipients,

    #[error("local recipient key record account is required")]
    MissingAccount,

    #[error("local recipient key record public key is required: {0}")]
    MissingPublicKey(SubstrateAccountId),

    #[error("local recipient key record key type is required: {0}")]
    MissingKeyType(SubstrateAccountId),

    #[error("local recipient key record key version must be greater than zero: {0}")]
    InvalidKeyVersion(SubstrateAccountId),

    #[error("local recipient key file I/O failed: {0}")]
    Io(String),

    #[error("local recipient key file JSON failed: {0}")]
    Json(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecipientKeyFileResolver {
    records: BTreeMap<SubstrateAccountId, RecipientKeyRecord>,
}

impl LocalRecipientKeyFileResolver {
    pub fn new(records: Vec<RecipientKeyRecord>) -> Self {
        let mut selected = BTreeMap::new();

        for record in records {
            if !record.enabled {
                continue;
            }

            selected
                .entry(record.account.clone())
                .and_modify(|existing: &mut RecipientKeyRecord| {
                    if record.key_version > existing.key_version {
                        *existing = record.clone();
                    }
                })
                .or_insert(record);
        }

        Self { records: selected }
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl RecipientKeyResolver for LocalRecipientKeyFileResolver {
    fn resolve_recipient_key(
        &self,
        account: &SubstrateAccountId,
    ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
        Ok(self.records.get(account.trim()).cloned())
    }
}

pub struct LocalRecipientKeyFile;

impl LocalRecipientKeyFile {
    pub fn read_records(
        path: impl AsRef<Path>,
    ) -> Result<Vec<RecipientKeyRecord>, LocalRecipientKeyFileError> {
        let bytes = fs::read(path.as_ref())
            .map_err(|error| LocalRecipientKeyFileError::Io(error.to_string()))?;

        if bytes.is_empty() {
            return Err(LocalRecipientKeyFileError::EmptyOrMalformedFile);
        }

        let document: LocalRecipientKeyFileDocument = serde_json::from_slice(&bytes)
            .map_err(|error| LocalRecipientKeyFileError::Json(error.to_string()))?;

        if document.schema_version != RECIPIENT_KEY_FILE_SCHEMA_VERSION {
            return Err(LocalRecipientKeyFileError::UnsupportedSchemaVersion(
                document.schema_version,
            ));
        }

        if document.recipients.is_empty() {
            return Err(LocalRecipientKeyFileError::MissingRecipients);
        }

        document
            .recipients
            .into_iter()
            .map(validate_record)
            .collect()
    }

    #[cfg(test)]
    pub fn write_records(
        path: impl AsRef<Path>,
        records: &[RecipientKeyRecord],
    ) -> Result<(), LocalRecipientKeyFileError> {
        let document = LocalRecipientKeyFileDocument {
            schema_version: RECIPIENT_KEY_FILE_SCHEMA_VERSION,
            recipients: records
                .iter()
                .cloned()
                .map(|record| LocalRecipientKeyFileRecord {
                    account: record.account,
                    public_key: record.public_key,
                    key_type: record.key_type,
                    key_version: record.key_version,
                    enabled: record.enabled,
                })
                .collect(),
        };

        let bytes = serde_json::to_vec_pretty(&document)
            .map_err(|error| LocalRecipientKeyFileError::Json(error.to_string()))?;

        fs::write(path.as_ref(), bytes)
            .map_err(|error| LocalRecipientKeyFileError::Io(error.to_string()))
    }
}

fn validate_record(
    record: LocalRecipientKeyFileRecord,
) -> Result<RecipientKeyRecord, LocalRecipientKeyFileError> {
    let account = record.account.trim().to_owned();

    if account.is_empty() {
        return Err(LocalRecipientKeyFileError::MissingAccount);
    }

    let public_key = record.public_key.trim().to_owned();

    if public_key.is_empty() {
        return Err(LocalRecipientKeyFileError::MissingPublicKey(account));
    }

    let key_type = record.key_type.trim().to_owned();

    if key_type.is_empty() {
        return Err(LocalRecipientKeyFileError::MissingKeyType(account));
    }

    if record.key_version == 0 {
        return Err(LocalRecipientKeyFileError::InvalidKeyVersion(account));
    }

    Ok(RecipientKeyRecord {
        account,
        public_key,
        key_type,
        key_version: record.key_version,
        enabled: record.enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "s3w-local-recipient-keys-{}-{name}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn record(account: &str, version: u32, enabled: bool) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: format!(
                "-----BEGIN PUBLIC KEY-----\n{account}-{version}\n-----END PUBLIC KEY-----\n"
            ),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: version,
            enabled,
        }
    }

    #[test]
    fn local_recipient_key_file_writes_reads_and_resolves_highest_enabled_key() {
        let path = temp_path("roundtrip");

        LocalRecipientKeyFile::write_records(
            &path,
            &[
                record("alice", 1, true),
                record("alice", 3, false),
                record("alice", 2, true),
                record("bob", 1, true),
            ],
        )
        .unwrap();

        let records = LocalRecipientKeyFile::read_records(&path).unwrap();
        let resolver = LocalRecipientKeyFileResolver::new(records);

        let alice = resolver
            .resolve_recipient_key(&"alice".to_owned())
            .unwrap()
            .unwrap();

        assert_eq!(resolver.record_count(), 2);
        assert_eq!(alice.account, "alice");
        assert_eq!(alice.key_version, 2);
        assert!(alice.enabled);

        let missing = resolver.resolve_recipient_key(&"carol".to_owned()).unwrap();
        assert!(missing.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_recipient_key_file_rejects_empty_or_malformed_records() {
        let path = temp_path("bad");

        std::fs::write(&path, br#"{"schema_version":1,"recipients":[]}"#).unwrap();

        assert_eq!(
            LocalRecipientKeyFile::read_records(&path).unwrap_err(),
            LocalRecipientKeyFileError::MissingRecipients
        );

        std::fs::write(
            &path,
            br#"{"schema_version":1,"recipients":[{"account":"","public_key":"pk","key_type":"aws-esdk-rust-recipient-key","key_version":1,"enabled":true}]}"#,
        )
        .unwrap();

        assert_eq!(
            LocalRecipientKeyFile::read_records(&path).unwrap_err(),
            LocalRecipientKeyFileError::MissingAccount
        );

        std::fs::write(
            &path,
            br#"{"schema_version":2,"recipients":[{"account":"alice","public_key":"pk","key_type":"aws-esdk-rust-recipient-key","key_version":1,"enabled":true}]}"#,
        )
        .unwrap();

        assert_eq!(
            LocalRecipientKeyFile::read_records(&path).unwrap_err(),
            LocalRecipientKeyFileError::UnsupportedSchemaVersion(2)
        );

        let _ = std::fs::remove_file(path);
    }
}
