use std::{collections::BTreeMap, fmt, future::Future};

use crate::keyring::{KeyringError, TrustlessRecipientKeyring};
use crate::types::{RecipientEncryptionKey, RecipientEnvelopeContext, SubstrateAccountId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkKeyringConfig {
    pub keyring_name: &'static str,
    pub commitment_policy: &'static str,
}

impl Default for AwsEsdkKeyringConfig {
    fn default() -> Self {
        Self {
            keyring_name: "aws-esdk-trustless-recipient-keyring",
            commitment_policy: "require-encrypt-require-decrypt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkRecipientEnvelopeDescriptor {
    pub account: SubstrateAccountId,
    pub public_key: String,
    pub key_type: String,
    pub key_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkRecipientEnvelopePlan {
    pub bucket_id: String,
    pub object_key_id: String,
    pub policy_version: u32,
    pub recipients: Vec<AwsEsdkRecipientEnvelopeDescriptor>,
    pub uses_official_aws_encryption_sdk: bool,
    pub manual_algorithm_selection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkEncryptionContext {
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkEncryptInput {
    pub keyring_name: &'static str,
    pub commitment_policy: &'static str,
    pub encryption_context: AwsEsdkEncryptionContext,
    pub envelope_plan: AwsEsdkRecipientEnvelopePlan,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkDecryptInput {
    pub keyring_name: &'static str,
    pub commitment_policy: &'static str,
    pub encryption_context: AwsEsdkEncryptionContext,
    pub envelope_plan: AwsEsdkRecipientEnvelopePlan,
    pub ciphertext: Vec<u8>,
}

pub trait AwsEsdkByteCryptoAdapter {
    fn encrypt(&self, input: AwsEsdkEncryptInput) -> Result<Vec<u8>, KeyringError>;

    fn decrypt(&self, input: AwsEsdkDecryptInput) -> Result<Vec<u8>, KeyringError>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AwsEsdkRawRsaPaddingScheme {
    #[default]
    OaepSha256Mgf1,
}

impl AwsEsdkRawRsaPaddingScheme {
    fn to_aws_padding_scheme(self) -> aws_esdk::material_providers::types::PaddingScheme {
        match self {
            Self::OaepSha256Mgf1 => {
                aws_esdk::material_providers::types::PaddingScheme::OaepSha256Mgf1
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AwsEsdkRawRsaByteCryptoAdapterConfig {
    pub key_namespace: String,
    pub local_key_name: Option<String>,
    pub local_private_key_pem: Option<Vec<u8>>,
    pub padding_scheme: AwsEsdkRawRsaPaddingScheme,
}

impl fmt::Debug for AwsEsdkRawRsaByteCryptoAdapterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsEsdkRawRsaByteCryptoAdapterConfig")
            .field("key_namespace", &self.key_namespace)
            .field("local_key_name", &self.local_key_name)
            .field(
                "local_private_key_pem",
                &self
                    .local_private_key_pem
                    .as_ref()
                    .map(|value| format!("<redacted:{} bytes>", value.len())),
            )
            .field("padding_scheme", &self.padding_scheme)
            .finish()
    }
}

impl Default for AwsEsdkRawRsaByteCryptoAdapterConfig {
    fn default() -> Self {
        Self {
            key_namespace: "swarm-s3-trustless-recipient".to_owned(),
            local_key_name: None,
            local_private_key_pem: None,
            padding_scheme: AwsEsdkRawRsaPaddingScheme::OaepSha256Mgf1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealAwsEsdkRawRsaByteCryptoAdapter {
    config: AwsEsdkRawRsaByteCryptoAdapterConfig,
}

impl RealAwsEsdkRawRsaByteCryptoAdapter {
    pub fn new(config: AwsEsdkRawRsaByteCryptoAdapterConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &AwsEsdkRawRsaByteCryptoAdapterConfig {
        &self.config
    }
}

impl Default for RealAwsEsdkRawRsaByteCryptoAdapter {
    fn default() -> Self {
        Self::new(AwsEsdkRawRsaByteCryptoAdapterConfig::default())
    }
}

impl AwsEsdkByteCryptoAdapter for RealAwsEsdkRawRsaByteCryptoAdapter {
    fn encrypt(&self, input: AwsEsdkEncryptInput) -> Result<Vec<u8>, KeyringError> {
        run_aws_esdk_blocking(encrypt_with_raw_rsa_keyrings(self.config.clone(), input))
    }

    fn decrypt(&self, input: AwsEsdkDecryptInput) -> Result<Vec<u8>, KeyringError> {
        run_aws_esdk_blocking(decrypt_with_raw_rsa_keyring(self.config.clone(), input))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnwiredAwsEsdkByteCryptoAdapter;

impl AwsEsdkByteCryptoAdapter for UnwiredAwsEsdkByteCryptoAdapter {
    fn encrypt(&self, _input: AwsEsdkEncryptInput) -> Result<Vec<u8>, KeyringError> {
        Err(KeyringError::AwsEsdkAdapterNotWired)
    }

    fn decrypt(&self, _input: AwsEsdkDecryptInput) -> Result<Vec<u8>, KeyringError> {
        Err(KeyringError::AwsEsdkAdapterNotWired)
    }
}

#[derive(Debug, Clone)]
pub struct AwsEsdkTrustlessRecipientKeyring<A = UnwiredAwsEsdkByteCryptoAdapter> {
    config: AwsEsdkKeyringConfig,
    adapter: A,
}

impl Default for AwsEsdkTrustlessRecipientKeyring<UnwiredAwsEsdkByteCryptoAdapter> {
    fn default() -> Self {
        Self::new(AwsEsdkKeyringConfig::default())
    }
}

impl AwsEsdkTrustlessRecipientKeyring<UnwiredAwsEsdkByteCryptoAdapter> {
    pub fn new(config: AwsEsdkKeyringConfig) -> Self {
        Self {
            config,
            adapter: UnwiredAwsEsdkByteCryptoAdapter,
        }
    }
}

impl<A> AwsEsdkTrustlessRecipientKeyring<A> {
    pub fn with_adapter(config: AwsEsdkKeyringConfig, adapter: A) -> Self {
        Self { config, adapter }
    }

    pub fn recipient_envelope_plan(
        &self,
        context: &RecipientEnvelopeContext,
    ) -> Result<AwsEsdkRecipientEnvelopePlan, KeyringError> {
        let bucket_id = require_non_empty(&context.bucket_id, KeyringError::MissingBucketId)?;
        let object_key_id =
            require_non_empty(&context.object_key_id, KeyringError::MissingObjectKeyId)?;

        if context.recipients.is_empty() {
            return Err(KeyringError::MissingRecipientEnvelopes);
        }

        let mut recipients = Vec::with_capacity(context.recipients.len());

        for recipient in &context.recipients {
            recipients.push(validate_recipient(recipient)?);
        }

        Ok(AwsEsdkRecipientEnvelopePlan {
            bucket_id,
            object_key_id,
            policy_version: context.policy_version,
            recipients,
            uses_official_aws_encryption_sdk: true,
            manual_algorithm_selection: false,
        })
    }

    pub fn commitment_policy(&self) -> &'static str {
        self.config.commitment_policy
    }
}

impl<A> TrustlessRecipientKeyring for AwsEsdkTrustlessRecipientKeyring<A>
where
    A: AwsEsdkByteCryptoAdapter,
{
    fn keyring_name(&self) -> &'static str {
        self.config.keyring_name
    }

    fn encrypt_with_recipient_envelopes(
        &self,
        plaintext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError> {
        if plaintext.is_empty() {
            return Err(KeyringError::MissingPlaintextPayload);
        }

        let envelope_plan = self.recipient_envelope_plan(context)?;
        let encryption_context = aws_esdk_encryption_context(context)?;

        self.adapter.encrypt(AwsEsdkEncryptInput {
            keyring_name: self.keyring_name(),
            commitment_policy: self.commitment_policy(),
            encryption_context,
            envelope_plan,
            plaintext: plaintext.to_vec(),
        })
    }

    fn decrypt_with_local_recipient_key(
        &self,
        ciphertext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError> {
        if ciphertext.is_empty() {
            return Err(KeyringError::MissingCiphertextPayload);
        }

        let envelope_plan = self.recipient_envelope_plan(context)?;
        let encryption_context = aws_esdk_encryption_context(context)?;

        self.adapter.decrypt(AwsEsdkDecryptInput {
            keyring_name: self.keyring_name(),
            commitment_policy: self.commitment_policy(),
            encryption_context,
            envelope_plan,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

fn run_aws_esdk_blocking<F, T>(future: F) -> Result<T, KeyringError>
where
    F: Future<Output = Result<T, KeyringError>> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                KeyringError::AwsEsdkSdkError(format!(
                    "failed to build local AWS ESDK runtime: {error}"
                ))
            })?;

        runtime.block_on(future)
    })
    .join()
    .map_err(|_| {
        KeyringError::AwsEsdkSdkError(
            "AWS ESDK runtime worker panicked during crypto operation".to_owned(),
        )
    })?
}

async fn encrypt_with_raw_rsa_keyrings(
    config: AwsEsdkRawRsaByteCryptoAdapterConfig,
    input: AwsEsdkEncryptInput,
) -> Result<Vec<u8>, KeyringError> {
    let key_namespace = validated_key_namespace(&config)?;

    let esdk_config = aws_esdk::types::aws_encryption_sdk_config::AwsEncryptionSdkConfig::builder()
        .build()
        .map_err(aws_esdk_error)?;

    let esdk_client = aws_esdk::client::Client::from_conf(esdk_config).map_err(aws_esdk_error)?;

    let mpl_config = aws_esdk::material_providers::types::material_providers_config::MaterialProvidersConfig::builder()
        .build()
        .map_err(aws_esdk_error)?;

    let mpl = aws_esdk::material_providers::client::Client::from_conf(mpl_config)
        .map_err(aws_esdk_error)?;

    let keyring = build_raw_rsa_encrypt_keyring(&mpl, &config, &key_namespace, &input).await?;
    let expected_context = input.encryption_context.entries.clone();

    let response = esdk_client
        .encrypt()
        .plaintext(input.plaintext)
        .keyring(keyring)
        .encryption_context(
            expected_context
                .clone()
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        )
        .send()
        .await
        .map_err(aws_esdk_error)?;

    ensure_returned_context_contains_expected(response.encryption_context, &expected_context)?;

    let ciphertext = response
        .ciphertext
        .ok_or(KeyringError::AwsEsdkMissingCiphertextOutput)?;

    Ok(ciphertext.into_inner())
}

async fn decrypt_with_raw_rsa_keyring(
    config: AwsEsdkRawRsaByteCryptoAdapterConfig,
    input: AwsEsdkDecryptInput,
) -> Result<Vec<u8>, KeyringError> {
    let key_namespace = validated_key_namespace(&config)?;
    let local_key_name = config
        .local_key_name
        .as_ref()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(KeyringError::AwsEsdkMissingLocalKeyName)?;

    let private_key = config
        .local_private_key_pem
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or(KeyringError::AwsEsdkMissingPrivateKeyPem)?;

    let esdk_config = aws_esdk::types::aws_encryption_sdk_config::AwsEncryptionSdkConfig::builder()
        .build()
        .map_err(aws_esdk_error)?;

    let esdk_client = aws_esdk::client::Client::from_conf(esdk_config).map_err(aws_esdk_error)?;

    let mpl_config = aws_esdk::material_providers::types::material_providers_config::MaterialProvidersConfig::builder()
        .build()
        .map_err(aws_esdk_error)?;

    let mpl = aws_esdk::material_providers::client::Client::from_conf(mpl_config)
        .map_err(aws_esdk_error)?;

    let keyring = mpl
        .create_raw_rsa_keyring()
        .key_namespace(key_namespace)
        .key_name(local_key_name)
        .padding_scheme(config.padding_scheme.to_aws_padding_scheme())
        .private_key(private_key)
        .send()
        .await
        .map_err(aws_esdk_error)?;

    let expected_context = input.encryption_context.entries.clone();

    let response = esdk_client
        .decrypt()
        .ciphertext(input.ciphertext)
        .keyring(keyring)
        .encryption_context(
            expected_context
                .clone()
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        )
        .send()
        .await
        .map_err(aws_esdk_error)?;

    ensure_returned_context_contains_expected(response.encryption_context, &expected_context)?;

    let plaintext = response
        .plaintext
        .ok_or(KeyringError::AwsEsdkMissingPlaintextOutput)?;

    Ok(plaintext.into_inner())
}

async fn build_raw_rsa_encrypt_keyring(
    mpl: &aws_esdk::material_providers::client::Client,
    config: &AwsEsdkRawRsaByteCryptoAdapterConfig,
    key_namespace: &str,
    input: &AwsEsdkEncryptInput,
) -> Result<aws_esdk::material_providers::types::keyring::KeyringRef, KeyringError> {
    if input.envelope_plan.recipients.is_empty() {
        return Err(KeyringError::MissingRecipientEnvelopes);
    }

    let mut keyrings = Vec::with_capacity(input.envelope_plan.recipients.len());

    for recipient in &input.envelope_plan.recipients {
        let public_key = recipient.public_key.trim().as_bytes().to_vec();

        let keyring = mpl
            .create_raw_rsa_keyring()
            .key_namespace(key_namespace.to_owned())
            .key_name(raw_rsa_recipient_key_name(recipient))
            .padding_scheme(config.padding_scheme.to_aws_padding_scheme())
            .public_key(public_key)
            .send()
            .await
            .map_err(aws_esdk_error)?;

        keyrings.push(keyring);
    }

    if keyrings.len() == 1 {
        return Ok(keyrings.remove(0));
    }

    let generator = keyrings.remove(0);

    mpl.create_multi_keyring()
        .generator(generator)
        .child_keyrings(keyrings)
        .send()
        .await
        .map_err(aws_esdk_error)
}

fn validated_key_namespace(
    config: &AwsEsdkRawRsaByteCryptoAdapterConfig,
) -> Result<String, KeyringError> {
    config
        .key_namespace
        .trim()
        .to_owned()
        .split_once('\0')
        .map(|_| String::new())
        .unwrap_or_else(|| config.key_namespace.trim().to_owned())
        .is_empty()
        .then_some(())
        .map_or_else(
            || Ok(config.key_namespace.trim().to_owned()),
            |_| Err(KeyringError::AwsEsdkMissingKeyNamespace),
        )
}

fn raw_rsa_recipient_key_name(recipient: &AwsEsdkRecipientEnvelopeDescriptor) -> String {
    format!(
        "{}:{}:{}",
        recipient.account, recipient.key_type, recipient.key_version
    )
}

fn ensure_returned_context_contains_expected(
    returned_context: Option<std::collections::HashMap<String, String>>,
    expected_context: &BTreeMap<String, String>,
) -> Result<(), KeyringError> {
    let Some(returned_context) = returned_context else {
        return Err(KeyringError::AwsEsdkSdkError(
            "AWS ESDK response did not return an encryption context".to_owned(),
        ));
    };

    for (key, expected_value) in expected_context {
        if returned_context.get(key) != Some(expected_value) {
            return Err(KeyringError::AwsEsdkSdkError(format!(
                "AWS ESDK response encryption context mismatch for {key}"
            )));
        }
    }

    Ok(())
}

fn aws_esdk_error(error: impl fmt::Debug) -> KeyringError {
    KeyringError::AwsEsdkSdkError(format!("{error:?}"))
}

fn aws_esdk_encryption_context(
    context: &RecipientEnvelopeContext,
) -> Result<AwsEsdkEncryptionContext, KeyringError> {
    let bucket_id = require_non_empty(&context.bucket_id, KeyringError::MissingBucketId)?;
    let object_key_id =
        require_non_empty(&context.object_key_id, KeyringError::MissingObjectKeyId)?;

    let mut entries = BTreeMap::new();
    entries.insert("trustless.domain".to_owned(), "object".to_owned());
    entries.insert("trustless.bucket_id".to_owned(), bucket_id);
    entries.insert("trustless.object_key_id".to_owned(), object_key_id);
    entries.insert(
        "trustless.policy_version".to_owned(),
        context.policy_version.to_string(),
    );

    Ok(AwsEsdkEncryptionContext { entries })
}

fn validate_recipient(
    recipient: &RecipientEncryptionKey,
) -> Result<AwsEsdkRecipientEnvelopeDescriptor, KeyringError> {
    if !recipient.enabled {
        return Err(KeyringError::DisabledRecipientEnvelope(
            recipient.account.clone(),
        ));
    }

    let public_key = require_non_empty(
        &recipient.public_key,
        KeyringError::EmptyRecipientPublicKey(recipient.account.clone()),
    )?;

    let key_type = require_non_empty(
        &recipient.key_type,
        KeyringError::EmptyRecipientKeyType(recipient.account.clone()),
    )?;

    Ok(AwsEsdkRecipientEnvelopeDescriptor {
        account: recipient.account.clone(),
        public_key,
        key_type,
        key_version: recipient.key_version,
    })
}

fn require_non_empty(value: &str, error: KeyringError) -> Result<String, KeyringError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(account: &str) -> RecipientEncryptionKey {
        RecipientEncryptionKey {
            account: account.to_owned(),
            public_key: format!("{account}-public-key"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 7,
            recipients: vec![recipient("alice"), recipient("bob")],
        }
    }

    #[test]
    fn aws_esdk_keyring_builds_recipient_envelope_plan_from_context() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        let plan = keyring.recipient_envelope_plan(&context()).unwrap();

        assert_eq!(
            keyring.keyring_name(),
            "aws-esdk-trustless-recipient-keyring"
        );
        assert_eq!(
            keyring.commitment_policy(),
            "require-encrypt-require-decrypt"
        );
        assert_eq!(plan.policy_version, 7);
        assert_eq!(plan.recipients.len(), 2);
        assert!(plan.uses_official_aws_encryption_sdk);
        assert!(!plan.manual_algorithm_selection);
    }

    #[test]
    fn aws_esdk_keyring_rejects_empty_context_fields() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    bucket_id: " ".to_owned(),
                    ..context()
                })
                .unwrap_err(),
            KeyringError::MissingBucketId
        );

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    object_key_id: " ".to_owned(),
                    ..context()
                })
                .unwrap_err(),
            KeyringError::MissingObjectKeyId
        );
    }

    #[test]
    fn aws_esdk_keyring_rejects_missing_or_disabled_recipients() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: Vec::new(),
                    ..context()
                })
                .unwrap_err(),
            KeyringError::MissingRecipientEnvelopes
        );

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: vec![RecipientEncryptionKey {
                        enabled: false,
                        ..recipient("bob")
                    }],
                    ..context()
                })
                .unwrap_err(),
            KeyringError::DisabledRecipientEnvelope("bob".to_owned())
        );
    }

    #[test]
    fn aws_esdk_keyring_rejects_malformed_recipient_records() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: vec![RecipientEncryptionKey {
                        public_key: " ".to_owned(),
                        ..recipient("alice")
                    }],
                    ..context()
                })
                .unwrap_err(),
            KeyringError::EmptyRecipientPublicKey("alice".to_owned())
        );

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: vec![RecipientEncryptionKey {
                        key_type: " ".to_owned(),
                        ..recipient("alice")
                    }],
                    ..context()
                })
                .unwrap_err(),
            KeyringError::EmptyRecipientKeyType("alice".to_owned())
        );
    }

    #[test]
    fn aws_esdk_keyring_fails_closed_until_sdk_wiring_exists() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring.encrypt_with_recipient_envelopes(b"plaintext", &context()),
            Err(KeyringError::AwsEsdkAdapterNotWired)
        );

        assert_eq!(
            keyring.decrypt_with_local_recipient_key(b"ciphertext", &context()),
            Err(KeyringError::AwsEsdkAdapterNotWired)
        );
    }

    #[test]
    fn aws_esdk_keyring_rejects_empty_payloads_before_sdk_wiring() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring.encrypt_with_recipient_envelopes(b"", &context()),
            Err(KeyringError::MissingPlaintextPayload)
        );

        assert_eq!(
            keyring.decrypt_with_local_recipient_key(b"", &context()),
            Err(KeyringError::MissingCiphertextPayload)
        );
    }

    #[derive(Debug, Clone, Default)]
    struct MockAwsEsdkAdapter {
        encrypt_input: std::rc::Rc<std::cell::RefCell<Option<AwsEsdkEncryptInput>>>,
        decrypt_input: std::rc::Rc<std::cell::RefCell<Option<AwsEsdkDecryptInput>>>,
    }

    impl AwsEsdkByteCryptoAdapter for MockAwsEsdkAdapter {
        fn encrypt(&self, input: AwsEsdkEncryptInput) -> Result<Vec<u8>, KeyringError> {
            *self.encrypt_input.borrow_mut() = Some(input);
            Ok(b"aws-esdk-ciphertext".to_vec())
        }

        fn decrypt(&self, input: AwsEsdkDecryptInput) -> Result<Vec<u8>, KeyringError> {
            *self.decrypt_input.borrow_mut() = Some(input);
            Ok(b"aws-esdk-plaintext".to_vec())
        }
    }

    #[test]
    fn aws_esdk_keyring_delegates_encrypt_to_adapter_with_bound_context() {
        let adapter = MockAwsEsdkAdapter::default();
        let seen_encrypt = adapter.encrypt_input.clone();
        let keyring = AwsEsdkTrustlessRecipientKeyring::with_adapter(
            AwsEsdkKeyringConfig::default(),
            adapter,
        );

        let ciphertext = keyring
            .encrypt_with_recipient_envelopes(b"plaintext", &context())
            .unwrap();

        assert_eq!(ciphertext, b"aws-esdk-ciphertext".to_vec());

        let input = seen_encrypt.borrow().clone().unwrap();
        assert_eq!(input.keyring_name, "aws-esdk-trustless-recipient-keyring");
        assert_eq!(input.commitment_policy, "require-encrypt-require-decrypt");
        assert_eq!(input.plaintext, b"plaintext".to_vec());
        assert_eq!(input.envelope_plan.recipients.len(), 2);
        assert_eq!(
            input.encryption_context.entries.get("trustless.domain"),
            Some(&"object".to_owned())
        );
        assert_eq!(
            input.encryption_context.entries.get("trustless.bucket_id"),
            Some(&hex::encode([1u8; 32]))
        );
        assert_eq!(
            input
                .encryption_context
                .entries
                .get("trustless.object_key_id"),
            Some(&hex::encode([2u8; 32]))
        );
        assert_eq!(
            input
                .encryption_context
                .entries
                .get("trustless.policy_version"),
            Some(&"7".to_owned())
        );
    }

    #[test]
    fn aws_esdk_keyring_delegates_decrypt_to_adapter_with_bound_context() {
        let adapter = MockAwsEsdkAdapter::default();
        let seen_decrypt = adapter.decrypt_input.clone();
        let keyring = AwsEsdkTrustlessRecipientKeyring::with_adapter(
            AwsEsdkKeyringConfig::default(),
            adapter,
        );

        let plaintext = keyring
            .decrypt_with_local_recipient_key(b"ciphertext", &context())
            .unwrap();

        assert_eq!(plaintext, b"aws-esdk-plaintext".to_vec());

        let input = seen_decrypt.borrow().clone().unwrap();
        assert_eq!(input.keyring_name, "aws-esdk-trustless-recipient-keyring");
        assert_eq!(input.commitment_policy, "require-encrypt-require-decrypt");
        assert_eq!(input.ciphertext, b"ciphertext".to_vec());
        assert_eq!(input.envelope_plan.recipients.len(), 2);
        assert_eq!(
            input.encryption_context.entries.get("trustless.domain"),
            Some(&"object".to_owned())
        );
        assert_eq!(
            input.encryption_context.entries.get("trustless.bucket_id"),
            Some(&hex::encode([1u8; 32]))
        );
        assert_eq!(
            input
                .encryption_context
                .entries
                .get("trustless.object_key_id"),
            Some(&hex::encode([2u8; 32]))
        );
    }

    fn real_encrypt_input() -> AwsEsdkEncryptInput {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();
        let context = context();

        AwsEsdkEncryptInput {
            keyring_name: keyring.keyring_name(),
            commitment_policy: keyring.commitment_policy(),
            encryption_context: aws_esdk_encryption_context(&context).unwrap(),
            envelope_plan: keyring.recipient_envelope_plan(&context).unwrap(),
            plaintext: b"plaintext".to_vec(),
        }
    }

    fn real_decrypt_input() -> AwsEsdkDecryptInput {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();
        let context = context();

        AwsEsdkDecryptInput {
            keyring_name: keyring.keyring_name(),
            commitment_policy: keyring.commitment_policy(),
            encryption_context: aws_esdk_encryption_context(&context).unwrap(),
            envelope_plan: keyring.recipient_envelope_plan(&context).unwrap(),
            ciphertext: b"ciphertext".to_vec(),
        }
    }

    #[test]
    fn real_aws_esdk_raw_rsa_adapter_derives_stable_recipient_key_names() {
        let plan = real_encrypt_input().envelope_plan;

        assert_eq!(
            raw_rsa_recipient_key_name(&plan.recipients[0]),
            "alice:aws-esdk-rust-recipient-key:1"
        );
        assert_eq!(
            raw_rsa_recipient_key_name(&plan.recipients[1]),
            "bob:aws-esdk-rust-recipient-key:1"
        );
    }

    #[test]
    fn real_aws_esdk_raw_rsa_adapter_rejects_missing_key_namespace_before_sdk_call() {
        let adapter =
            RealAwsEsdkRawRsaByteCryptoAdapter::new(AwsEsdkRawRsaByteCryptoAdapterConfig {
                key_namespace: " ".to_owned(),
                ..AwsEsdkRawRsaByteCryptoAdapterConfig::default()
            });

        assert_eq!(
            adapter.encrypt(real_encrypt_input()).unwrap_err(),
            KeyringError::AwsEsdkMissingKeyNamespace
        );
    }

    #[test]
    fn real_aws_esdk_raw_rsa_adapter_rejects_missing_decrypt_private_key_before_sdk_call() {
        let adapter =
            RealAwsEsdkRawRsaByteCryptoAdapter::new(AwsEsdkRawRsaByteCryptoAdapterConfig {
                local_key_name: Some("alice:aws-esdk-rust-recipient-key:1".to_owned()),
                local_private_key_pem: None,
                ..AwsEsdkRawRsaByteCryptoAdapterConfig::default()
            });

        assert_eq!(
            adapter.decrypt(real_decrypt_input()).unwrap_err(),
            KeyringError::AwsEsdkMissingPrivateKeyPem
        );
    }

    #[test]
    fn real_aws_esdk_raw_rsa_adapter_rejects_missing_decrypt_local_key_name_before_sdk_call() {
        let adapter =
            RealAwsEsdkRawRsaByteCryptoAdapter::new(AwsEsdkRawRsaByteCryptoAdapterConfig {
                local_key_name: None,
                local_private_key_pem: Some(b"not-a-real-private-key".to_vec()),
                ..AwsEsdkRawRsaByteCryptoAdapterConfig::default()
            });

        assert_eq!(
            adapter.decrypt(real_decrypt_input()).unwrap_err(),
            KeyringError::AwsEsdkMissingLocalKeyName
        );
    }
}
