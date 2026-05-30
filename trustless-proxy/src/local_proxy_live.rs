use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use thiserror::Error;

use crate::execution_engine::{LocalTrustlessExecutionEngine, LocalTrustlessExecutionInput};
use crate::http_mapping::{
    LocalTrustlessHttpMethod, LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext,
    LocalTrustlessHttpResponse,
};
use crate::local_keystore::LocalKeystoreResolver;
use crate::manifest::{TrustlessManifestCipher, TrustlessManifestEntry};
use crate::recipient_keys::RecipientKeyResolver;
use crate::remote_gateway::TrustlessRemoteGatewayClient;
use crate::types::{RecipientEncryptionKey, RecipientEnvelopeContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessLiveBindConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub max_request_body_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessLiveServeResult {
    pub response: LocalTrustlessHttpResponse,
    pub network_bind_performed: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessLiveExecutionMetadata {
    pub http_context: LocalTrustlessHttpRequestContext,
    pub manifest_entry: TrustlessManifestEntry,
    pub envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessLiveBindError {
    #[error("local proxy live bind listen host is required")]
    MissingListenHost,

    #[error("local proxy live bind listen port must be greater than zero")]
    InvalidListenPort,

    #[error("local proxy live bind request body limit must be greater than zero")]
    InvalidRequestBodyLimit,

    #[error("local proxy live bind must use localhost only: {0}")]
    NonLocalBindHostRejected(String),

    #[error("malformed HTTP request")]
    MalformedHttpRequest,

    #[error("unsupported HTTP method for live local proxy: {0}")]
    UnsupportedHttpMethod(String),

    #[error("missing required live local proxy header: {0}")]
    MissingHeader(&'static str),

    #[error("invalid live local proxy header {header}: {reason}")]
    InvalidHeader {
        header: &'static str,
        reason: String,
    },

    #[error("request body exceeds local proxy live bind limit")]
    RequestBodyTooLarge,

    #[error("plaintext body is only allowed for local PUT object requests")]
    UnexpectedPlaintextBody,

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("local trustless execution engine failed: {0}")]
    Execution(String),

    #[error("local proxy live bind I/O failed: {0}")]
    Io(String),
}

pub trait LocalTrustlessLiveRequestExecutor {
    fn execute_live_http_request(
        &self,
        input: LocalTrustlessExecutionInput,
    ) -> Result<LocalTrustlessHttpResponse, LocalTrustlessLiveBindError>;
}

impl<C, RK, LK, G> LocalTrustlessLiveRequestExecutor for LocalTrustlessExecutionEngine<C, RK, LK, G>
where
    C: TrustlessManifestCipher + Clone,
    RK: RecipientKeyResolver,
    LK: LocalKeystoreResolver,
    G: TrustlessRemoteGatewayClient,
{
    fn execute_live_http_request(
        &self,
        input: LocalTrustlessExecutionInput,
    ) -> Result<LocalTrustlessHttpResponse, LocalTrustlessLiveBindError> {
        self.execute_http_request(input)
            .map_err(|error| LocalTrustlessLiveBindError::Execution(error.to_string()))
    }
}

pub trait LocalTrustlessLiveContextBuilder {
    fn build_execution_metadata(
        &self,
        request: &LocalTrustlessHttpRequest,
        headers: &BTreeMap<String, String>,
    ) -> Result<LocalTrustlessLiveExecutionMetadata, LocalTrustlessLiveBindError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalTrustlessHeaderContextBuilder;

impl LocalTrustlessLiveContextBuilder for LocalTrustlessHeaderContextBuilder {
    fn build_execution_metadata(
        &self,
        request: &LocalTrustlessHttpRequest,
        headers: &BTreeMap<String, String>,
    ) -> Result<LocalTrustlessLiveExecutionMetadata, LocalTrustlessLiveBindError> {
        let bucket_id = required_header(headers, "x-s3w-bucket-id")?;
        let object_key_id = required_header(headers, "x-s3w-object-key-id")?;
        let policy_version = parse_u32_header(headers, "x-s3w-policy-version")?;
        let local_account = required_header(headers, "x-s3w-local-account")?;
        let local_key_type = required_header(headers, "x-s3w-local-key-type")?;
        let recipients = parse_recipients(headers)?;

        let http_context = LocalTrustlessHttpRequestContext {
            bucket_id: bucket_id.clone(),
            object_key_id: Some(object_key_id.clone()),
            policy_version,
            local_account,
            local_key_type,
            recipients,
        };

        let manifest_entry = TrustlessManifestEntry {
            object_key: object_key_from_path(&request.path)?,
            object_key_id: object_key_id.clone(),
            ciphertext_ref: required_header(headers, "x-s3w-manifest-ciphertext-ref")?,
            ciphertext_size: parse_u64_header(headers, "x-s3w-manifest-ciphertext-size")?,
            content_type: optional_header(headers, "x-s3w-manifest-content-type"),
            etag: optional_header(headers, "x-s3w-manifest-etag"),
        };

        let envelope_context = RecipientEnvelopeContext {
            bucket_id,
            object_key_id,
            policy_version,
            recipients: parse_recipient_keys(headers)?,
        };

        Ok(LocalTrustlessLiveExecutionMetadata {
            http_context,
            manifest_entry,
            envelope_context,
        })
    }
}

pub struct LocalTrustlessLiveHttpServer;

impl LocalTrustlessLiveHttpServer {
    pub fn bind(
        config: LocalTrustlessLiveBindConfig,
    ) -> Result<TcpListener, LocalTrustlessLiveBindError> {
        validate_live_bind_config(&config)?;

        TcpListener::bind(format!("{}:{}", config.listen_host, config.listen_port))
            .map_err(io_error)
    }

    pub fn serve_one<E, B>(
        listener: TcpListener,
        executor: E,
        context_builder: B,
        max_request_body_bytes: u64,
    ) -> Result<LocalTrustlessLiveServeResult, LocalTrustlessLiveBindError>
    where
        E: LocalTrustlessLiveRequestExecutor,
        B: LocalTrustlessLiveContextBuilder,
    {
        if max_request_body_bytes == 0 {
            return Err(LocalTrustlessLiveBindError::InvalidRequestBodyLimit);
        }

        let (mut stream, _) = listener.accept().map_err(io_error)?;

        let result = handle_stream(
            &mut stream,
            &executor,
            &context_builder,
            max_request_body_bytes,
        );

        match result {
            Ok(response) => {
                write_http_response(&mut stream, &response)?;

                Ok(LocalTrustlessLiveServeResult {
                    response,
                    network_bind_performed: true,
                    gateway_plaintext_access: false,
                })
            }
            Err(error) => {
                let status = error_status_code(&error);
                let body = error.to_string().into_bytes();
                let _ = write_raw_http_response(
                    &mut stream,
                    status,
                    vec![(
                        "x-s3w-gateway-plaintext-access".to_owned(),
                        "false".to_owned(),
                    )],
                    &body,
                );

                Err(error)
            }
        }
    }
}

fn handle_stream<E, B>(
    stream: &mut TcpStream,
    executor: &E,
    context_builder: &B,
    max_request_body_bytes: u64,
) -> Result<LocalTrustlessHttpResponse, LocalTrustlessLiveBindError>
where
    E: LocalTrustlessLiveRequestExecutor,
    B: LocalTrustlessLiveContextBuilder,
{
    let parsed = read_http_request(stream, max_request_body_bytes)?;

    if parsed.request.method != LocalTrustlessHttpMethod::Put && parsed.request.body.is_some() {
        return Err(LocalTrustlessLiveBindError::UnexpectedPlaintextBody);
    }

    let metadata = context_builder.build_execution_metadata(&parsed.request, &parsed.headers)?;

    let response = executor.execute_live_http_request(LocalTrustlessExecutionInput {
        http_request: parsed.request,
        http_context: metadata.http_context,
        manifest_entry: metadata.manifest_entry,
        envelope_context: metadata.envelope_context,
    })?;

    if response.gateway_plaintext_access {
        return Err(LocalTrustlessLiveBindError::GatewayPlaintextAccessRejected);
    }

    Ok(response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedLiveHttpRequest {
    request: LocalTrustlessHttpRequest,
    headers: BTreeMap<String, String>,
}

fn read_http_request(
    stream: &mut TcpStream,
    max_request_body_bytes: u64,
) -> Result<ParsedLiveHttpRequest, LocalTrustlessLiveBindError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(io_error)?;

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    let header_end = loop {
        let read = stream.read(&mut chunk).map_err(io_error)?;

        if read == 0 {
            return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
        }

        buffer.extend_from_slice(&chunk[..read]);

        if let Some(index) = find_header_end(&buffer) {
            break index;
        }

        if buffer.len() as u64 > max_request_body_bytes + 16 * 1024 {
            return Err(LocalTrustlessLiveBindError::RequestBodyTooLarge);
        }
    };

    let header_bytes = &buffer[..header_end];
    let body_start = header_end + 4;

    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| LocalTrustlessLiveBindError::MalformedHttpRequest)?;

    let (request_line, headers) = parse_header_block(header_text)?;
    let content_length = headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| LocalTrustlessLiveBindError::InvalidHeader {
                    header: "content-length",
                    reason: "must be an integer".to_owned(),
                })
        })
        .transpose()?
        .unwrap_or(0);

    if content_length as u64 > max_request_body_bytes {
        return Err(LocalTrustlessLiveBindError::RequestBodyTooLarge);
    }

    let mut body = buffer[body_start..].to_vec();

    while body.len() < content_length {
        let read = stream.read(&mut chunk).map_err(io_error)?;

        if read == 0 {
            return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
        }

        body.extend_from_slice(&chunk[..read]);

        if body.len() as u64 > max_request_body_bytes {
            return Err(LocalTrustlessLiveBindError::RequestBodyTooLarge);
        }
    }

    body.truncate(content_length);

    let (method, path, query) = parse_request_line(request_line)?;

    Ok(ParsedLiveHttpRequest {
        request: LocalTrustlessHttpRequest {
            method,
            path,
            query,
            body: if body.is_empty() { None } else { Some(body) },
        },
        headers,
    })
}

fn parse_header_block(
    header_text: &str,
) -> Result<(&str, BTreeMap<String, String>), LocalTrustlessLiveBindError> {
    let mut lines = header_text.split("\r\n");

    let request_line = lines
        .next()
        .ok_or(LocalTrustlessLiveBindError::MalformedHttpRequest)?;

    let mut headers = BTreeMap::new();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
        };

        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();

        if name.is_empty() {
            return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
        }

        headers.insert(name, value);
    }

    Ok((request_line, headers))
}

fn parse_request_line(
    request_line: &str,
) -> Result<(LocalTrustlessHttpMethod, String, Option<String>), LocalTrustlessLiveBindError> {
    let mut parts = request_line.split_whitespace();

    let method = parts
        .next()
        .ok_or(LocalTrustlessLiveBindError::MalformedHttpRequest)?;
    let target = parts
        .next()
        .ok_or(LocalTrustlessLiveBindError::MalformedHttpRequest)?;

    let method = match method {
        "PUT" => LocalTrustlessHttpMethod::Put,
        "GET" => LocalTrustlessHttpMethod::Get,
        "HEAD" => LocalTrustlessHttpMethod::Head,
        "DELETE" => LocalTrustlessHttpMethod::Delete,
        "POST" => LocalTrustlessHttpMethod::Post,
        other => {
            return Err(LocalTrustlessLiveBindError::UnsupportedHttpMethod(
                other.to_owned(),
            ));
        }
    };

    let (path, query) = if let Some((path, query)) = target.split_once('?') {
        (path.to_owned(), Some(query.to_owned()))
    } else {
        (target.to_owned(), None)
    };

    if !path.starts_with('/') {
        return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
    }

    Ok((method, path, query))
}

fn write_http_response(
    stream: &mut TcpStream,
    response: &LocalTrustlessHttpResponse,
) -> Result<(), LocalTrustlessLiveBindError> {
    if response.gateway_plaintext_access {
        return Err(LocalTrustlessLiveBindError::GatewayPlaintextAccessRejected);
    }

    write_raw_http_response(
        stream,
        response.status_code,
        response.headers.clone(),
        response.body.as_deref().unwrap_or(&[]),
    )
}

fn write_raw_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    headers: Vec<(String, String)>,
    body: &[u8],
) -> Result<(), LocalTrustlessLiveBindError> {
    let mut response = Vec::new();

    response.extend_from_slice(
        format!(
            "HTTP/1.1 {} {}\r\n",
            status_code,
            status_reason(status_code)
        )
        .as_bytes(),
    );

    response.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    response.extend_from_slice(b"Connection: close\r\n");

    for (name, value) in headers {
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
        }

        response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(body);

    stream.write_all(&response).map_err(io_error)?;
    stream.flush().map_err(io_error)
}

fn status_reason(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn error_status_code(error: &LocalTrustlessLiveBindError) -> u16 {
    match error {
        LocalTrustlessLiveBindError::UnsupportedHttpMethod(_) => 405,
        LocalTrustlessLiveBindError::RequestBodyTooLarge => 413,
        LocalTrustlessLiveBindError::Execution(_) => 500,
        LocalTrustlessLiveBindError::Io(_) => 500,
        _ => 400,
    }
}

fn validate_live_bind_config(
    config: &LocalTrustlessLiveBindConfig,
) -> Result<(), LocalTrustlessLiveBindError> {
    let host = config.listen_host.trim();

    if host.is_empty() {
        return Err(LocalTrustlessLiveBindError::MissingListenHost);
    }

    if config.listen_port == 0 {
        return Err(LocalTrustlessLiveBindError::InvalidListenPort);
    }

    if config.max_request_body_bytes == 0 {
        return Err(LocalTrustlessLiveBindError::InvalidRequestBodyLimit);
    }

    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Err(LocalTrustlessLiveBindError::NonLocalBindHostRejected(
            host.to_owned(),
        ));
    }

    Ok(())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn required_header(
    headers: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, LocalTrustlessLiveBindError> {
    let Some(value) = headers.get(name) else {
        return Err(LocalTrustlessLiveBindError::MissingHeader(name));
    };

    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(LocalTrustlessLiveBindError::MissingHeader(name));
    }

    Ok(value)
}

fn optional_header(headers: &BTreeMap<String, String>, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_u32_header(
    headers: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<u32, LocalTrustlessLiveBindError> {
    required_header(headers, name)?.parse::<u32>().map_err(|_| {
        LocalTrustlessLiveBindError::InvalidHeader {
            header: name,
            reason: "must be a u32".to_owned(),
        }
    })
}

fn parse_u64_header(
    headers: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<u64, LocalTrustlessLiveBindError> {
    required_header(headers, name)?.parse::<u64>().map_err(|_| {
        LocalTrustlessLiveBindError::InvalidHeader {
            header: name,
            reason: "must be a u64".to_owned(),
        }
    })
}

fn parse_recipients(
    headers: &BTreeMap<String, String>,
) -> Result<Vec<String>, LocalTrustlessLiveBindError> {
    let recipients = required_header(headers, "x-s3w-recipients")?
        .split(',')
        .map(str::trim)
        .filter(|recipient| !recipient.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if recipients.is_empty() {
        return Err(LocalTrustlessLiveBindError::InvalidHeader {
            header: "x-s3w-recipients",
            reason: "at least one recipient is required".to_owned(),
        });
    }

    Ok(recipients)
}

fn parse_recipient_keys(
    headers: &BTreeMap<String, String>,
) -> Result<Vec<RecipientEncryptionKey>, LocalTrustlessLiveBindError> {
    let records = required_header(headers, "x-s3w-recipient-keys")?;
    let mut recipients = Vec::new();

    for record in records
        .split(';')
        .map(str::trim)
        .filter(|record| !record.is_empty())
    {
        let parts = record.split('|').collect::<Vec<_>>();

        if parts.len() != 5 {
            return Err(LocalTrustlessLiveBindError::InvalidHeader {
                header: "x-s3w-recipient-keys",
                reason: "expected account|key_type|key_version|enabled|public_key_hex".to_owned(),
            });
        }

        let key_version = parts[2].trim().parse::<u32>().map_err(|_| {
            LocalTrustlessLiveBindError::InvalidHeader {
                header: "x-s3w-recipient-keys",
                reason: "recipient key_version must be a u32".to_owned(),
            }
        })?;

        let enabled = match parts[3].trim() {
            "true" => true,
            "false" => false,
            _ => {
                return Err(LocalTrustlessLiveBindError::InvalidHeader {
                    header: "x-s3w-recipient-keys",
                    reason: "recipient enabled flag must be true or false".to_owned(),
                });
            }
        };

        let public_key_bytes = hex::decode(parts[4].trim()).map_err(|_| {
            LocalTrustlessLiveBindError::InvalidHeader {
                header: "x-s3w-recipient-keys",
                reason: "recipient public key must be hex encoded".to_owned(),
            }
        })?;

        let public_key = String::from_utf8(public_key_bytes).map_err(|_| {
            LocalTrustlessLiveBindError::InvalidHeader {
                header: "x-s3w-recipient-keys",
                reason: "recipient public key must decode to UTF-8".to_owned(),
            }
        })?;

        recipients.push(RecipientEncryptionKey {
            account: parts[0].trim().to_owned(),
            public_key,
            key_type: parts[1].trim().to_owned(),
            key_version,
            enabled,
        });
    }

    if recipients.is_empty() {
        return Err(LocalTrustlessLiveBindError::InvalidHeader {
            header: "x-s3w-recipient-keys",
            reason: "at least one recipient key is required".to_owned(),
        });
    }

    Ok(recipients)
}

fn object_key_from_path(path: &str) -> Result<String, LocalTrustlessLiveBindError> {
    let trimmed = path.trim_start_matches('/');
    let Some((_bucket, key)) = trimmed.split_once('/') else {
        return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
    };

    let key = key.trim();

    if key.is_empty() {
        return Err(LocalTrustlessLiveBindError::MalformedHttpRequest);
    }

    Ok(key.to_owned())
}

fn io_error(error: std::io::Error) -> LocalTrustlessLiveBindError {
    LocalTrustlessLiveBindError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Debug, Clone)]
    struct RecordingLiveExecutor {
        seen_input: Arc<Mutex<Option<LocalTrustlessExecutionInput>>>,
        response: LocalTrustlessHttpResponse,
    }

    impl LocalTrustlessLiveRequestExecutor for RecordingLiveExecutor {
        fn execute_live_http_request(
            &self,
            input: LocalTrustlessExecutionInput,
        ) -> Result<LocalTrustlessHttpResponse, LocalTrustlessLiveBindError> {
            *self.seen_input.lock().unwrap() = Some(input);
            Ok(self.response.clone())
        }
    }

    fn response(status_code: u16, body: Option<Vec<u8>>) -> LocalTrustlessHttpResponse {
        LocalTrustlessHttpResponse {
            status_code,
            body,
            headers: vec![
                ("x-s3w-test-response".to_owned(), "true".to_owned()),
                (
                    "x-s3w-gateway-plaintext-access".to_owned(),
                    "false".to_owned(),
                ),
            ],
            metadata_only: status_code != 200,
            plaintext_returned_locally: status_code == 200,
            gateway_plaintext_access: false,
        }
    }

    fn live_headers() -> String {
        format!(
            "\
x-s3w-bucket-id: {bucket_id}\r\n\
x-s3w-object-key-id: {object_key_id}\r\n\
x-s3w-policy-version: 7\r\n\
x-s3w-local-account: alice\r\n\
x-s3w-local-key-type: aws-esdk-rust-recipient-key\r\n\
x-s3w-recipients: alice\r\n\
x-s3w-recipient-keys: alice|aws-esdk-rust-recipient-key|1|true|{public_key_hex}\r\n\
x-s3w-manifest-ciphertext-ref: bee://ciphertext/live-bind\r\n\
x-s3w-manifest-ciphertext-size: 64\r\n\
x-s3w-manifest-content-type: text/plain\r\n\
x-s3w-manifest-etag: live-etag\r\n",
            bucket_id = hex::encode([1u8; 32]),
            object_key_id = hex::encode([2u8; 32]),
            public_key_hex = hex::encode("public-key")
        )
    }

    fn serve_one_in_thread(
        executor: RecordingLiveExecutor,
    ) -> (
        std::net::SocketAddr,
        thread::JoinHandle<Result<LocalTrustlessLiveServeResult, LocalTrustlessLiveBindError>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            LocalTrustlessLiveHttpServer::serve_one(
                listener,
                executor,
                LocalTrustlessHeaderContextBuilder,
                1024 * 1024,
            )
        });

        (addr, handle)
    }

    fn send_raw_http(addr: std::net::SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    }

    #[test]
    fn live_bind_rejects_non_localhost_host() {
        let err = LocalTrustlessLiveHttpServer::bind(LocalTrustlessLiveBindConfig {
            listen_host: "0.0.0.0".to_owned(),
            listen_port: 9090,
            max_request_body_bytes: 1024,
        })
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessLiveBindError::NonLocalBindHostRejected("0.0.0.0".to_owned())
        );
    }

    #[test]
    fn live_bind_executes_put_request_through_engine() {
        let seen_input = Arc::new(Mutex::new(None));
        let executor = RecordingLiveExecutor {
            seen_input: seen_input.clone(),
            response: response(202, None),
        };

        let (addr, handle) = serve_one_in_thread(executor);
        let body = b"live bind plaintext";
        let request = format!(
            "PUT /bucket/secret.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n{}\r\n",
            body.len(),
            live_headers()
        );

        let mut raw_request = request.into_bytes();
        raw_request.extend_from_slice(body);

        let raw_response = send_raw_http(addr, &raw_request);
        let result = handle.join().unwrap().unwrap();

        assert!(result.network_bind_performed);
        assert!(!result.gateway_plaintext_access);
        assert_eq!(result.response.status_code, 202);

        let raw_response = String::from_utf8_lossy(&raw_response);
        assert!(raw_response.starts_with("HTTP/1.1 202 Accepted"));
        assert!(raw_response.contains("x-s3w-test-response: true"));

        let input = seen_input.lock().unwrap().clone().unwrap();
        assert_eq!(input.http_request.method, LocalTrustlessHttpMethod::Put);
        assert_eq!(input.http_request.path, "/bucket/secret.txt");
        assert_eq!(input.http_request.body, Some(body.to_vec()));
        assert_eq!(input.http_context.bucket_id, hex::encode([1u8; 32]));
        assert_eq!(
            input.http_context.object_key_id,
            Some(hex::encode([2u8; 32]))
        );
        assert_eq!(input.http_context.policy_version, 7);
        assert_eq!(input.http_context.local_account, "alice");
        assert_eq!(input.manifest_entry.object_key, "secret.txt");
        assert_eq!(input.envelope_context.recipients.len(), 1);
        assert_eq!(
            input.envelope_context.recipients[0].public_key,
            "public-key"
        );
    }

    #[test]
    fn live_bind_executes_get_request_through_engine() {
        let seen_input = Arc::new(Mutex::new(None));
        let executor = RecordingLiveExecutor {
            seen_input: seen_input.clone(),
            response: response(200, Some(b"local plaintext".to_vec())),
        };

        let (addr, handle) = serve_one_in_thread(executor);
        let request = format!(
            "GET /bucket/secret.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n{}\r\n",
            live_headers()
        );

        let raw_response = send_raw_http(addr, request.as_bytes());
        let result = handle.join().unwrap().unwrap();

        assert_eq!(result.response.status_code, 200);
        assert_eq!(result.response.body, Some(b"local plaintext".to_vec()));
        assert!(result.response.plaintext_returned_locally);

        let raw_response = String::from_utf8_lossy(&raw_response);
        assert!(raw_response.starts_with("HTTP/1.1 200 OK"));
        assert!(raw_response.contains("local plaintext"));

        let input = seen_input.lock().unwrap().clone().unwrap();
        assert_eq!(input.http_request.method, LocalTrustlessHttpMethod::Get);
        assert!(input.http_request.body.is_none());
    }

    #[test]
    fn live_bind_rejects_plaintext_body_on_get() {
        let seen_input = Arc::new(Mutex::new(None));
        let executor = RecordingLiveExecutor {
            seen_input: seen_input.clone(),
            response: response(200, Some(b"should-not-run".to_vec())),
        };

        let (addr, handle) = serve_one_in_thread(executor);
        let request = format!(
            "GET /bucket/secret.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\n{}\r\nbad",
            live_headers()
        );

        let raw_response = send_raw_http(addr, request.as_bytes());
        let err = handle.join().unwrap().unwrap_err();

        assert_eq!(err, LocalTrustlessLiveBindError::UnexpectedPlaintextBody);
        assert!(seen_input.lock().unwrap().is_none());

        let raw_response = String::from_utf8_lossy(&raw_response);
        assert!(raw_response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(raw_response.contains("plaintext body is only allowed"));
    }

    #[test]
    fn live_bind_maps_engine_response_to_http_response() {
        let seen_input = Arc::new(Mutex::new(None));
        let executor = RecordingLiveExecutor {
            seen_input,
            response: LocalTrustlessHttpResponse {
                status_code: 204,
                body: None,
                headers: vec![
                    ("x-s3w-custom".to_owned(), "mapped".to_owned()),
                    (
                        "x-s3w-gateway-plaintext-access".to_owned(),
                        "false".to_owned(),
                    ),
                ],
                metadata_only: true,
                plaintext_returned_locally: false,
                gateway_plaintext_access: false,
            },
        };

        let (addr, handle) = serve_one_in_thread(executor);
        let body = b"abc";
        let request = format!(
            "PUT /bucket/secret.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n{}\r\n",
            body.len(),
            live_headers()
        );

        let mut raw_request = request.into_bytes();
        raw_request.extend_from_slice(body);

        let raw_response = send_raw_http(addr, &raw_request);
        let result = handle.join().unwrap().unwrap();

        assert_eq!(result.response.status_code, 204);

        let raw_response = String::from_utf8_lossy(&raw_response);
        assert!(raw_response.starts_with("HTTP/1.1 204 No Content"));
        assert!(raw_response.contains("x-s3w-custom: mapped"));
        assert!(raw_response.contains("Content-Length: 0"));
    }
}
