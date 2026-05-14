use std::fmt::Display;

use aws_smithy_xml::encode::XmlWriter;
use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;

pub const S3_XML_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3ErrorKind {
    AccessDenied,
    NoSuchBucket,
    NoSuchKey,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    InvalidBucketName,
    InvalidRequest,
    InternalError,
    NotImplemented,
    ServiceUnavailable,
    SignatureDoesNotMatch,
    InvalidAccessKeyId,
    MethodNotAllowed,
    PreconditionFailed,
}

impl S3ErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::AccessDenied => "AccessDenied",
            Self::NoSuchBucket => "NoSuchBucket",
            Self::NoSuchKey => "NoSuchKey",
            Self::BucketAlreadyExists => "BucketAlreadyExists",
            Self::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidRequest => "InvalidRequest",
            Self::InternalError => "InternalError",
            Self::NotImplemented => "NotImplemented",
            Self::ServiceUnavailable => "ServiceUnavailable",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::MethodNotAllowed => "MethodNotAllowed",
            Self::PreconditionFailed => "PreconditionFailed",
        }
    }

    pub fn default_message(self) -> &'static str {
        match self {
            Self::AccessDenied => "Access Denied",
            Self::NoSuchBucket => "The specified bucket does not exist",
            Self::NoSuchKey => "The specified key does not exist",
            Self::BucketAlreadyExists => "The requested bucket name is not available",
            Self::BucketAlreadyOwnedByYou => {
                "Your previous request to create the named bucket succeeded and you already own it"
            }
            Self::BucketNotEmpty => "The bucket you tried to delete is not empty",
            Self::InvalidBucketName => "The specified bucket is not valid",
            Self::InvalidRequest => "Invalid Request",
            Self::InternalError => "We encountered an internal error. Please try again.",
            Self::NotImplemented => {
                "A header or feature you provided implies functionality that is not implemented"
            }
            Self::ServiceUnavailable => "Please reduce your request rate.",
            Self::SignatureDoesNotMatch => {
                "The request signature we calculated does not match the signature you provided"
            }
            Self::InvalidAccessKeyId => {
                "The AWS Access Key Id you provided does not exist in our records"
            }
            Self::MethodNotAllowed => "The specified method is not allowed against this resource",
            Self::PreconditionFailed => {
                "At least one of the preconditions you specified did not hold"
            }
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::AccessDenied => StatusCode::FORBIDDEN,
            Self::NoSuchBucket | Self::NoSuchKey => StatusCode::NOT_FOUND,
            Self::BucketAlreadyExists
            | Self::BucketAlreadyOwnedByYou
            | Self::InvalidBucketName
            | Self::InvalidRequest
            | Self::SignatureDoesNotMatch
            | Self::InvalidAccessKeyId
            | Self::PreconditionFailed => StatusCode::BAD_REQUEST,
            Self::BucketNotEmpty => StatusCode::CONFLICT,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct S3ErrorResponse {
    pub kind: S3ErrorKind,
    pub message: Option<String>,
    pub resource: Option<String>,
    pub request_id: Option<String>,
}

impl S3ErrorResponse {
    pub fn new(kind: S3ErrorKind) -> Self {
        Self {
            kind,
            message: None,
            resource: None,
            request_id: None,
        }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn into_response(self) -> Response {
        let mut xml = String::new();
        let mut writer = XmlWriter::new(&mut xml);
        let root = writer.start_el("Error").write_ns(S3_XML_NS, None);
        let mut root = root.finish();

        write_text_element(&mut root, "Code", self.kind.code());
        write_text_element(
            &mut root,
            "Message",
            self.message
                .as_deref()
                .unwrap_or(self.kind.default_message()),
        );

        if let Some(resource) = self.resource.as_deref() {
            write_text_element(&mut root, "Resource", resource);
        }

        if let Some(request_id) = self.request_id.as_deref() {
            write_text_element(&mut root, "RequestId", request_id);
        }

        root.finish();

        xml_response(self.kind.status(), xml)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketSummary {
    pub name: String,
    pub creation_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListObjectsV2Entry {
    pub key: String,
    pub last_modified: String,
    pub etag: String,
    pub size: u64,
    pub storage_class: String,
}

pub fn xml_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

pub fn empty_response(status: StatusCode) -> Response {
    status.into_response()
}

pub fn create_bucket_response(bucket: &str) -> Response {
    let location = format!("/{bucket}");
    (
        StatusCode::OK,
        [(header::LOCATION, HeaderValue::from_str(&location).unwrap())],
    )
        .into_response()
}

pub fn put_object_response(swarm_ref: &str) -> Response {
    (
        StatusCode::OK,
        [(
            "x-amz-meta-swarm-ref",
            HeaderValue::from_str(swarm_ref).unwrap(),
        )],
    )
        .into_response()
}

pub fn get_object_response(swarm_ref: &str, content_type: &str, body: Bytes) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
            ),
            (
                header::HeaderName::from_static("x-amz-meta-swarm-ref"),
                HeaderValue::from_str(swarm_ref).unwrap(),
            ),
        ],
        body,
    )
        .into_response()
}

pub fn head_object_response(
    swarm_ref: &str,
    content_type: &str,
    size: u64,
    etag: &str,
    last_modified: &str,
) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
            ),
            (
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&size.to_string()).unwrap(),
            ),
            (
                header::ETAG,
                HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap(),
            ),
            (
                header::LAST_MODIFIED,
                HeaderValue::from_str(last_modified)
                    .unwrap_or_else(|_| HeaderValue::from_static("")),
            ),
            (
                header::HeaderName::from_static("x-amz-meta-swarm-ref"),
                HeaderValue::from_str(swarm_ref).unwrap(),
            ),
        ],
    )
        .into_response()
}

pub fn no_content_response() -> Response {
    empty_response(StatusCode::NO_CONTENT)
}

pub fn not_implemented_response() -> Response {
    S3ErrorResponse::new(S3ErrorKind::NotImplemented).into_response()
}

pub fn list_buckets_response(
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[BucketSummary],
) -> Response {
    let mut xml = String::new();
    let mut writer = XmlWriter::new(&mut xml);

    let root = writer
        .start_el("ListAllMyBucketsResult")
        .write_ns(S3_XML_NS, None);
    let mut root = root.finish();

    {
        let mut owner = root.start_el("Owner").finish();
        write_text_element(&mut owner, "ID", owner_id);
        write_text_element(&mut owner, "DisplayName", owner_display_name);
        owner.finish();
    }

    {
        let mut buckets_el = root.start_el("Buckets").finish();
        for bucket in buckets {
            let mut bucket_el = buckets_el.start_el("Bucket").finish();
            write_text_element(&mut bucket_el, "Name", &bucket.name);
            write_text_element(&mut bucket_el, "CreationDate", &bucket.creation_date);
            bucket_el.finish();
        }
        buckets_el.finish();
    }

    root.finish();

    xml_response(StatusCode::OK, xml)
}

pub fn list_objects_v2_response(
    bucket: &str,
    prefix: Option<&str>,
    max_keys: usize,
    continuation_token: Option<&str>,
    objects: &[ListObjectsV2Entry],
) -> Response {
    let mut xml = String::new();
    let mut writer = XmlWriter::new(&mut xml);

    let root = writer
        .start_el("ListBucketResult")
        .write_ns(S3_XML_NS, None);
    let mut root = root.finish();

    write_text_element(&mut root, "Name", bucket);
    write_text_element(&mut root, "Prefix", prefix.unwrap_or(""));
    write_text_element(&mut root, "MaxKeys", &max_keys.to_string());
    write_text_element(&mut root, "KeyCount", &objects.len().to_string());
    write_text_element(&mut root, "IsTruncated", "false");

    if let Some(token) = continuation_token {
        write_text_element(&mut root, "ContinuationToken", token);
    }

    for object in objects {
        let mut contents = root.start_el("Contents").finish();
        write_text_element(&mut contents, "Key", &object.key);
        write_text_element(&mut contents, "LastModified", &object.last_modified);
        write_text_element(&mut contents, "ETag", &format!("\"{}\"", object.etag));
        write_text_element(&mut contents, "Size", &object.size.to_string());
        write_text_element(&mut contents, "StorageClass", &object.storage_class);
        contents.finish();
    }

    root.finish();

    xml_response(StatusCode::OK, xml)
}

pub fn bee_error_response(err: impl Display) -> Response {
    S3ErrorResponse::new(S3ErrorKind::InternalError)
        .with_message(format!("Bee backend error: {err}"))
        .into_response()
}

pub fn bee_unavailable_response(err: impl Display) -> Response {
    S3ErrorResponse::new(S3ErrorKind::ServiceUnavailable)
        .with_message(format!("Bee backend unavailable: {err}"))
        .into_response()
}

pub fn chain_error_response(err: impl Display) -> Response {
    S3ErrorResponse::new(S3ErrorKind::InternalError)
        .with_message(format!("Chain backend error: {err}"))
        .into_response()
}

fn write_text_element(
    scope: &mut aws_smithy_xml::encode::ScopeWriter<'_, '_>,
    tag: &str,
    value: &str,
) {
    let mut el = scope.start_el(tag).finish();
    el.data(value);
    el.finish();
}

pub fn omit_swarm_ref_for_private_response(mut response: Response, is_private: bool) -> Response {
    if is_private {
        response.headers_mut().remove("x-amz-meta-swarm-ref");
    }

    response
}

#[cfg(test)]
mod private_response_header_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Response, StatusCode},
    };

    #[test]
    fn private_response_omits_swarm_ref_header() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(
                "x-amz-meta-swarm-ref",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .body(Body::empty())
            .unwrap();

        let response = omit_swarm_ref_for_private_response(response, true);

        assert!(response.headers().get("x-amz-meta-swarm-ref").is_none());
    }

    #[test]
    fn public_response_keeps_swarm_ref_header() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(
                "x-amz-meta-swarm-ref",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .body(Body::empty())
            .unwrap();

        let response = omit_swarm_ref_for_private_response(response, false);

        assert_eq!(
            response
                .headers()
                .get("x-amz-meta-swarm-ref")
                .unwrap()
                .to_str()
                .unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }
}
