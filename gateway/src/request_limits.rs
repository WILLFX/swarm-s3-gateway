use anyhow::{Context, Result, bail};
use std::env;

pub const MAX_REQUEST_BODY_BYTES_ENV: &str = "S3GW_MAX_REQUEST_BODY_BYTES";
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

pub fn max_request_body_bytes_from_env() -> Result<usize> {
    parse_max_request_body_bytes(env::var(MAX_REQUEST_BODY_BYTES_ENV).ok().as_deref())
}

fn parse_max_request_body_bytes(raw: Option<&str>) -> Result<usize> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_MAX_REQUEST_BODY_BYTES);
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_MAX_REQUEST_BODY_BYTES);
    }

    let value = trimmed.parse::<usize>().with_context(|| {
        format!("{MAX_REQUEST_BODY_BYTES_ENV} must be a positive integer byte count")
    })?;

    if value == 0 {
        bail!("{MAX_REQUEST_BODY_BYTES_ENV} must be greater than zero");
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_limit_defaults_when_unset_or_blank() -> Result<()> {
        assert_eq!(
            parse_max_request_body_bytes(None)?,
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        assert_eq!(
            parse_max_request_body_bytes(Some("   "))?,
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );

        Ok(())
    }

    #[test]
    fn request_body_limit_accepts_positive_byte_count() -> Result<()> {
        assert_eq!(parse_max_request_body_bytes(Some("1048576"))?, 1_048_576);
        Ok(())
    }

    #[test]
    fn request_body_limit_rejects_zero() {
        let err = parse_max_request_body_bytes(Some("0"))
            .expect_err("zero request body limit must be rejected");

        assert!(
            format!("{err:#}").contains("must be greater than zero"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn request_body_limit_rejects_non_numeric_value() {
        let err = parse_max_request_body_bytes(Some("not-a-number"))
            .expect_err("non-numeric request body limit must be rejected");

        assert!(
            format!("{err:#}").contains(MAX_REQUEST_BODY_BYTES_ENV),
            "unexpected error: {err:#}"
        );
    }
}
