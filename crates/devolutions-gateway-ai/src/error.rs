use reqwest::StatusCode;

use crate::{Usage, wire};

/// Error returned when a purpose request fails; no variant ever holds the API key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request got no answer, such as on a connection failure or a timeout.
    ///
    /// The underlying error is not kept as `source()`, because its chain could expose the key unredacted.
    #[error("AI provider request failed: {message}")]
    Transport { message: String },
    /// The provider answered with an error status.
    #[error("AI provider answered HTTP {status}: {message}")]
    Status { status: u16, message: String },
    /// The provider answered with a body that is not in the format of its API.
    #[error("AI provider answer is not valid: {reason}")]
    InvalidResponse { reason: String },
    /// The answer reached the output token limit, so its end is missing: send a shorter input instead.
    ///
    /// The provider still counts the tokens of the request in `usage`.
    #[error("AI answer was cut at the output token limit")]
    Truncated { usage: Option<Usage> },
    /// The answer does not follow the output format the purpose asked for.
    #[error("AI answer is not in the expected format: {reason}")]
    InvalidOutput { reason: String },
}

impl Error {
    /// Returns `true` when sending the same request again later may succeed, such as after a rate limit.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Transport { .. } => true,
            // Request timeout, rate limit, and server errors, including Anthropic's 529 "overloaded".
            Self::Status { status, .. } => matches!(*status, 408 | 429 | 500..),
            Self::InvalidResponse { .. } | Self::Truncated { .. } | Self::InvalidOutput { .. } => false,
        }
    }
}

pub(crate) fn transport(error: &dyn std::error::Error, api_key: &str) -> Error {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }

    Error::Transport {
        message: redact(message, api_key),
    }
}

pub(crate) fn status(status: StatusCode, body: &[u8], api_key: &str) -> Error {
    let message =
        wire::error_message(body).unwrap_or_else(|| status.canonical_reason().unwrap_or("unknown status").to_owned());

    Error::Status {
        status: status.as_u16(),
        message: redact(message, api_key),
    }
}

// Provider error bodies may echo the API key back.
fn redact(message: String, api_key: &str) -> String {
    if api_key.is_empty() {
        message
    } else {
        message.replace(api_key, "[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_KEY: &str = "sk-very-secret";

    #[test]
    fn transport_error_redacts_api_key() {
        let error = std::io::Error::other(format!("invalid key {API_KEY} provided"));

        let error = transport(&error, API_KEY);

        assert!(!error.to_string().contains(API_KEY));
        assert!(!format!("{error:?}").contains(API_KEY));
        assert!(error.to_string().contains("[REDACTED]"));
    }

    #[test]
    fn status_error_redacts_api_key_echoed_by_the_provider() {
        let body = format!(r#"{{"error":{{"message":"Incorrect API key provided: {API_KEY}"}}}}"#);

        let error = status(StatusCode::UNAUTHORIZED, body.as_bytes(), API_KEY);

        assert!(matches!(error, Error::Status { status: 401, .. }), "{error:?}");
        assert!(!format!("{error:?}").contains(API_KEY));
        assert!(error.to_string().contains("[REDACTED]"));
    }

    #[test]
    fn status_error_without_provider_message_uses_the_reason() {
        let error = status(StatusCode::BAD_GATEWAY, b"<html>proxy error</html>", API_KEY);

        assert_eq!(error.to_string(), "AI provider answered HTTP 502: Bad Gateway");
    }

    #[test]
    fn transient_errors() {
        let status = |status| Error::Status {
            status,
            message: "failed".to_owned(),
        };

        for error in [
            Error::Transport {
                message: "connection refused".to_owned(),
            },
            status(408),
            status(429),
            status(500),
            status(503),
            status(529),
        ] {
            assert!(error.is_transient(), "{error:?}");
        }

        for error in [
            status(400),
            status(401),
            status(403),
            status(404),
            Error::InvalidResponse {
                reason: "syntax error".to_owned(),
            },
            Error::Truncated { usage: None },
            Error::InvalidOutput {
                reason: "no valid line".to_owned(),
            },
        ] {
            assert!(!error.is_transient(), "{error:?}");
        }
    }
}
