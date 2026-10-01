use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{HeaderMap, RETRY_AFTER};

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
    Status {
        status: u16,
        message: String,
        /// Error code of the provider, such as `insufficient_quota`, when the answer has one.
        code: Option<String>,
        /// Time the provider asks to wait before sending again, from a `Retry-After` header in seconds.
        retry_after: Option<Duration>,
    },
    /// The provider answered with a body that is not in the format of its API, or reported a failure instead of an
    /// answer.
    #[error("AI provider answer is not valid: {reason}")]
    InvalidResponse { reason: String },
    /// The answer reached the output token limit or filled the context window, so its end is missing: send a shorter
    /// input instead.
    ///
    /// The provider still counts the tokens of the request in `usage`.
    #[error("AI answer was cut short by the output token limit or the context window")]
    Truncated { usage: Option<Usage> },
    /// The provider refused to answer, such as when its content filter blocked the request.
    ///
    /// The reason names the signal of the provider and never quotes the model.
    #[error("AI provider refused to answer: {reason}")]
    Refused { reason: String },
    /// The answer does not follow the output format the purpose asked for.
    #[error("AI answer is not in the expected format: {reason}")]
    InvalidOutput { reason: String },
}

impl Error {
    /// Returns `true` when sending the same request again later may succeed, such as after a rate limit.
    ///
    /// A spent quota or spend limit is not transient, even when the provider answers it as a rate limit.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Transport { .. } => true,
            // Request timeout, conflict, rate limit, and server errors, including Anthropic's 529 "overloaded".
            // The Anthropic SDKs retry a conflict too.
            Self::Status { status, code, .. } => {
                matches!(*status, 408 | 409 | 429 | 500..)
                    && !code.as_deref().is_some_and(|code| SPENT_QUOTA_CODES.contains(&code))
            }
            Self::InvalidResponse { .. }
            | Self::Truncated { .. }
            | Self::Refused { .. }
            | Self::InvalidOutput { .. } => false,
        }
    }
}

/// Error codes of a spent quota or spend limit, which lasts until the account changes or the billing period ends.
const SPENT_QUOTA_CODES: [&str; 6] = [
    // OpenAI.
    "insufficient_quota",
    "credit_balance_exhausted",
    "organization_spend_limit_exceeded",
    "project_spend_limit_exceeded",
    "organization_usage_limit_exceeded",
    // Anthropic.
    "enforced_spend_limit_reached",
];

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

pub(crate) fn status(status: StatusCode, retry_after: Option<Duration>, body: &[u8], api_key: &str) -> Error {
    let wire::ErrorBody { message, code } = wire::parse_error_body(body);
    let message = message.unwrap_or_else(|| status.canonical_reason().unwrap_or("unknown status").to_owned());

    Error::Status {
        status: status.as_u16(),
        message: redact(message, api_key),
        code: code.map(|code| redact(code, api_key)),
        retry_after,
    }
}

/// Reads a `Retry-After` header holding a number of seconds; the HTTP date form is ignored.
pub(crate) fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let seconds = headers.get(RETRY_AFTER)?.to_str().ok()?.parse::<u64>().ok()?;

    Some(Duration::from_secs(seconds))
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
    use reqwest::header::HeaderValue;

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
        let body = format!(r#"{{"error":{{"message":"Incorrect API key provided: {API_KEY}","code":"{API_KEY}"}}}}"#);

        let error = status(StatusCode::UNAUTHORIZED, None, body.as_bytes(), API_KEY);

        assert!(matches!(error, Error::Status { status: 401, .. }), "{error:?}");
        assert!(!format!("{error:?}").contains(API_KEY));
        assert!(error.to_string().contains("[REDACTED]"));
        assert!(
            matches!(&error, Error::Status { code: Some(code), .. } if code == "[REDACTED]"),
            "{error:?}"
        );
    }

    #[test]
    fn status_error_without_provider_message_uses_the_reason() {
        let error = status(StatusCode::BAD_GATEWAY, None, b"<html>proxy error</html>", API_KEY);

        assert_eq!(error.to_string(), "AI provider answered HTTP 502: Bad Gateway");
    }

    #[test]
    fn status_error_keeps_the_code_and_retry_after() {
        let body = br#"{"error":{"message":"You exceeded your current quota.","type":"insufficient_quota","param":null,"code":"insufficient_quota"}}"#;

        let error = status(
            StatusCode::TOO_MANY_REQUESTS,
            Some(Duration::from_secs(7)),
            body,
            API_KEY,
        );

        assert!(
            matches!(
                &error,
                Error::Status { status: 429, message, code: Some(code), retry_after: Some(retry_after) }
                    if message == "You exceeded your current quota."
                        && code == "insufficient_quota"
                        && *retry_after == Duration::from_secs(7)
            ),
            "{error:?}"
        );
    }

    #[test]
    fn retry_after_is_a_number_of_seconds() {
        for (value, expected) in [
            ("7", Some(7)),
            ("0", Some(0)),
            ("Wed, 21 Oct 2015 07:28:00 GMT", None),
            ("1.5", None),
            ("-1", None),
            ("soon", None),
            ("", None),
        ] {
            let headers = HeaderMap::from_iter([(RETRY_AFTER, HeaderValue::from_static(value))]);

            assert_eq!(retry_after(&headers), expected.map(Duration::from_secs), "{value:?}");
        }

        assert_eq!(retry_after(&HeaderMap::new()), None);
    }

    #[test]
    fn refusal_names_the_signal() {
        let error = Error::Refused {
            reason: "content filter".to_owned(),
        };

        assert_eq!(error.to_string(), "AI provider refused to answer: content filter");
    }

    fn status_error(status: u16, code: Option<&str>) -> Error {
        Error::Status {
            status,
            message: "failed".to_owned(),
            code: code.map(str::to_owned),
            retry_after: None,
        }
    }

    #[test]
    fn transient_errors() {
        for error in [
            Error::Transport {
                message: "connection refused".to_owned(),
            },
            status_error(408, None),
            status_error(409, None),
            status_error(429, None),
            status_error(429, Some("rate_limit_exceeded")),
            status_error(500, None),
            status_error(503, None),
            status_error(529, None),
        ] {
            assert!(error.is_transient(), "{error:?}");
        }

        for error in [
            status_error(400, None),
            status_error(401, None),
            status_error(403, None),
            status_error(404, None),
            Error::InvalidResponse {
                reason: "syntax error".to_owned(),
            },
            Error::Truncated { usage: None },
            Error::Refused {
                reason: "content filter".to_owned(),
            },
            Error::InvalidOutput {
                reason: "no valid line".to_owned(),
            },
        ] {
            assert!(!error.is_transient(), "{error:?}");
        }
    }

    #[test]
    fn spent_quota_is_permanent() {
        for code in [
            "insufficient_quota",
            "credit_balance_exhausted",
            "organization_spend_limit_exceeded",
            "project_spend_limit_exceeded",
            "organization_usage_limit_exceeded",
            "enforced_spend_limit_reached",
        ] {
            for status in [400, 429, 503] {
                let error = status_error(status, Some(code));

                assert!(!error.is_transient(), "{error:?}");
            }
        }
    }
}
