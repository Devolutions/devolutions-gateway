//! Request and answer formats of the provider HTTP APIs, reduced to what a single text completion needs.

pub(crate) mod anthropic;
pub(crate) mod openai;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;

use crate::{Error, Usage};

/// HTTP API spoken by a provider.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Api {
    OpenAiChat(openai::Dialect),
    AnthropicMessages,
}

/// Answer of a provider, in the terms shared by every API.
pub(crate) struct Completion {
    pub(crate) text: String,
    pub(crate) stop: Stop,
    pub(crate) model: Option<String>,
    pub(crate) usage: Option<Usage>,
}

/// How the answer ended, read from the stop or finish reason of the provider.
///
/// A reason is fixed text naming the signal of the provider, never model output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The model finished its answer.
    Complete,
    /// The answer reached the output token limit or filled the context window, so its end is missing.
    Truncated,
    /// The provider refused to answer, so the text is not an answer.
    Refused(&'static str),
    /// The answer ended in a way no purpose can use, such as a failure of the provider or an unexpected stop reason.
    Failed(&'static str),
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'static str,
    content: &'a str,
}

/// Message and code of an error answer, when its body has them.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ErrorBody {
    pub(crate) message: Option<String>,
    /// Error code of the provider, such as `insufficient_quota`.
    pub(crate) code: Option<String>,
}

/// Reads the error bodies of OpenAI, Anthropic, Mistral, and Gemini; a body of another shape has neither field.
pub(crate) fn parse_error_body(body: &[u8]) -> ErrorBody {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return ErrorBody::default();
    };

    // Gemini's OpenAI-compatible endpoint may wrap the error in an array.
    let body = match body {
        Value::Array(items) => items.into_iter().next().unwrap_or_default(),
        body => body,
    };

    // OpenAI, Anthropic, and Gemini nest the error in `error`; Mistral does not.
    let error = body.get("error").filter(|error| error.is_object()).unwrap_or(&body);
    let string = |pointer: &str| error.pointer(pointer).and_then(Value::as_str).map(str::to_owned);

    ErrorBody {
        message: string("/message"),
        // Anthropic puts its code in `details`. Numeric codes, such as the HTTP status Gemini repeats, are ignored.
        code: string("/code").or_else(|| string("/details/error_code")),
    }
}

/// URL of an API path, such as `chat/completions`, under the path of the base URL.
///
/// The query of the base URL is kept, for servers that need one on every request, such as the `api-version` of Azure
/// OpenAI; its fragment is dropped.
fn endpoint(base_url: &Url, path: &str) -> Url {
    let mut endpoint = base_url.clone();
    endpoint.set_path(&format!("{}/{path}", base_url.path().trim_end_matches('/')));
    endpoint.set_fragment(None);
    endpoint
}

// The reason never quotes the body, because the answer may contain session data.
fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|error| Error::InvalidResponse {
        reason: format!(
            "{:?} error at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
        ),
    })
}

fn usage(input_tokens: Option<u64>, output_tokens: Option<u64>) -> Option<Usage> {
    Some(Usage {
        input_tokens: input_tokens?,
        output_tokens: output_tokens?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_under_the_base_path() {
        for (base_url, expected) in [
            ("https://h/v1", "https://h/v1/chat/completions"),
            ("https://h/v1/", "https://h/v1/chat/completions"),
            (
                "https://h/v1?api-version=1",
                "https://h/v1/chat/completions?api-version=1",
            ),
            (
                "https://h/v1/?api-version=1",
                "https://h/v1/chat/completions?api-version=1",
            ),
            ("https://h/v1/#frag", "https://h/v1/chat/completions"),
            ("https://h", "https://h/chat/completions"),
            ("http://127.0.0.1:8080/v1/", "http://127.0.0.1:8080/v1/chat/completions"),
        ] {
            let base_url = Url::parse(base_url).expect("valid URL");

            assert_eq!(endpoint(&base_url, "chat/completions").as_str(), expected, "{base_url}");
        }
    }

    #[test]
    fn invalid_response_reason_does_not_quote_the_body() {
        let error = parse_body::<Vec<u32>>(br#"["secret-value"]"#).expect_err("invalid body");

        assert!(matches!(error, Error::InvalidResponse { .. }));
        assert!(!error.to_string().contains("secret-value"));
    }

    #[test]
    fn usage_needs_both_counts() {
        assert_eq!(
            usage(Some(1), Some(2)),
            Some(Usage {
                input_tokens: 1,
                output_tokens: 2
            })
        );
        assert_eq!(usage(Some(1), None), None);
        assert_eq!(usage(None, Some(2)), None);
    }

    #[test]
    fn error_body_of_every_provider() {
        for (provider, body, message, code) in [
            (
                "OpenAI",
                r#"{"error":{"message":"m","type":"insufficient_quota","param":null,"code":"insufficient_quota"}}"#,
                Some("m"),
                Some("insufficient_quota"),
            ),
            (
                "OpenAI",
                r#"{"error":{"message":"m","type":"invalid_request_error","param":null,"code":null}}"#,
                Some("m"),
                None,
            ),
            (
                "Anthropic",
                r#"{"type":"error","error":{"type":"rate_limit_error","message":"m","details":{"error_code":"enforced_spend_limit_reached"}},"request_id":"req_1"}"#,
                Some("m"),
                Some("enforced_spend_limit_reached"),
            ),
            (
                "Mistral",
                r#"{"object":"error","message":"m","type":"invalid_request_error","param":null,"code":"3505"}"#,
                Some("m"),
                Some("3505"),
            ),
            (
                "Mistral",
                r#"{"object":"error","message":"m","type":"invalid_request_error","param":null,"code":3505}"#,
                Some("m"),
                None,
            ),
            (
                "Gemini",
                r#"[{"error":{"code":400,"message":"m","status":"INVALID_ARGUMENT"}}]"#,
                Some("m"),
                None,
            ),
            (
                "Gemini",
                r#"{"error":{"code":429,"message":"m","status":"RESOURCE_EXHAUSTED"}}"#,
                Some("m"),
                None,
            ),
        ] {
            assert_eq!(
                parse_error_body(body.as_bytes()),
                ErrorBody {
                    message: message.map(str::to_owned),
                    code: code.map(str::to_owned),
                },
                "{provider}: {body}"
            );
        }
    }

    #[test]
    fn error_body_of_another_shape_has_no_field() {
        for body in [
            "<html>proxy error</html>",
            "",
            "[]",
            "null",
            r#"{"error":"m"}"#,
            r#"{"object":"error","message":{"detail":[{"msg":"m"}]},"code":null}"#,
        ] {
            assert_eq!(parse_error_body(body.as_bytes()), ErrorBody::default(), "{body}");
        }
    }
}
