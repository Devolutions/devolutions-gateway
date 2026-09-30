//! Request and answer formats of the provider HTTP APIs, reduced to what a single text completion needs.

pub(crate) mod anthropic;
pub(crate) mod openai;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Usage};

/// HTTP API spoken by a provider.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Api {
    OpenAiChat(openai::TokenLimit),
    AnthropicMessages,
}

/// Answer of a provider, in the terms shared by every API.
pub(crate) struct Completion {
    pub(crate) text: String,
    /// The answer reached the output token limit.
    pub(crate) truncated: bool,
    pub(crate) model: Option<String>,
    pub(crate) usage: Option<Usage>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'static str,
    content: &'a str,
}

/// Error body shared by the OpenAI-style and Anthropic APIs.
#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    message: String,
}

pub(crate) fn error_message(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ErrorBody>(body)
        .ok()
        .map(|body| body.error.message)
}

fn endpoint(base_url: &Url, path: &str) -> String {
    format!("{}/{path}", base_url.as_str().trim_end_matches('/'))
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
    fn endpoint_joins_with_or_without_trailing_slash() {
        for base_url in ["https://api.example/v1/", "https://api.example/v1"] {
            let base_url = Url::parse(base_url).expect("valid URL");
            assert_eq!(
                endpoint(&base_url, "chat/completions"),
                "https://api.example/v1/chat/completions"
            );
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
}
