//! OpenAI chat completions, also spoken by Mistral, Gemini, and many other providers.

use serde::{Deserialize, Serialize};
use url::Url;

use super::{Completion, Message, endpoint, parse_body, usage};
use crate::Error;
use crate::client::Prompt;

/// Field holding the output token limit in the request.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TokenLimit {
    /// `max_completion_tokens`, the only one the newer OpenAI models accept.
    MaxCompletionTokens,
    /// `max_tokens`, the only one most other servers know.
    MaxTokens,
}

pub(crate) fn request(
    http_client: &reqwest::Client,
    base_url: &Url,
    api_key: &str,
    model: &str,
    prompt: &Prompt<'_>,
    limit: TokenLimit,
) -> reqwest::RequestBuilder {
    let (max_completion_tokens, max_tokens) = match limit {
        TokenLimit::MaxCompletionTokens => (Some(prompt.max_output_tokens), None),
        TokenLimit::MaxTokens => (None, Some(prompt.max_output_tokens)),
    };

    http_client
        .post(endpoint(base_url, "chat/completions"))
        .bearer_auth(api_key)
        .json(&ChatRequest {
            model,
            messages: [
                Message {
                    role: "system",
                    content: prompt.system,
                },
                Message {
                    role: "user",
                    content: prompt.input,
                },
            ],
            max_completion_tokens,
            max_tokens,
        })
}

pub(crate) fn parse(body: &[u8]) -> Result<Completion, Error> {
    let response: ChatResponse = parse_body(body)?;
    let choice = response.choices.into_iter().next();

    Ok(Completion {
        truncated: choice
            .as_ref()
            .is_some_and(|choice| choice.finish_reason.as_deref() == Some("length")),
        text: choice.and_then(|choice| choice.message.content).unwrap_or_default(),
        model: response.model,
        usage: response
            .usage
            .and_then(|counts| usage(counts.prompt_tokens, counts.completion_tokens)),
    })
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: [Message<'a>; 2],
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct ChatResponse {
    model: Option<String>,
    choices: Vec<ChatChoice>,
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatAnswer,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatAnswer {
    content: Option<String>,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Usage;

    #[test]
    fn parses_text_model_and_usage() {
        let completion = parse(
            br#"{"model":"gpt-4o-2024-08-06","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#,
        )
        .expect("valid answer");

        assert_eq!(completion.text, "hello");
        assert!(!completion.truncated);
        assert_eq!(completion.model.as_deref(), Some("gpt-4o-2024-08-06"));
        assert_eq!(
            completion.usage,
            Some(Usage {
                input_tokens: 10,
                output_tokens: 20
            })
        );
    }

    #[test]
    fn length_finish_reason_is_truncated() {
        let completion = parse(br#"{"choices":[{"message":{"content":"partial"},"finish_reason":"length"}]}"#)
            .expect("valid answer");

        assert!(completion.truncated);
    }

    #[test]
    fn model_usage_and_content_are_optional() {
        let completion = parse(br#"{"choices":[{"message":{"content":null}}]}"#).expect("valid answer");

        assert_eq!(completion.text, "");
        assert!(!completion.truncated);
        assert_eq!(completion.model, None);
        assert_eq!(completion.usage, None);
    }
}
