//! OpenAI chat completions, also spoken by Mistral, Gemini, and many other providers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::{Completion, Message, Stop, endpoint, parse_body, usage};
use crate::Error;
use crate::client::Prompt;

/// Server behind the API, because a few request fields differ between servers.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Dialect {
    /// OpenAI itself: its newer models only accept `max_completion_tokens`, and it stores completions unless the
    /// request has `"store": false`.
    OpenAi,
    /// Any other server, such as Mistral or Gemini: it only knows `max_tokens`, and may reject unknown fields.
    Other,
}

pub(crate) fn request(
    http_client: &reqwest::Client,
    base_url: &Url,
    api_key: &str,
    model: &str,
    prompt: &Prompt<'_>,
    dialect: Dialect,
) -> reqwest::RequestBuilder {
    // The input may hold sensitive data, such as a session transcript, so OpenAI must not store it.
    let (max_completion_tokens, max_tokens, store) = match dialect {
        Dialect::OpenAi => (Some(prompt.max_output_tokens), None, Some(false)),
        Dialect::Other => (None, Some(prompt.max_output_tokens), None),
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
            store,
        })
}

pub(crate) fn parse(body: &[u8]) -> Result<Completion, Error> {
    let response: ChatResponse = parse_body(body)?;
    let choice = response.choices.into_iter().next();

    Ok(Completion {
        stop: choice.as_ref().map_or(Stop::Complete, ChatChoice::stop),
        text: choice
            .and_then(|choice| choice.message.content)
            .map(ChatContent::into_text)
            .unwrap_or_default(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    store: Option<bool>,
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

impl ChatChoice {
    fn stop(&self) -> Stop {
        let refused = self
            .message
            .refusal
            .as_deref()
            .is_some_and(|refusal| !refusal.is_empty());

        // A refusal replaces the answer, whatever the finish reason.
        if refused {
            return Stop::Refused("refusal message");
        }

        // Mistral also reports a full context window as `model_length`, and a failure as `error`.
        match self.finish_reason.as_deref() {
            Some("length" | "model_length") => Stop::Truncated,
            Some("content_filter") => Stop::Refused("content filter"),
            Some("error") => Stop::Failed("provider stopped with finish_reason error"),
            _ => Stop::Complete,
        }
    }
}

#[derive(Deserialize)]
struct ChatAnswer {
    content: Option<ChatContent>,
    /// Why the model refused to answer, in its own words, so it is never quoted.
    refusal: Option<String>,
}

/// Text of the answer, which Mistral may send as a list of chunks.
#[derive(Deserialize)]
#[serde(untagged)]
enum ChatContent {
    Text(String),
    Chunks(Vec<Value>),
}

impl ChatContent {
    /// Joins the text chunks; other chunks, such as reasoning, and chunks of an unknown shape are skipped.
    fn into_text(self) -> String {
        match self {
            Self::Text(text) => text,
            Self::Chunks(chunks) => chunks
                .iter()
                .filter(|chunk| chunk["type"] == "text")
                .filter_map(|chunk| chunk["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
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
            br#"{"model":"gpt-4o-2024-08-06","choices":[{"message":{"role":"assistant","content":"hello","refusal":null},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#,
        )
        .expect("valid answer");

        assert_eq!(completion.text, "hello");
        assert_eq!(completion.stop, Stop::Complete);
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
    fn length_finish_reasons_are_truncated() {
        for finish_reason in ["length", "model_length"] {
            let body =
                format!(r#"{{"choices":[{{"message":{{"content":"partial"}},"finish_reason":"{finish_reason}"}}]}}"#);

            let completion = parse(body.as_bytes()).expect("valid answer");

            assert_eq!(completion.stop, Stop::Truncated, "{finish_reason}");
        }
    }

    #[test]
    fn model_usage_and_content_are_optional() {
        let completion = parse(br#"{"choices":[{"message":{"content":null}}]}"#).expect("valid answer");

        assert_eq!(completion.text, "");
        assert_eq!(completion.stop, Stop::Complete);
        assert_eq!(completion.model, None);
        assert_eq!(completion.usage, None);
    }

    #[test]
    fn chunked_content_joins_the_text_chunks() {
        let completion = parse(
            br#"{"choices":[{"message":{"content":[{"type":"thinking","thinking":[{"type":"text","text":"hidden"}]},{"type":"text","text":"a"},{"type":"reference","reference_ids":[1]},"odd",{"text":"untyped"},{"type":"text","text":null},{"type":"text","text":"b"}]},"finish_reason":"stop"}]}"#,
        )
        .expect("valid answer");

        assert_eq!(completion.text, "a\nb");
        assert_eq!(completion.stop, Stop::Complete);
    }

    #[test]
    fn content_of_another_type_is_invalid() {
        let Err(error) = parse(br#"{"choices":[{"message":{"content":{"text":"secret-value"}}}]}"#) else {
            panic!("object content must be invalid");
        };

        assert!(matches!(error, Error::InvalidResponse { .. }), "{error:?}");
        assert!(!error.to_string().contains("secret-value"));
    }

    #[test]
    fn content_filter_and_refusal_are_refused() {
        for (body, reason) in [
            (
                r#"{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}]}"#,
                "content filter",
            ),
            (
                r#"{"choices":[{"message":{"content":null,"refusal":"I cannot help."},"finish_reason":"stop"}]}"#,
                "refusal message",
            ),
            (
                r#"{"choices":[{"message":{"content":"partial","refusal":"I cannot help."},"finish_reason":"length"}]}"#,
                "refusal message",
            ),
        ] {
            let completion = parse(body.as_bytes()).expect("valid answer");

            assert_eq!(completion.stop, Stop::Refused(reason), "{body}");
        }
    }

    #[test]
    fn empty_refusal_is_not_a_refusal() {
        let completion = parse(br#"{"choices":[{"message":{"content":"hello","refusal":""},"finish_reason":"stop"}]}"#)
            .expect("valid answer");

        assert_eq!(completion.stop, Stop::Complete);
    }

    #[test]
    fn error_finish_reason_is_failed() {
        let completion =
            parse(br#"{"choices":[{"message":{"content":"partial"},"finish_reason":"error"}]}"#).expect("valid answer");

        assert!(matches!(completion.stop, Stop::Failed(_)), "{:?}", completion.stop);
    }
}
