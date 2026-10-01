//! Anthropic Messages.

use serde::{Deserialize, Serialize};
use url::Url;

use super::{Completion, Message, Stop, endpoint, parse_body, usage};
use crate::Error;
use crate::client::Prompt;

const VERSION: &str = "2023-06-01";

pub(crate) fn request(
    http_client: &reqwest::Client,
    base_url: &Url,
    api_key: &str,
    model: &str,
    prompt: &Prompt<'_>,
) -> reqwest::RequestBuilder {
    http_client
        .post(endpoint(base_url, "messages"))
        .header("x-api-key", api_key)
        .header("anthropic-version", VERSION)
        .json(&MessagesRequest {
            model,
            system: prompt.system,
            messages: [Message {
                role: "user",
                content: prompt.input,
            }],
            max_tokens: prompt.max_output_tokens,
        })
}

pub(crate) fn parse(body: &[u8]) -> Result<Completion, Error> {
    let response: MessagesResponse = parse_body(body)?;

    let text = response
        .content
        .into_iter()
        .filter_map(|block| match block {
            ContentBlock::Text { text } => Some(text),
            ContentBlock::Other => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    let stop = match response.stop_reason.as_deref() {
        // A full context window cuts the answer like the output token limit.
        Some("max_tokens" | "model_context_window_exceeded") => Stop::Truncated,
        Some("refusal") => Stop::Refused("stop reason refusal"),
        _ => Stop::Complete,
    };

    Ok(Completion {
        text,
        stop,
        model: response.model,
        usage: response
            .usage
            .and_then(|counts| usage(counts.input_tokens, counts.output_tokens)),
    })
}

#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    system: &'a str,
    messages: [Message<'a>; 1],
    max_tokens: u32,
}

#[derive(Deserialize)]
struct MessagesResponse {
    model: Option<String>,
    content: Vec<ContentBlock>,
    stop_reason: Option<String>,
    usage: Option<MessagesUsage>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ContentBlock {
    Text {
        text: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct MessagesUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Usage;

    #[test]
    fn parses_text_blocks_model_and_usage() {
        let completion = parse(
            br#"{"model":"claude-test-20260101","content":[{"type":"text","text":"a"},{"type":"thinking","thinking":"hidden"},{"type":"text","text":"b"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":20}}"#,
        )
        .expect("valid answer");

        assert_eq!(completion.text, "a\nb");
        assert_eq!(completion.stop, Stop::Complete);
        assert_eq!(completion.model.as_deref(), Some("claude-test-20260101"));
        assert_eq!(
            completion.usage,
            Some(Usage {
                input_tokens: 10,
                output_tokens: 20
            })
        );
    }

    #[test]
    fn max_tokens_and_full_context_window_are_truncated() {
        for stop_reason in ["max_tokens", "model_context_window_exceeded"] {
            let body = format!(r#"{{"content":[{{"type":"text","text":"partial"}}],"stop_reason":"{stop_reason}"}}"#);

            let completion = parse(body.as_bytes()).expect("valid answer");

            assert_eq!(completion.stop, Stop::Truncated, "{stop_reason}");
            assert_eq!(completion.usage, None);
        }
    }

    #[test]
    fn refusal_stop_reason_is_refused() {
        let completion = parse(br#"{"content":[{"type":"text","text":"I cannot help."}],"stop_reason":"refusal"}"#)
            .expect("valid answer");

        assert_eq!(completion.stop, Stop::Refused("stop reason refusal"));
    }

    #[test]
    fn other_stop_reasons_are_complete() {
        for stop_reason in [r#""end_turn""#, r#""stop_sequence""#, r#""pause_turn""#, "null"] {
            let body = format!(r#"{{"content":[{{"type":"text","text":"answer"}}],"stop_reason":{stop_reason}}}"#);

            let completion = parse(body.as_bytes()).expect("valid answer");

            assert_eq!(completion.stop, Stop::Complete, "{stop_reason}");
        }
    }
}
