//! Anthropic Messages.

use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use super::{Completion, Content, Message, Stop, base64, endpoint, parse_body, usage};
use crate::Error;
use crate::client::{Input, Prompt};

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
                content: Content::of(prompt.input, |input| match input {
                    Input::Text(text) => serde_json::json!({ "type": "text", "text": text }),
                    Input::Png(png) => serde_json::json!({
                        "type": "image",
                        "source": { "type": "base64", "media_type": "image/png", "data": base64(png) },
                    }),
                }),
            }],
            max_tokens: prompt.max_output_tokens,
        })
}

pub(crate) fn parse(body: &[u8]) -> Result<Completion, Error> {
    let response: MessagesResponse = parse_body(body)?;

    // Without a text block, such as in an empty `end_turn` answer, the text is empty.
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
        // Some Anthropic-compatible servers send no stop reason.
        Some("end_turn" | "stop_sequence") | None => Stop::Complete,
        // A full context window cuts the answer like the output token limit.
        Some("max_tokens" | "model_context_window_exceeded") => Stop::Truncated,
        Some("refusal") => Stop::Refused("stop reason refusal"),
        // Such as `tool_use` or `pause_turn`, which a request without tools should never get.
        Some(stop_reason) => {
            warn!(stop_reason, "Unexpected AI stop reason");
            Stop::Failed("unexpected stop reason")
        }
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
    fn end_turn_stop_sequence_and_no_stop_reason_are_complete() {
        for stop_reason in [
            r#","stop_reason":"end_turn""#,
            r#","stop_reason":"stop_sequence""#,
            r#","stop_reason":null"#,
            "",
        ] {
            let body = format!(r#"{{"content":[{{"type":"text","text":"answer"}}]{stop_reason}}}"#);

            let completion = parse(body.as_bytes()).expect("valid answer");

            assert_eq!(completion.text, "answer", "{body}");
            assert_eq!(completion.stop, Stop::Complete, "{body}");
        }
    }

    #[test]
    fn answer_without_text_block_is_empty() {
        for content in ["[]", r#"[{"type":"thinking","thinking":"hidden"}]"#] {
            let body = format!(r#"{{"content":{content},"stop_reason":"end_turn"}}"#);

            let completion = parse(body.as_bytes()).expect("valid answer");

            assert_eq!(completion.text, "", "{body}");
            assert_eq!(completion.stop, Stop::Complete, "{body}");
        }
    }

    #[test]
    fn other_stop_reasons_are_failed() {
        for stop_reason in ["tool_use", "pause_turn", "something_new"] {
            let body = format!(r#"{{"content":[{{"type":"text","text":"answer"}}],"stop_reason":"{stop_reason}"}}"#);

            let completion = parse(body.as_bytes()).expect("valid answer");

            assert_eq!(completion.stop, Stop::Failed("unexpected stop reason"), "{stop_reason}");
        }
    }
}
