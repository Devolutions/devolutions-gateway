//! Anthropic Messages.

use serde::{Deserialize, Serialize};
use url::Url;

use super::{Completion, Message, endpoint, parse_body, usage};
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

    Ok(Completion {
        text,
        truncated: response.stop_reason.as_deref() == Some("max_tokens"),
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
        assert!(!completion.truncated);
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
    fn max_tokens_stop_reason_is_truncated() {
        let completion = parse(br#"{"content":[{"type":"text","text":"partial"}],"stop_reason":"max_tokens"}"#)
            .expect("valid answer");

        assert!(completion.truncated);
        assert_eq!(completion.usage, None);
    }
}
