//! Purpose: list what the user did in a session transcript, with [`AiClient::describe_session_actions`].

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use tracing::warn;

use crate::client::{AiClient, Prompt};
use crate::{Error, Response};

/// Version of the prompt of this purpose.
///
/// Results do not carry it: a caller that stores results should store it with them, so readers know which prompt
/// produced them.
/// Bump it whenever the prompt changes.
pub const PROMPT_VERSION: &str = "session-actions-2";

const PROMPT: &str = r#"You read the transcript of a remote session and list what the user did.

Input: each transcript line starts with the elapsed time since the session started, in seconds, between square brackets. Example: `[12.5] ls -la`.

Output: JSON Lines only. Write one JSON object per line and nothing else: no prose, no Markdown, no code fences.
Each object has these fields:
- "offsetSeconds": number. Elapsed seconds when the action started, taken from the transcript.
- "description": string. A short past-tense sentence naming the action, like "Listed directory contents".
- "object": string, optional. The main thing acted on, like a file path, host, service, or account.
- "parameters": object, optional. Every value is a string. Important details, like the exact command.

Example output line:
{"offsetSeconds":12.5,"description":"Listed directory contents","object":"/var/log","parameters":{"Command":"ls -la /var/log"}}

Rules:
- Write one line per meaningful user action, in time order. Merge the keystrokes of one command into one action.
- Ignore noise, such as prompt redraws, cursor movement, and output that has no user action.
- Never copy passwords, secrets, or tokens. Write "[redacted]" instead.
- If the user did nothing, write only this line: {"noActions":true}"#;

/// The same limit DVLS and RDM use for Claude. Reasoning models count their reasoning in it, so it cannot be small.
const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 16_000;

/// One user action found in a session transcript.
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    /// Elapsed time since the start of the session, as reported by the model.
    pub offset: Duration,
    /// Short past-tense sentence naming the action, never empty.
    pub description: String,
    /// Main thing acted on, such as a file path, host, service, or account; never an empty string.
    pub object: Option<String>,
    /// Important details, such as the exact command, keyed by name.
    pub parameters: BTreeMap<String, String>,
}

impl AiClient {
    /// Asks the model which actions the user performed in a session transcript.
    ///
    /// Each line of `transcript` must start with the elapsed time in seconds between square brackets, such as
    /// `[12.5] ls`.
    pub fn describe_session_actions<'a>(&'a self, transcript: &'a str) -> DescribeSessionActions<'a> {
        DescribeSessionActions {
            client: self,
            transcript,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
        }
    }
}

/// Request built by [`AiClient::describe_session_actions`].
#[must_use = "the request is sent only by `send`"]
pub struct DescribeSessionActions<'a> {
    client: &'a AiClient,
    transcript: &'a str,
    max_output_tokens: u32,
}

// The transcript holds session data, so only its length is printed.
impl fmt::Debug for DescribeSessionActions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DescribeSessionActions")
            .field("client", self.client)
            .field("transcript_len", &self.transcript.len())
            .field("max_output_tokens", &self.max_output_tokens)
            .finish()
    }
}

impl DescribeSessionActions<'_> {
    /// Upper bound of tokens in the answer; the default is 16000.
    ///
    /// Some models accept less, such as older Claude models, and the provider then refuses the request: lower it for
    /// them.
    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = max_output_tokens;
        self
    }

    /// Returns the actions in the order of the answer; the list is empty only when the model answered that the user did
    /// nothing.
    ///
    /// Invalid lines in the answer are skipped with a warning.
    /// The answer is [`Error::InvalidOutput`] when it has no valid action and does not say that the user did nothing,
    /// such as an empty answer.
    /// An answer cut short by the output token limit or the context window is [`Error::Truncated`]: send a shorter
    /// transcript instead.
    /// A refusal of the provider is [`Error::Refused`], never an empty list.
    pub async fn send(self) -> Result<Response<Vec<Action>>, Error> {
        let prompt = Prompt {
            system: PROMPT,
            input: self.transcript,
            max_output_tokens: self.max_output_tokens,
        };

        self.client
            .complete(&prompt)
            .await?
            .try_map(|answer| parse_actions(&answer))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActionLine {
    offset_seconds: f64,
    description: String,
    #[serde(default)]
    object: Option<String>,
    #[serde(default)]
    parameters: BTreeMap<String, String>,
}

fn parse_actions(answer: &str) -> Result<Vec<Action>, Error> {
    let mut actions = Vec::new();
    let mut invalid_lines = 0usize;
    let mut no_actions = false;

    for (index, line) in answer.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with("```") {
            continue;
        }

        if is_no_actions_line(line) {
            no_actions = true;
            continue;
        }

        match parse_action_line(line) {
            Ok(action) => actions.push(action),
            Err(reason) => {
                invalid_lines += 1;
                warn!(line_number = index + 1, %reason, "Skipped invalid AI action line");
            }
        }
    }

    if !actions.is_empty() {
        if no_actions {
            warn!(
                actions = actions.len(),
                "AI answer has actions and says that the user did nothing"
            );
        }

        return Ok(actions);
    }

    if no_actions {
        return Ok(actions);
    }

    let reason = if invalid_lines > 0 {
        format!("no valid action line, {invalid_lines} invalid lines")
    } else {
        "empty answer, without the no-actions line".to_owned()
    };

    Err(Error::InvalidOutput { reason })
}

/// Tells whether `line` is the `{"noActions":true}` line the prompt asks for when the user did nothing, so that an empty
/// answer is never read as an idle session.
fn is_no_actions_line(line: &str) -> bool {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct NoActions {
        no_actions: bool,
    }

    serde_json::from_str::<NoActions>(line).is_ok_and(|line| line.no_actions)
}

// The reason never quotes the line, because the line may contain session data.
fn parse_action_line(line: &str) -> Result<Action, String> {
    let parsed: ActionLine = serde_json::from_str(line)
        .map_err(|error| format!("{:?} error at column {}", error.classify(), error.column()))?;

    let offset = Duration::try_from_secs_f64(parsed.offset_seconds).map_err(|_| "invalid offsetSeconds".to_owned())?;

    let description = parsed.description.trim();
    if description.is_empty() {
        return Err("empty description".to_owned());
    }

    Ok(Action {
        offset,
        description: description.to_owned(),
        object: parsed
            .object
            .map(|object| object.trim().to_owned())
            .filter(|object| !object.is_empty()),
        parameters: parsed.parameters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_lines() {
        let answer = concat!(
            "{\"offsetSeconds\":1.5,\"description\":\"Listed files\",\"object\":\"/var/log\",\"parameters\":{\"Command\":\"ls\"}}\n",
            "\n",
            "{\"offsetSeconds\":3,\"description\":\"Opened a shell\"}\n",
        );

        let actions = parse_actions(answer).expect("valid answer");

        assert_eq!(
            actions,
            vec![
                Action {
                    offset: Duration::from_millis(1500),
                    description: "Listed files".to_owned(),
                    object: Some("/var/log".to_owned()),
                    parameters: BTreeMap::from([("Command".to_owned(), "ls".to_owned())]),
                },
                Action {
                    offset: Duration::from_secs(3),
                    description: "Opened a shell".to_owned(),
                    object: None,
                    parameters: BTreeMap::new(),
                },
            ]
        );
    }

    #[test]
    fn skips_code_fences_and_invalid_lines() {
        let answer = concat!(
            "```jsonl\n",
            "{\"offsetSeconds\":1,\"description\":\"Listed files\"}\n",
            "Here are the actions:\n",
            "{\"offsetSeconds\":-1,\"description\":\"Negative offset\"}\n",
            "{\"offsetSeconds\":2,\"description\":\"  \"}\n",
            "{\"offsetSeconds\":2,\"description\":\"Numeric parameter\",\"parameters\":{\"Count\":5}}\n",
            "```\n",
        );

        let actions = parse_actions(answer).expect("one valid line");

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].description, "Listed files");
    }

    #[test]
    fn no_actions_line_means_no_action() {
        for answer in [
            "{\"noActions\":true}",
            "\n```jsonl\n{\"noActions\":true}\n```\n",
            " { \"noActions\" : true } ",
        ] {
            assert_eq!(parse_actions(answer).expect("no actions"), Vec::new(), "{answer:?}");
        }
    }

    #[test]
    fn empty_answer_is_invalid_output() {
        for answer in ["", "\n```\n```\n"] {
            let error = parse_actions(answer).expect_err("empty answer");

            assert!(matches!(error, Error::InvalidOutput { .. }), "{answer:?}: {error:?}");
        }
    }

    #[test]
    fn other_no_actions_lines_are_invalid() {
        for line in [
            "{\"noActions\":false}",
            "{\"noActions\":true,\"extra\":1}",
            "{\"noActions\":\"yes\"}",
        ] {
            let error = parse_actions(line).expect_err("not the no-actions line");

            assert!(error.to_string().contains("1 invalid lines"), "{line}: {error}");
        }
    }

    #[test]
    fn actions_win_over_the_no_actions_line() {
        let answer = "{\"noActions\":true}\n{\"offsetSeconds\":1,\"description\":\"Listed files\"}\n";

        let actions = parse_actions(answer).expect("one action");

        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn prompt_and_parser_agree_on_the_no_actions_line() {
        let line = PROMPT
            .lines()
            .last()
            .and_then(|rule| rule.split_once(": "))
            .map(|(_, line)| line);

        assert_eq!(line, Some(r#"{"noActions":true}"#));
        assert!(is_no_actions_line(r#"{"noActions":true}"#));
    }

    #[test]
    fn answer_without_valid_line_is_invalid_output() {
        let error = parse_actions("not json\n{\"description\":\"no offset\"}\n").expect_err("no valid line");

        assert!(matches!(error, Error::InvalidOutput { .. }), "{error:?}");
        assert!(error.to_string().contains("2 invalid lines"), "{error}");
    }

    #[test]
    fn invalid_line_reason_does_not_quote_the_line() {
        let reason =
            parse_action_line("{\"offsetSeconds\":1,\"description\":\"secret-value\",\"parameters\":{\"a\":1}}")
                .expect_err("numeric parameter");

        assert!(!reason.contains("secret-value"));
    }

    #[test]
    fn prompt_asks_for_the_parsed_fields() {
        for field in [
            "offsetSeconds",
            "description",
            "object",
            "parameters",
            "JSON Lines",
            "noActions",
        ] {
            assert!(PROMPT.contains(field), "prompt is missing {field}");
        }
    }

    #[test]
    fn request_debug_hides_the_transcript() {
        let client = AiClient::builder()
            .provider(crate::Provider::OpenAi)
            .model("gpt-test")
            .api_key("sk-very-secret")
            .http_client(reqwest::Client::new())
            .build()
            .expect("valid settings");

        let debug = format!("{:?}", client.describe_session_actions("[1] secret-command"));

        assert!(!debug.contains("secret-command"));
        assert!(!debug.contains("sk-very-secret"));
        assert!(debug.contains("transcript_len: 18"));
    }
}
