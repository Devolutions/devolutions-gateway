//! Purpose: summarize what the user did in a session, from its actions, with [`AiClient::summarize_session`].

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use crate::client::{AiClient, Input, Prompt, with_language};
use crate::session_actions::{Action, DEFAULT_MAX_OUTPUT_TOKENS};
use crate::{Error, Response};

/// Version of the prompt of this purpose.
///
/// Results do not carry it: a caller that stores results should store it with them, so readers know which prompt
/// produced them.
/// Bump it whenever the prompt changes.
pub const PROMPT_VERSION: &str = "session-summary-1";

const PROMPT: &str = r#"You summarize what the user did in a remote session, from the list of their actions.

Input: JSON Lines, one action per line, in time order. Each action has "elapsedSeconds", the time since the session started, and "description", a short sentence naming the action. It may have "object", the main thing acted on, and "parameters", important details.

Output: plain text only: no Markdown, no JSON, no lists. Write a short summary of a few sentences, five at most, saying what the user did and on what.

Rules:
- Name the main hosts, services, accounts, files, or settings the user acted on.
- Report only what the actions show; never guess.
- Never copy passwords, secrets, or tokens. Write "[redacted]" instead."#;

fn language_rule(language: &str) -> String {
    format!("- Write the summary in the language of the BCP 47 tag `{language}`; keep \"[redacted]\" as it is.")
}

impl AiClient {
    /// Asks the model for a short plain-text summary of what the user did in a session, given the actions found in it,
    /// such as by [`AiClient::describe_session_actions`].
    ///
    /// With no action there is nothing to summarize, so callers should not ask.
    pub fn summarize_session<'a>(&'a self, actions: &'a [Action]) -> SummarizeSession<'a> {
        SummarizeSession {
            client: self,
            actions,
            language: None,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
        }
    }
}

/// Request built by [`AiClient::summarize_session`].
#[must_use = "the request is sent only by `send`"]
pub struct SummarizeSession<'a> {
    client: &'a AiClient,
    actions: &'a [Action],
    language: Option<&'a str>,
    max_output_tokens: u32,
}

// The actions hold session data, so only their count is printed.
impl fmt::Debug for SummarizeSession<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SummarizeSession")
            .field("client", self.client)
            .field("actions", &self.actions.len())
            .field("language", &self.language)
            .field("max_output_tokens", &self.max_output_tokens)
            .finish()
    }
}

impl<'a> SummarizeSession<'a> {
    /// Language of the session, as a BCP 47 tag such as `fr-CA`: the summary is written in it.
    ///
    /// A value that is not a tag is ignored with a warning.
    pub fn language(mut self, language: &'a str) -> Self {
        self.language = Some(language);
        self
    }

    /// Upper bound of tokens in the answer; the default is 16000.
    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = max_output_tokens;
        self
    }

    /// Returns the summary, trimmed and never empty.
    ///
    /// An empty answer is [`Error::InvalidOutput`]; the other errors are the same as for
    /// [`DescribeSessionActions::send`](crate::session_actions::DescribeSessionActions::send).
    pub async fn send(self) -> Result<Response<String>, Error> {
        let input = actions_as_lines(self.actions);
        let system = with_language(PROMPT, self.language, language_rule);

        let prompt = Prompt {
            system: &system,
            input: &[Input::Text(&input)],
            max_output_tokens: self.max_output_tokens,
        };

        self.client.complete(&prompt).await?.try_map(|answer| {
            let summary = answer.trim();

            if summary.is_empty() {
                return Err(Error::InvalidOutput {
                    reason: "empty summary".to_owned(),
                });
            }

            Ok(summary.to_owned())
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionLine<'a> {
    elapsed_seconds: f64,
    description: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    object: Option<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    parameters: &'a BTreeMap<String, String>,
}

fn actions_as_lines(actions: &[Action]) -> String {
    let mut lines = String::new();

    for action in actions {
        let line = serde_json::to_string(&ActionLine {
            // Tenths of a second are enough to tell the order, and keep the input short.
            elapsed_seconds: (action.offset.as_secs_f64() * 10.0).round() / 10.0,
            description: &action.description,
            object: action.object.as_deref(),
            parameters: &action.parameters,
        })
        .expect("strings and numbers always serialize to JSON");

        lines.push_str(&line);
        lines.push('\n');
    }

    lines
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn actions_are_sent_as_json_lines() {
        let actions = [
            Action {
                offset: Duration::from_millis(1540),
                description: "Listed files".to_owned(),
                object: Some("/var/log".to_owned()),
                parameters: BTreeMap::from([("Command".to_owned(), "ls".to_owned())]),
            },
            Action {
                offset: Duration::from_secs(62),
                description: "Closed the shell".to_owned(),
                object: None,
                parameters: BTreeMap::new(),
            },
        ];

        assert_eq!(
            actions_as_lines(&actions),
            concat!(
                "{\"elapsedSeconds\":1.5,\"description\":\"Listed files\",\"object\":\"/var/log\",\"parameters\":{\"Command\":\"ls\"}}\n",
                "{\"elapsedSeconds\":62.0,\"description\":\"Closed the shell\"}\n",
            )
        );
    }

    #[test]
    fn prompt_names_the_input_fields() {
        for field in [
            "\"elapsedSeconds\"",
            "\"description\"",
            "\"object\"",
            "\"parameters\"",
            "[redacted]",
        ] {
            assert!(PROMPT.contains(field), "prompt is missing {field}");
        }
    }
}
