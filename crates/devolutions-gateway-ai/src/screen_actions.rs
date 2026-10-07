//! Purpose: list what the user did in screenshots of a session, with [`AiClient::describe_screen_actions`].

use std::fmt;
use std::time::Duration;

use crate::client::{AiClient, Input, Prompt};
use crate::session_actions::{Action, DEFAULT_MAX_OUTPUT_TOKENS, parse_actions};
use crate::{Error, Response};

/// Version of the prompt of this purpose.
///
/// Results do not carry it: a caller that stores results should store it with them, so readers know which prompt
/// produced them.
/// Bump it whenever the prompt changes.
pub const PROMPT_VERSION: &str = "screen-actions-1";

const PROMPT: &str = r#"You see screenshots of a remote desktop session, in time order, and list what the user did.

Input: each screenshot comes after a label with its id and the elapsed time since the session started, in seconds. Example: `[F00012 t=34.5s]`. A label that ends with `context` marks a screenshot from before this part of the session: it only shows where the session was.

Output: JSON Lines only. Write one JSON object per line and nothing else: no prose, no Markdown, no code fences.
Each object has these fields:
- "frame": string. The id of the earliest screenshot that shows the action or its result, like "F00012". Never a context screenshot.
- "description": string. A short past-tense sentence naming the action, like "Reset the password of a user account". Say so when the screen shows that it failed.
- "object": string, optional. The main thing acted on, like a file path, host, service, user, or setting.
- "parameters": object, optional. Every value is a string. Important details, like the window, the exact command, or the new value.

Example output line:
{"frame":"F00012","description":"Reset the password of a user account","object":"David Moreau","parameters":{"Window":"Active Directory Users and Computers"}}

Rules:
- Write one line per meaningful user action, in time order, such as opening a tool, changing a setting, running a command, or confirming a dialog.
- Ignore noise, such as mouse movement, hovering, and screen redraws, and actions only visible in context screenshots.
- Report only what the screenshots show; never guess actions between them.
- Never copy passwords, secrets, or tokens. Write "[redacted]" instead.
- If the user did nothing, write only this line: {"noActions":true}"#;

/// One screenshot of a session.
#[derive(Clone, Copy)]
pub struct Screenshot<'a> {
    /// Short id the model cites, unique in the request, such as `F00012`.
    pub id: &'a str,
    /// Elapsed time since the start of the session.
    pub offset: Duration,
    /// The image, as PNG.
    pub png: &'a [u8],
    /// Whether the screenshot comes from before the part of the session being described, to show where it was; no
    /// action is ever found in it.
    pub context: bool,
}

// Screenshots hold session data, so only their id and size are printed.
impl fmt::Debug for Screenshot<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Screenshot")
            .field("id", &self.id)
            .field("offset", &self.offset)
            .field("png_len", &self.png.len())
            .field("context", &self.context)
            .finish()
    }
}

impl AiClient {
    /// Asks the model which actions the user performed in screenshots of a session, in time order.
    ///
    /// The model cites the screenshot that shows each action, and the action gets the time of that screenshot.
    pub fn describe_screen_actions<'a>(&'a self, screenshots: &'a [Screenshot<'a>]) -> DescribeScreenActions<'a> {
        DescribeScreenActions {
            client: self,
            screenshots,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
        }
    }
}

/// Request built by [`AiClient::describe_screen_actions`].
#[must_use = "the request is sent only by `send`"]
pub struct DescribeScreenActions<'a> {
    client: &'a AiClient,
    screenshots: &'a [Screenshot<'a>],
    max_output_tokens: u32,
}

impl fmt::Debug for DescribeScreenActions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DescribeScreenActions")
            .field("client", self.client)
            .field("screenshots", &self.screenshots.len())
            .field("max_output_tokens", &self.max_output_tokens)
            .finish()
    }
}

impl DescribeScreenActions<'_> {
    /// Upper bound of tokens in the answer; the default is 16000.
    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = max_output_tokens;
        self
    }

    /// Returns the actions in the order of the answer; the list is empty only when the model answered that the user did
    /// nothing.
    ///
    /// Invalid lines in the answer are skipped with a warning, and so are actions citing an unknown or context
    /// screenshot.
    /// The errors are the same as for
    /// [`DescribeSessionActions::send`](crate::session_actions::DescribeSessionActions::send): send fewer screenshots
    /// when the answer is [`Error::Truncated`].
    pub async fn send(self) -> Result<Response<Vec<Action>>, Error> {
        let labels = self
            .screenshots
            .iter()
            .map(|screenshot| {
                let context = if screenshot.context { " context" } else { "" };
                format!("[{} t={:.1}s{context}]", screenshot.id, screenshot.offset.as_secs_f64())
            })
            .collect::<Vec<_>>();

        let input = self
            .screenshots
            .iter()
            .zip(&labels)
            .flat_map(|(screenshot, label)| [Input::Text(label), Input::Png(screenshot.png)])
            .collect::<Vec<_>>();

        let prompt = Prompt {
            system: PROMPT,
            input: &input,
            max_output_tokens: self.max_output_tokens,
        };

        self.client.complete(&prompt).await?.try_map(|answer| {
            parse_actions(&answer, "frame", |frame| {
                self.screenshots
                    .iter()
                    .find(|screenshot| screenshot.id == frame && !screenshot.context)
                    .map(|screenshot| screenshot.offset)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_and_parser_agree_on_the_no_actions_line() {
        let line = PROMPT
            .lines()
            .last()
            .and_then(|rule| rule.split_once(": "))
            .map(|(_, line)| line);

        assert_eq!(line, Some(r#"{"noActions":true}"#));
    }

    #[test]
    fn prompt_asks_for_the_parsed_fields() {
        for field in [
            "\"frame\"",
            "description",
            "object",
            "parameters",
            "context",
            "noActions",
        ] {
            assert!(PROMPT.contains(field), "prompt is missing {field}");
        }
    }
}
