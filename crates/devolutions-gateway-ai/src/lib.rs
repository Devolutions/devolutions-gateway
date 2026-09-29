//! Purpose-level AI helpers for Devolutions Gateway.
//!
//! Each provider is reached through its own HTTP API: OpenAI chat completions (also spoken by Mistral and many
//! others) or Anthropic Messages. Only the few fields a single text completion needs are modeled.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

pub use reqwest;
pub use secrecy;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use url::Url;

/// Version of the prompt used by [`AiClient::describe_session_actions`].
///
/// Bump it whenever the session actions prompt changes, so readers of the results know which prompt produced them.
pub const PROMPT_VERSION: &str = "session-actions-1";

const SESSION_ACTIONS_PROMPT: &str = r#"You read the transcript of a remote session and list what the user did.

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
- If the user did nothing, write nothing."#;

const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 4_096;

const ANTHROPIC_VERSION: &str = "2023-06-01";

/// AI provider behind an [`AiClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// OpenAI chat completions; the default base URL is `https://api.openai.com/v1/`.
    OpenAi,
    /// Anthropic Messages; the default base URL is `https://api.anthropic.com/v1/`.
    Anthropic,
    /// Mistral chat completions; the default base URL is `https://api.mistral.ai/v1/`.
    Mistral,
    /// Any endpoint speaking OpenAI chat completions, such as Gemini; the base URL is required.
    OpenAiCompatible,
}

impl Provider {
    fn default_base_url(self) -> Option<&'static str> {
        match self {
            Self::OpenAi => Some("https://api.openai.com/v1/"),
            Self::Anthropic => Some("https://api.anthropic.com/v1/"),
            Self::Mistral => Some("https://api.mistral.ai/v1/"),
            Self::OpenAiCompatible => None,
        }
    }
}

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

/// Error returned by [`AiClientBuilder::build`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    #[error("AI provider is missing")]
    MissingProvider,
    #[error("AI model is missing")]
    MissingModel,
    #[error("API key is missing for AI provider {0:?}")]
    MissingApiKey(Provider),
    #[error("base URL is missing for AI provider {0:?}")]
    MissingBaseUrl(Provider),
    #[error("HTTP client is missing")]
    MissingHttpClient,
}

/// Error returned by [`DescribeSessionActions::send`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The provider request failed; `message` never contains the API key.
    ///
    /// `status` is the HTTP status of the provider answer, when there is one.
    /// The underlying error is not kept as `source()`, because its chain could expose the key unredacted.
    #[error("AI provider request failed: {message}")]
    Request { status: Option<u16>, message: String },
    /// The provider answered with a body that is not the expected format.
    #[error("AI provider answer is not valid: {reason}")]
    InvalidResponse { reason: String },
    /// The answer has lines, but none of them is a valid action.
    #[error("AI response has no valid action line ({invalid_lines} invalid lines)")]
    NoValidAction { invalid_lines: usize },
}

/// Builds an [`AiClient`]; every setting is checked by [`AiClientBuilder::build`].
#[derive(Debug, Default)]
pub struct AiClientBuilder {
    provider: Option<Provider>,
    model: Option<String>,
    api_key: Option<SecretString>,
    base_url: Option<Url>,
    http_client: Option<reqwest::Client>,
}

impl AiClientBuilder {
    #[must_use]
    pub fn provider(mut self, provider: Provider) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Model identifier, passed to the provider as is.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<SecretString>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Overrides the provider default; required for [`Provider::OpenAiCompatible`].
    #[must_use]
    pub fn base_url(mut self, base_url: Url) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Client used for every request, so the caller's proxy and TLS policy apply.
    #[must_use]
    pub fn http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn build(self) -> Result<AiClient, BuildError> {
        let provider = self.provider.ok_or(BuildError::MissingProvider)?;

        let model = self
            .model
            .filter(|model| !model.trim().is_empty())
            .ok_or(BuildError::MissingModel)?;

        let api_key = self
            .api_key
            .filter(|api_key| !api_key.expose_secret().is_empty())
            .ok_or(BuildError::MissingApiKey(provider))?;

        let base_url = resolve_base_url(provider, self.base_url)?;
        let http_client = self.http_client.ok_or(BuildError::MissingHttpClient)?;

        Ok(AiClient {
            provider,
            model,
            base_url,
            api_key,
            http_client,
        })
    }
}

fn resolve_base_url(provider: Provider, base_url: Option<Url>) -> Result<Url, BuildError> {
    match (base_url, provider.default_base_url()) {
        (Some(base_url), _) => Ok(base_url),
        (None, Some(default)) => Ok(Url::parse(default).expect("default base URLs are valid")),
        (None, None) => Err(BuildError::MissingBaseUrl(provider)),
    }
}

/// Runs purpose-level AI requests against one provider.
#[derive(Clone)]
pub struct AiClient {
    provider: Provider,
    model: String,
    base_url: Url,
    api_key: SecretString,
    http_client: reqwest::Client,
}

impl fmt::Debug for AiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiClient")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url.as_str())
            .finish_non_exhaustive()
    }
}

impl AiClient {
    pub fn builder() -> AiClientBuilder {
        AiClientBuilder::default()
    }

    /// Asks the model which actions the user performed in a session transcript.
    ///
    /// Each line of `input` must start with the elapsed time in seconds between square brackets, such as `[12.5] ls`.
    pub fn describe_session_actions<'a>(&'a self, input: &'a str) -> DescribeSessionActions<'a> {
        DescribeSessionActions {
            client: self,
            input,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
        }
    }

    async fn complete(&self, system: &str, input: &str, max_output_tokens: u32) -> Result<String, Error> {
        debug!(
            provider = ?self.provider,
            model = %self.model,
            base_url = %self.base_url,
            input_len = input.len(),
            max_output_tokens,
            "Send AI completion request"
        );

        let model = self.model.as_str();
        let api_key = self.api_key.expose_secret();

        let request = match self.provider {
            Provider::OpenAi | Provider::Mistral | Provider::OpenAiCompatible => {
                // OpenAI's newer models only accept `max_completion_tokens`; other servers only know `max_tokens`.
                let (max_completion_tokens, max_tokens) = match self.provider {
                    Provider::OpenAi => (Some(max_output_tokens), None),
                    _ => (None, Some(max_output_tokens)),
                };

                self.http_client
                    .post(self.endpoint("chat/completions"))
                    .bearer_auth(api_key)
                    .json(&ChatRequest {
                        model,
                        messages: [
                            ChatMessage {
                                role: "system",
                                content: system,
                            },
                            ChatMessage {
                                role: "user",
                                content: input,
                            },
                        ],
                        max_completion_tokens,
                        max_tokens,
                    })
            }
            Provider::Anthropic => self
                .http_client
                .post(self.endpoint("messages"))
                .header("x-api-key", api_key)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .json(&MessagesRequest {
                    model,
                    system,
                    messages: [ChatMessage {
                        role: "user",
                        content: input,
                    }],
                    max_tokens: max_output_tokens,
                }),
        };

        let response = request.send().await.map_err(|error| self.request_error(None, &error))?;

        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| self.request_error(Some(status.as_u16()), &error))?;

        if !status.is_success() {
            let message = serde_json::from_slice::<ProviderErrorBody>(&body)
                .map(|body| body.error.message)
                .unwrap_or_else(|_| status.to_string());

            return Err(Error::Request {
                status: Some(status.as_u16()),
                message: redact(message, api_key),
            });
        }

        let text = match self.provider {
            Provider::OpenAi | Provider::Mistral | Provider::OpenAiCompatible => {
                let response: ChatResponse = parse_response(&body)?;
                response
                    .choices
                    .into_iter()
                    .next()
                    .and_then(|choice| choice.message.content)
                    .unwrap_or_default()
            }
            Provider::Anthropic => {
                let response: MessagesResponse = parse_response(&body)?;
                response
                    .content
                    .into_iter()
                    .filter_map(|block| match block {
                        ContentBlock::Text { text } => Some(text),
                        ContentBlock::Other => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        };

        debug!(output_len = text.len(), "Received AI completion");

        Ok(text)
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}/{path}", self.base_url.as_str().trim_end_matches('/'))
    }

    fn request_error(&self, status: Option<u16>, error: &dyn std::error::Error) -> Error {
        request_error(status, error, self.api_key.expose_secret())
    }
}

/// Request built by [`AiClient::describe_session_actions`].
#[must_use = "the request is sent only by `send`"]
pub struct DescribeSessionActions<'a> {
    client: &'a AiClient,
    input: &'a str,
    max_output_tokens: u32,
}

// The transcript holds session data, so only its length is printed.
impl fmt::Debug for DescribeSessionActions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DescribeSessionActions")
            .field("client", self.client)
            .field("input_len", &self.input.len())
            .field("max_output_tokens", &self.max_output_tokens)
            .finish()
    }
}

impl DescribeSessionActions<'_> {
    /// Upper bound of tokens in the answer; the default is 4096.
    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = max_output_tokens;
        self
    }

    /// Invalid lines in the model answer are skipped with a warning.
    /// It is an error only when the answer has lines but none of them is a valid action.
    pub async fn send(self) -> Result<Vec<Action>, Error> {
        let answer = self
            .client
            .complete(SESSION_ACTIONS_PROMPT, self.input, self.max_output_tokens)
            .await?;
        parse_actions(&answer)
    }
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'static str,
    content: &'a str,
}

/// OpenAI chat completions request.
#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: [ChatMessage<'a>; 2],
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatAnswer,
}

#[derive(Deserialize)]
struct ChatAnswer {
    content: Option<String>,
}

/// Anthropic Messages request.
#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    system: &'a str,
    messages: [ChatMessage<'a>; 1],
    max_tokens: u32,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
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

/// Error body shared by OpenAI-style and Anthropic APIs.
#[derive(Deserialize)]
struct ProviderErrorBody {
    error: ProviderError,
}

#[derive(Deserialize)]
struct ProviderError {
    message: String,
}

// The reason never quotes the body, because the answer may contain session data.
fn parse_response<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|error| Error::InvalidResponse {
        reason: format!(
            "{:?} error at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
        ),
    })
}

fn request_error(status: Option<u16>, error: &dyn std::error::Error, api_key: &str) -> Error {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }

    Error::Request {
        status,
        message: redact(message, api_key),
    }
}

// Provider error bodies may echo the API key back.
fn redact(message: String, api_key: &str) -> String {
    if api_key.is_empty() {
        message
    } else {
        message.replace(api_key, "[REDACTED]")
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

    for (index, line) in answer.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with("```") {
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

    if actions.is_empty() && invalid_lines > 0 {
        return Err(Error::NoValidAction { invalid_lines });
    }

    Ok(actions)
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
    #![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

    use super::*;

    #[test]
    fn parses_valid_lines() {
        let answer = concat!(
            "{\"offsetSeconds\":1.5,\"description\":\"Listed files\",\"object\":\"/var/log\",\"parameters\":{\"Command\":\"ls\"}}\n",
            "\n",
            "{\"offsetSeconds\":3,\"description\":\"Opened a shell\"}\n",
        );

        let actions = parse_actions(answer).unwrap();

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

        let actions = parse_actions(answer).unwrap();

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].description, "Listed files");
    }

    #[test]
    fn empty_answer_means_no_action() {
        assert_eq!(parse_actions("").unwrap(), Vec::new());
        assert_eq!(parse_actions("\n```\n```\n").unwrap(), Vec::new());
    }

    #[test]
    fn answer_without_valid_line_is_an_error() {
        let error = parse_actions("not json\n{\"description\":\"no offset\"}\n").unwrap_err();

        assert!(matches!(error, Error::NoValidAction { invalid_lines: 2 }));
    }

    #[test]
    fn invalid_line_reason_does_not_quote_the_line() {
        let reason =
            parse_action_line("{\"offsetSeconds\":1,\"description\":\"secret-value\",\"parameters\":{\"a\":1}}")
                .unwrap_err();

        assert!(!reason.contains("secret-value"));
    }

    #[test]
    fn invalid_response_reason_does_not_quote_the_body() {
        let error = parse_response::<ChatResponse>(br#"{"choices":"secret-value"}"#)
            .err()
            .unwrap();

        assert!(matches!(error, Error::InvalidResponse { .. }));
        assert!(!error.to_string().contains("secret-value"));
    }

    #[test]
    fn prompt_asks_for_the_parsed_fields() {
        for field in ["offsetSeconds", "description", "object", "parameters", "JSON Lines"] {
            assert!(SESSION_ACTIONS_PROMPT.contains(field), "prompt is missing {field}");
        }
    }

    #[test]
    fn debug_redacts_api_key() {
        let builder = AiClient::builder()
            .provider(Provider::OpenAi)
            .model("gpt-test")
            .api_key("sk-very-secret");

        assert!(!format!("{builder:?}").contains("sk-very-secret"));
    }

    #[test]
    fn describe_session_actions_debug_hides_input() {
        let client = AiClient::builder()
            .provider(Provider::OpenAi)
            .model("gpt-test")
            .api_key("sk-very-secret")
            .http_client(reqwest::Client::new())
            .build()
            .unwrap();

        let debug = format!("{:?}", client.describe_session_actions("[1] secret-command"));

        assert!(!debug.contains("secret-command"));
        assert!(debug.contains("input_len: 18"));
    }

    #[test]
    fn default_base_urls() {
        for (provider, expected) in [
            (Provider::OpenAi, "https://api.openai.com/v1/"),
            (Provider::Anthropic, "https://api.anthropic.com/v1/"),
            (Provider::Mistral, "https://api.mistral.ai/v1/"),
        ] {
            assert_eq!(resolve_base_url(provider, None).unwrap().as_str(), expected);
        }

        assert!(matches!(
            resolve_base_url(Provider::OpenAiCompatible, None),
            Err(BuildError::MissingBaseUrl(Provider::OpenAiCompatible))
        ));
    }

    #[test]
    fn base_url_overrides_default() {
        let custom = Url::parse("https://proxy.example/anthropic/").unwrap();

        assert_eq!(
            resolve_base_url(Provider::Anthropic, Some(custom.clone())).unwrap(),
            custom
        );
    }

    #[test]
    fn error_message_redacts_api_key() {
        let error = std::io::Error::other("invalid key sk-very-secret provided");

        let error = request_error(Some(401), &error, "sk-very-secret");

        assert!(!error.to_string().contains("sk-very-secret"));
        assert!(!format!("{error:?}").contains("sk-very-secret"));
        assert!(error.to_string().contains("[REDACTED]"));
    }
}
