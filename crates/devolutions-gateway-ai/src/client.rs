use std::fmt;
use std::time::Duration;

use reqwest::header::HeaderValue;
use secrecy::{ExposeSecret as _, SecretString};
use tracing::debug;
use url::Url;

use crate::wire::{Api, Stop, anthropic, openai};
use crate::{Error, Response, error};

/// Default of [`AiClientBuilder::request_timeout`].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Largest answer body read from a provider.
///
/// A 16000-token answer, the default output limit of session actions, is a few hundred KB of JSON, so the limit leaves
/// ample room while keeping a faulty or hostile endpoint from filling the memory of Gateway.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// AI provider behind an [`AiClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// OpenAI chat completions; the default base URL is `https://api.openai.com/v1/`.
    ///
    /// Requests are sent with `"store": false`, so OpenAI does not keep them as stored completions.
    OpenAi,
    /// Anthropic Messages; the default base URL is `https://api.anthropic.com/v1/`.
    Anthropic,
    /// Mistral chat completions; the default base URL is `https://api.mistral.ai/v1/`.
    Mistral,
    /// Google Gemini through its OpenAI-compatible endpoint; the default base URL is
    /// `https://generativelanguage.googleapis.com/v1beta/openai/`.
    Gemini,
    /// Any other endpoint speaking OpenAI chat completions, such as a self-hosted model server; the base URL is required.
    OpenAiCompatible,
}

impl Provider {
    /// Base URL used when the builder sets none; [`Provider::OpenAiCompatible`] has none.
    pub fn default_base_url(self) -> Option<Url> {
        let url = match self {
            Self::OpenAi => "https://api.openai.com/v1/",
            Self::Anthropic => "https://api.anthropic.com/v1/",
            Self::Mistral => "https://api.mistral.ai/v1/",
            Self::Gemini => "https://generativelanguage.googleapis.com/v1beta/openai/",
            Self::OpenAiCompatible => return None,
        };

        Some(Url::parse(url).expect("default base URLs are valid"))
    }

    fn api(self) -> Api {
        match self {
            Self::OpenAi => Api::OpenAiChat(openai::Dialect::OpenAi),
            Self::Mistral | Self::Gemini | Self::OpenAiCompatible => Api::OpenAiChat(openai::Dialect::Other),
            Self::Anthropic => Api::AnthropicMessages,
        }
    }
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
    /// The API key cannot be sent in an HTTP header, such as a key holding a line break.
    #[error("API key is not a valid HTTP header value")]
    InvalidApiKey,
    #[error("base URL is missing for AI provider {0:?}")]
    MissingBaseUrl(Provider),
    /// The base URL is not http or https, or has a query or a fragment, so the API paths cannot be appended to it.
    #[error("base URL must be http or https, without query or fragment")]
    UnsupportedBaseUrl,
    #[error("HTTP client is missing")]
    MissingHttpClient,
}

/// Builds an [`AiClient`]; every setting is checked by [`AiClientBuilder::build`].
#[derive(Debug, Default)]
pub struct AiClientBuilder {
    provider: Option<Provider>,
    model: Option<String>,
    api_key: Option<SecretString>,
    base_url: Option<Url>,
    http_client: Option<reqwest::Client>,
    request_timeout: Option<Duration>,
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

    /// Overrides [`Provider::default_base_url`]; required for [`Provider::OpenAiCompatible`].
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

    /// Longest time one request may take, answer included; the default is [`DEFAULT_REQUEST_TIMEOUT`].
    ///
    /// Requests are not streamed, so it must leave the model time to write its whole answer.
    #[must_use]
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = Some(request_timeout);
        self
    }

    /// Checks the settings that can be checked without calling the provider.
    ///
    /// A model the provider does not know, a wrong API key, or an endpoint that cannot be reached still makes the
    /// requests fail.
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

        if HeaderValue::from_str(api_key.expose_secret()).is_err() {
            return Err(BuildError::InvalidApiKey);
        }

        let base_url = resolve_base_url(provider, self.base_url)?;
        let http_client = self.http_client.ok_or(BuildError::MissingHttpClient)?;

        Ok(AiClient {
            provider,
            model,
            base_url,
            api_key,
            http_client,
            request_timeout: self.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        })
    }
}

fn resolve_base_url(provider: Provider, base_url: Option<Url>) -> Result<Url, BuildError> {
    let base_url = base_url
        .or_else(|| provider.default_base_url())
        .ok_or(BuildError::MissingBaseUrl(provider))?;

    if !matches!(base_url.scheme(), "http" | "https") || base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(BuildError::UnsupportedBaseUrl);
    }

    Ok(base_url)
}

/// Sends the requests of every purpose to one AI provider.
#[derive(Clone)]
pub struct AiClient {
    provider: Provider,
    model: String,
    base_url: Url,
    api_key: SecretString,
    http_client: reqwest::Client,
    request_timeout: Duration,
}

impl fmt::Debug for AiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiClient")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url.as_str())
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

/// Text completion request; a purpose is defined by its prompt and the parser of the answer.
pub(crate) struct Prompt<'a> {
    /// Instructions of the purpose.
    pub(crate) system: &'a str,
    /// Data the purpose works on, such as a session transcript or screenshots, in order.
    pub(crate) input: &'a [Input<'a>],
    pub(crate) max_output_tokens: u32,
}

/// Part of the data a purpose works on.
#[derive(Clone, Copy)]
pub(crate) enum Input<'a> {
    Text(&'a str),
    /// A PNG image.
    Png(&'a [u8]),
}

impl AiClient {
    pub fn builder() -> AiClientBuilder {
        AiClientBuilder::default()
    }

    /// Model requested from the provider.
    pub(crate) fn model(&self) -> &str {
        &self.model
    }

    /// Sends one completion request and returns the text of the answer.
    ///
    /// An answer cut short by the output token limit or the context window is [`Error::Truncated`], because no purpose
    /// can use a partial answer.
    /// A refusal is [`Error::Refused`], so that no purpose reads it as an empty answer.
    /// An answer larger than [`MAX_RESPONSE_BYTES`], without a choice or content, or that ended for another reason is
    /// [`Error::InvalidResponse`].
    /// The `<think>` blocks some models write at the start of their answer are removed.
    pub(crate) async fn complete(&self, prompt: &Prompt<'_>) -> Result<Response<String>, Error> {
        debug!(
            provider = ?self.provider,
            model = %self.model,
            input_len = prompt
                .input
                .iter()
                .map(|input| match input {
                    Input::Text(text) => text.len(),
                    Input::Png(_) => 0,
                })
                .sum::<usize>(),
            images = prompt.input.iter().filter(|input| matches!(input, Input::Png(_))).count(),
            max_output_tokens = prompt.max_output_tokens,
            "Send AI completion request"
        );

        let api = self.provider.api();
        let api_key = self.api_key.expose_secret();

        let request = match api {
            Api::OpenAiChat(dialect) => {
                openai::request(&self.http_client, &self.base_url, api_key, &self.model, prompt, dialect)
            }
            Api::AnthropicMessages => {
                anthropic::request(&self.http_client, &self.base_url, api_key, &self.model, prompt)
            }
        };

        let response = request
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(|error| error::transport(error, api_key))?;

        let status = response.status();
        let retry_after = error::retry_after(response.headers());
        let body = read_body(response)
            .await
            .map_err(|error| error::transport(error, api_key))?;

        if !status.is_success() {
            // An error body over the limit is not parsed, so the error holds the reason phrase of the status.
            return Err(error::status(
                status,
                retry_after,
                body.as_deref().unwrap_or_default(),
                api_key,
            ));
        }

        let Some(body) = body else {
            return Err(Error::InvalidResponse {
                reason: format!("answer is larger than {MAX_RESPONSE_BYTES} bytes"),
            });
        };

        let completion = match api {
            Api::OpenAiChat(_) => openai::parse(&body)?,
            Api::AnthropicMessages => anthropic::parse(&body)?,
        };

        let text = strip_think_blocks(completion.text);

        debug!(
            output_len = text.len(),
            stop = ?completion.stop,
            model = ?completion.model,
            usage = ?completion.usage,
            "Received AI completion"
        );

        match completion.stop {
            Stop::Complete => Ok(Response {
                output: text,
                model: completion.model,
                usage: completion.usage,
            }),
            Stop::Truncated => Err(Error::Truncated {
                usage: completion.usage,
            }),
            Stop::Refused(reason) => Err(Error::Refused {
                reason: reason.to_owned(),
            }),
            Stop::Failed(reason) => Err(Error::InvalidResponse {
                reason: reason.to_owned(),
            }),
        }
    }
}

/// Reads the body of an answer, or returns `None` as soon as it is larger than [`MAX_RESPONSE_BYTES`].
///
/// A body whose `Content-Length` is over the limit is not read at all.
async fn read_body(mut response: reqwest::Response) -> reqwest::Result<Option<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Ok(None);
    }

    let mut body = Vec::new();

    // INVARIANT: body.len() <= MAX_RESPONSE_BYTES
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Ok(None);
        }

        body.extend_from_slice(&chunk);
    }

    Ok(Some(body))
}

/// Removes the `<think>…</think>` blocks that some models write before their answer; an unclosed block runs to the end.
///
/// Only blocks at the start of the answer are removed, so tag text inside the answer, such as in a command, is kept.
fn strip_think_blocks(mut text: String) -> String {
    const OPEN: &str = "<think>";
    const CLOSE: &str = "</think>";

    let mut rest = text.as_str();

    while let Some(inside) = strip_prefix_ignore_ascii_case(rest.trim_start(), OPEN) {
        rest = find_ignore_ascii_case(inside, CLOSE).map_or("", |close| &inside[close + CLOSE.len()..]);
    }

    let removed = text.len() - rest.len();
    text.replace_range(..removed, "");
    text
}

fn strip_prefix_ignore_ascii_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let (head, tail) = text.split_at_checked(prefix.len())?;

    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

// The needle is ASCII, so a match always starts on a character boundary.
fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_debug_hides_the_api_key() {
        let builder = AiClient::builder()
            .provider(Provider::OpenAi)
            .model("gpt-test")
            .api_key("sk-very-secret");

        assert!(!format!("{builder:?}").contains("sk-very-secret"));
    }

    #[test]
    fn default_base_urls() {
        for (provider, expected) in [
            (Provider::OpenAi, "https://api.openai.com/v1/"),
            (Provider::Anthropic, "https://api.anthropic.com/v1/"),
            (Provider::Mistral, "https://api.mistral.ai/v1/"),
            (
                Provider::Gemini,
                "https://generativelanguage.googleapis.com/v1beta/openai/",
            ),
        ] {
            let resolved = resolve_base_url(provider, None).expect("default base URL");
            assert_eq!(resolved.as_str(), expected);
        }

        assert!(matches!(
            resolve_base_url(Provider::OpenAiCompatible, None),
            Err(BuildError::MissingBaseUrl(Provider::OpenAiCompatible))
        ));
    }

    #[test]
    fn leading_think_blocks_are_removed() {
        for (text, expected) in [
            ("answer", "answer"),
            ("  answer", "  answer"),
            ("<think>plan</think>answer", "answer"),
            ("<THINK>\nplan\n</Think>\nanswer\n", "\nanswer\n"),
            (" \n<think>1</think>\n<think>2</think>answer", "answer"),
            ("<think>plan", ""),
            ("<think>1</think><think>2", ""),
            (
                "<think>plan</think>{\"parameters\":{\"Command\":\"<think>x</think>\"}}",
                "{\"parameters\":{\"Command\":\"<think>x</think>\"}}",
            ),
        ] {
            assert_eq!(strip_think_blocks(text.to_owned()), expected, "{text:?}");
        }
    }

    #[test]
    fn think_tags_after_the_start_are_kept() {
        for text in [
            "a<think>1</think>b",
            "é<think>plan",
            "</think>answer",
            "{\"description\":\"Searched notes\",\"parameters\":{\"Command\":\"grep '<think>x</think>' notes\"}}",
            "{\"offsetSeconds\":1,\"description\":\"Listed files\"}\n<think>plan</think>\n",
        ] {
            assert_eq!(strip_think_blocks(text.to_owned()), text, "{text:?}");
        }
    }

    #[test]
    fn base_url_overrides_default() {
        let custom = Url::parse("https://proxy.example/anthropic/").expect("valid URL");

        let resolved = resolve_base_url(Provider::Anthropic, Some(custom.clone())).expect("custom base URL");

        assert_eq!(resolved, custom);
    }

    #[test]
    fn base_url_must_be_http_without_query_or_fragment() {
        for url in [
            "ftp://files.example/v1/",
            "https://host.example/v1/?api-version=1",
            "https://host.example/v1/?",
            "https://host.example/v1/#part",
        ] {
            let url = Url::parse(url).expect("valid URL");

            assert!(
                matches!(
                    resolve_base_url(Provider::OpenAiCompatible, Some(url.clone())),
                    Err(BuildError::UnsupportedBaseUrl)
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn api_key_must_fit_in_a_header() {
        let result = AiClient::builder()
            .provider(Provider::OpenAi)
            .model("gpt-test")
            .api_key("sk-line\nbreak")
            .http_client(reqwest::Client::new())
            .build();

        assert!(matches!(result, Err(BuildError::InvalidApiKey)), "{result:?}");
    }

    const PROVIDERS: [Provider; 5] = [
        Provider::OpenAi,
        Provider::Anthropic,
        Provider::Mistral,
        Provider::Gemini,
        Provider::OpenAiCompatible,
    ];

    fn complete_builder(provider: Provider) -> AiClientBuilder {
        AiClient::builder()
            .provider(provider)
            .model("gpt-test")
            .api_key("sk-very-secret")
            .base_url(Url::parse("http://127.0.0.1:1/v1/").expect("valid URL"))
            .http_client(reqwest::Client::new())
    }

    #[test]
    fn complete_settings_build() {
        for provider in PROVIDERS {
            let result = complete_builder(provider).build();
            assert!(result.is_ok(), "{provider:?}: {result:?}");
        }
    }

    #[test]
    fn build_requires_a_provider() {
        let result = AiClient::builder()
            .model("gpt-test")
            .api_key("sk-very-secret")
            .http_client(reqwest::Client::new())
            .build();

        assert!(matches!(result, Err(BuildError::MissingProvider)), "{result:?}");
    }

    #[test]
    fn build_requires_a_model() {
        for model in [None, Some("  ")] {
            let mut builder = AiClient::builder()
                .provider(Provider::OpenAi)
                .api_key("sk-very-secret")
                .http_client(reqwest::Client::new());
            if let Some(model) = model {
                builder = builder.model(model);
            }

            let result = builder.build();
            assert!(matches!(result, Err(BuildError::MissingModel)), "{model:?}: {result:?}");
        }
    }

    #[test]
    fn build_requires_an_api_key_for_every_provider() {
        for provider in PROVIDERS {
            let result = AiClient::builder()
                .provider(provider)
                .model("gpt-test")
                .base_url(Url::parse("http://127.0.0.1:1/v1/").expect("valid URL"))
                .http_client(reqwest::Client::new())
                .build();
            assert!(
                matches!(result, Err(BuildError::MissingApiKey(missing)) if missing == provider),
                "{provider:?}: {result:?}"
            );

            let result = complete_builder(provider).api_key("").build();
            assert!(
                matches!(result, Err(BuildError::MissingApiKey(missing)) if missing == provider),
                "{provider:?}: {result:?}"
            );
        }
    }

    #[test]
    fn build_uses_the_default_base_url() {
        for provider in PROVIDERS {
            let result = AiClient::builder()
                .provider(provider)
                .model("gpt-test")
                .api_key("sk-very-secret")
                .http_client(reqwest::Client::new())
                .build();

            if provider == Provider::OpenAiCompatible {
                assert!(
                    matches!(result, Err(BuildError::MissingBaseUrl(Provider::OpenAiCompatible))),
                    "{result:?}"
                );
            } else {
                assert!(result.is_ok(), "{provider:?}: {result:?}");
            }
        }
    }

    #[test]
    fn build_requires_an_http_client() {
        let result = AiClient::builder()
            .provider(Provider::OpenAi)
            .model("gpt-test")
            .api_key("sk-very-secret")
            .build();

        assert!(matches!(result, Err(BuildError::MissingHttpClient)), "{result:?}");
    }

    #[test]
    fn client_debug_hides_the_api_key() {
        let client = complete_builder(Provider::Anthropic).build().expect("valid settings");

        assert!(!format!("{client:?}").contains("sk-very-secret"));
    }
}
