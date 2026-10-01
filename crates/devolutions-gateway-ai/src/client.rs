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
    #[error("base URL scheme must be http or https")]
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

    /// Checks every setting, so that no request of the client can fail because of them.
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

    if !matches!(base_url.scheme(), "http" | "https") {
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
    /// Data the purpose works on, such as a session transcript.
    pub(crate) input: &'a str,
    pub(crate) max_output_tokens: u32,
}

impl AiClient {
    pub fn builder() -> AiClientBuilder {
        AiClientBuilder::default()
    }

    /// Sends one completion request and returns the text of the answer.
    ///
    /// An answer cut short by the output token limit or the context window is [`Error::Truncated`], because no purpose
    /// can use a partial answer.
    /// A refusal is [`Error::Refused`], so that no purpose reads it as an empty answer.
    /// The `<think>` blocks some models write before their answer are removed.
    pub(crate) async fn complete(&self, prompt: &Prompt<'_>) -> Result<Response<String>, Error> {
        debug!(
            provider = ?self.provider,
            model = %self.model,
            base_url = %self.base_url,
            input_len = prompt.input.len(),
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
            .map_err(|error| error::transport(&error, api_key))?;

        let status = response.status();
        let retry_after = error::retry_after(response.headers());
        let body = response
            .bytes()
            .await
            .map_err(|error| error::transport(&error, api_key))?;

        if !status.is_success() {
            return Err(error::status(status, retry_after, &body, api_key));
        }

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

/// Removes the `<think>…</think>` blocks that some models write before their answer; an unclosed block runs to the end.
fn strip_think_blocks(text: String) -> String {
    const OPEN: &str = "<think>";
    const CLOSE: &str = "</think>";

    if find_ignore_ascii_case(&text, OPEN).is_none() {
        return text;
    }

    let mut stripped = String::with_capacity(text.len());
    let mut rest = text.as_str();

    while let Some(open) = find_ignore_ascii_case(rest, OPEN) {
        stripped.push_str(&rest[..open]);

        let inside = &rest[open + OPEN.len()..];
        let Some(close) = find_ignore_ascii_case(inside, CLOSE) else {
            return stripped;
        };

        rest = &inside[close + CLOSE.len()..];
    }

    stripped.push_str(rest);
    stripped
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
    fn think_blocks_are_removed() {
        for (text, expected) in [
            ("answer", "answer"),
            ("<think>plan</think>answer", "answer"),
            ("<THINK>\nplan\n</Think>\nanswer\n", "\nanswer\n"),
            ("a<think>1</think>b<think>2</think>c", "abc"),
            ("é<think>plan", "é"),
            ("</think>answer", "</think>answer"),
        ] {
            assert_eq!(strip_think_blocks(text.to_owned()), expected, "{text:?}");
        }
    }

    #[test]
    fn base_url_overrides_default() {
        let custom = Url::parse("https://proxy.example/anthropic/").expect("valid URL");

        let resolved = resolve_base_url(Provider::Anthropic, Some(custom.clone())).expect("custom base URL");

        assert_eq!(resolved, custom);
    }

    #[test]
    fn base_url_must_be_http() {
        let url = Url::parse("ftp://files.example/v1/").expect("valid URL");

        assert!(matches!(
            resolve_base_url(Provider::OpenAiCompatible, Some(url)),
            Err(BuildError::UnsupportedBaseUrl)
        ));
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
