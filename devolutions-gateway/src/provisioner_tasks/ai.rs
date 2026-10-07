//! AI settings shared by the provisioner tasks that call an AI provider.
//!
//! The API key and the base URL never reach `gateway.db`: they stay in memory, encrypted, as the task secret of their
//! Task in the [`ProvisioningStore`](crate::provisioning::ProvisioningStore), until the Task ends.

use core::fmt;

use anyhow::Context as _;
use devolutions_gateway_ai::recording_analysis::RecordingAnalysisError;
use devolutions_gateway_ai::{AiClient, BuildError, Provider};
use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use super::AttemptError;
use crate::config::Conf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiProvider {
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "mistral")]
    Mistral,
    #[serde(rename = "gemini")]
    Gemini,
    #[serde(rename = "openai-compatible")]
    OpenAiCompatible,
}

impl From<AiProvider> for Provider {
    fn from(provider: AiProvider) -> Self {
        match provider {
            AiProvider::OpenAi => Provider::OpenAi,
            AiProvider::Anthropic => Provider::Anthropic,
            AiProvider::Mistral => Provider::Mistral,
            AiProvider::Gemini => Provider::Gemini,
            AiProvider::OpenAiCompatible => Provider::OpenAiCompatible,
        }
    }
}

/// How to reach an AI provider, except the API key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiSettings {
    pub provider: AiProvider,
    pub model: String,
    /// Required for [`AiProvider::OpenAiCompatible`]; the others have a default.
    pub base_url: Option<Url>,
    /// Upper bound of tokens in each AI answer.
    pub max_output_tokens: Option<u32>,
}

/// Why AI settings were refused before a Task was recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AiSettingsError {
    #[error("AI model is missing")]
    MissingModel,
    #[error("API key is missing")]
    MissingApiKey,
    #[error("base URL is missing for this AI provider")]
    MissingBaseUrl,
    #[error("invalid AI settings: {0}")]
    Invalid(String),
}

impl From<&BuildError> for AiSettingsError {
    fn from(error: &BuildError) -> Self {
        match error {
            BuildError::MissingModel => Self::MissingModel,
            BuildError::MissingApiKey(_) => Self::MissingApiKey,
            BuildError::MissingBaseUrl(_) => Self::MissingBaseUrl,
            _ => Self::Invalid(error.to_string()),
        }
    }
}

pub(crate) enum ClientError {
    Build(BuildError),
    HttpClient(reqwest::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Build(error) => fmt::Display::fmt(error, f),
            ClientError::HttpClient(error) => write!(f, "failed to build the HTTP client: {error}"),
        }
    }
}

/// What a Task needs to reach its AI provider and must never write to disk.
#[derive(Debug, Clone)]
pub(crate) struct AiAccess {
    pub(crate) api_key: SecretString,
    pub(crate) base_url: Option<Url>,
}

/// [`AiAccess`] as written into its task secret.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiAccessSecretRef<'a> {
    api_key: &'a str,
    base_url: Option<&'a Url>,
}

/// [`AiAccess`] as read back from its task secret.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AiAccessSecret {
    api_key: String,
    base_url: Option<Url>,
}

impl AiAccess {
    /// The task secret holding this access.
    pub(crate) fn to_secret(&self) -> anyhow::Result<SecretString> {
        let json = serde_json::to_string(&AiAccessSecretRef {
            api_key: self.api_key.expose_secret(),
            base_url: self.base_url.as_ref(),
        })
        .context("serialize the AI access")?;

        Ok(SecretString::from(json))
    }

    /// Reads back an access from its task secret.
    pub(crate) fn from_secret(secret: &SecretString) -> anyhow::Result<Self> {
        // The parse error is dropped: it may quote the API key.
        let access: AiAccessSecret =
            serde_json::from_str(secret.expose_secret()).map_err(|_| anyhow::anyhow!("invalid AI access secret"))?;

        Ok(Self {
            api_key: SecretString::from(access.api_key),
            base_url: access.base_url,
        })
    }
}

impl AiSettings {
    /// Builds a client going through the proxy configured for Gateway.
    pub(crate) fn client(&self, conf: &Conf, api_key: &SecretString) -> Result<AiClient, ClientError> {
        let provider = Provider::from(self.provider);

        let mut builder = AiClient::builder()
            .provider(provider)
            .model(self.model.clone())
            .api_key(api_key.clone());

        let endpoint = self.base_url.clone().or_else(|| provider.default_base_url());

        if let Some(base_url) = self.base_url.clone() {
            builder = builder.base_url(base_url);
        }

        // Without an endpoint, `build` reports the missing base URL before it needs the HTTP client.
        if let Some(endpoint) = endpoint {
            let proxy_config = conf.proxy.to_proxy_config();

            let http_client =
                http_client_proxy::get_or_create_cached_client(reqwest::Client::builder(), &endpoint, &proxy_config)
                    .map_err(|error| ClientError::HttpClient(error.without_url()))?;

            builder = builder.http_client(http_client);
        }

        builder.build().map_err(ClientError::Build)
    }
}

/// Retries only the failures that may pass later, such as a rate limit or a network error.
impl From<RecordingAnalysisError> for AttemptError {
    fn from(error: RecordingAnalysisError) -> Self {
        match error {
            RecordingAnalysisError::Cancelled => AttemptError::Cancelled,
            error if error.is_transient() => AttemptError::Transient(error.to_string()),
            error => AttemptError::Permanent(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use devolutions_gateway_ai::Error;

    use super::*;

    #[test]
    fn build_errors_map_to_settings_errors() {
        assert_eq!(
            AiSettingsError::from(&BuildError::MissingModel),
            AiSettingsError::MissingModel
        );
        assert_eq!(
            AiSettingsError::from(&BuildError::MissingApiKey(Provider::OpenAi)),
            AiSettingsError::MissingApiKey
        );
        assert_eq!(
            AiSettingsError::from(&BuildError::MissingBaseUrl(Provider::OpenAiCompatible)),
            AiSettingsError::MissingBaseUrl
        );
        assert!(matches!(
            AiSettingsError::from(&BuildError::InvalidApiKey),
            AiSettingsError::Invalid(_)
        ));
    }

    #[test]
    fn rate_limits_server_and_network_errors_are_transient() {
        let attempt = |error: Error| AttemptError::from(RecordingAnalysisError::Ai(error));
        let status = |status| Error::Status {
            status,
            message: "failed".to_owned(),
            code: None,
            retry_after: None,
        };

        let network = Error::Transport {
            message: "connection refused".to_owned(),
        };
        assert!(matches!(attempt(network), AttemptError::Transient(_)));

        for code in [429, 500, 503] {
            assert!(matches!(attempt(status(code)), AttemptError::Transient(_)), "{code}");
        }

        for code in [400, 401, 403, 404] {
            assert!(matches!(attempt(status(code)), AttemptError::Permanent(_)), "{code}");
        }

        let invalid = Error::InvalidOutput {
            reason: "no valid action line".to_owned(),
        };
        assert!(matches!(attempt(invalid), AttemptError::Permanent(_)));

        assert!(matches!(
            AttemptError::from(RecordingAnalysisError::Truncated),
            AttemptError::Permanent(_)
        ));
        assert_eq!(
            AttemptError::from(RecordingAnalysisError::Cancelled),
            AttemptError::Cancelled
        );
    }

    #[test]
    fn providers_keep_their_wire_names() {
        for (provider, name) in [
            (AiProvider::OpenAi, "openai"),
            (AiProvider::Anthropic, "anthropic"),
            (AiProvider::Mistral, "mistral"),
            (AiProvider::Gemini, "gemini"),
            (AiProvider::OpenAiCompatible, "openai-compatible"),
        ] {
            assert_eq!(serde_json::to_value(provider).expect("serializable"), name);
            assert_eq!(
                serde_json::from_value::<AiProvider>(serde_json::Value::from(name)).expect("known name"),
                provider
            );
        }
    }
}
