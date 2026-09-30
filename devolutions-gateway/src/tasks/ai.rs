//! AI settings shared by the task kinds that call an AI provider.
//!
//! The provisioner sends them with the API key in the body of `POST /jet/tasks`.
//! [`AiSettings`] is the part persisted with the task; the API key stays in memory as the task secret.

use devolutions_gateway_ai::{AiClient, BuildError, Provider};
use secrecy::SecretString;
use url::Url;

use super::{TaskError, TaskErrorCode};
use crate::DgwState;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiProvider {
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "mistral")]
    Mistral,
    #[serde(rename = "openai-compatible")]
    OpenAiCompatible,
}

impl From<AiProvider> for Provider {
    fn from(provider: AiProvider) -> Self {
        match provider {
            AiProvider::OpenAi => Provider::OpenAi,
            AiProvider::Anthropic => Provider::Anthropic,
            AiProvider::Mistral => Provider::Mistral,
            AiProvider::OpenAiCompatible => Provider::OpenAiCompatible,
        }
    }
}

/// AI settings of a task, persisted with it: everything but the API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiSettings {
    pub provider: AiProvider,
    pub model: String,
    pub base_url: Option<Url>,
    /// Upper bound of tokens in each AI answer.
    pub max_output_tokens: Option<u32>,
}

impl AiSettings {
    /// Checks the settings before the task is recorded.
    pub fn check(&self, api_key: &SecretString, state: &DgwState) -> Result<(), TaskErrorCode> {
        match self.build_client(api_key, state) {
            Ok(_) => Ok(()),
            Err(ClientError::Build(error)) => {
                let code = build_error_code(&error);
                debug!(%error, ?code, "Invalid AI settings");
                Err(code)
            }
            Err(ClientError::HttpClient(error)) => {
                error!(%error, "Failed to build the HTTP client for the AI provider");
                Err(TaskErrorCode::Internal)
            }
        }
    }

    /// Builds the client of a task run, through the proxy configured for Gateway.
    pub fn client(&self, api_key: &SecretString, state: &DgwState) -> Result<AiClient, TaskError> {
        self.build_client(api_key, state)
            .map_err(|error| TaskError::Permanent(error.message()))
    }

    fn build_client(&self, api_key: &SecretString, state: &DgwState) -> Result<AiClient, ClientError> {
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
            let proxy_config = state.conf_handle.get_conf().proxy.to_proxy_config();

            let http_client =
                http_client_proxy::get_or_create_cached_client(reqwest::Client::builder(), &endpoint, &proxy_config)
                    .map_err(ClientError::HttpClient)?;

            builder = builder.http_client(http_client);
        }

        builder.build().map_err(ClientError::Build)
    }
}

/// Retries only the AI errors that may pass later, such as a rate limit or a network error.
impl From<devolutions_gateway_ai::Error> for TaskError {
    fn from(error: devolutions_gateway_ai::Error) -> Self {
        if error.is_transient() {
            TaskError::Transient(error.to_string())
        } else {
            TaskError::Permanent(error.to_string())
        }
    }
}

enum ClientError {
    Build(BuildError),
    HttpClient(reqwest::Error),
}

impl ClientError {
    fn message(&self) -> String {
        match self {
            ClientError::Build(error) => error.to_string(),
            ClientError::HttpClient(error) => format!("failed to build the HTTP client: {error}"),
        }
    }
}

fn build_error_code(error: &BuildError) -> TaskErrorCode {
    match error {
        BuildError::MissingModel => TaskErrorCode::MissingModel,
        BuildError::MissingApiKey(_) => TaskErrorCode::MissingApiKey,
        BuildError::MissingBaseUrl(_) => TaskErrorCode::MissingBaseUrl,
        _ => TaskErrorCode::InvalidAiSettings,
    }
}

#[cfg(test)]
mod tests {
    use devolutions_gateway_ai::Error;

    use super::*;

    #[test]
    fn build_errors_map_to_stable_codes() {
        assert_eq!(build_error_code(&BuildError::MissingModel), TaskErrorCode::MissingModel);
        assert_eq!(
            build_error_code(&BuildError::MissingApiKey(Provider::OpenAi)),
            TaskErrorCode::MissingApiKey
        );
        assert_eq!(
            build_error_code(&BuildError::MissingBaseUrl(Provider::OpenAiCompatible)),
            TaskErrorCode::MissingBaseUrl
        );
        assert_eq!(
            build_error_code(&BuildError::InvalidApiKey),
            TaskErrorCode::InvalidAiSettings
        );
    }

    #[test]
    fn rate_limits_server_and_network_errors_are_transient() {
        let status = |status| Error::Status {
            status,
            message: "failed".to_owned(),
            code: None,
            retry_after: None,
        };

        let network = Error::Transport {
            message: "connection refused".to_owned(),
        };
        assert!(matches!(TaskError::from(network), TaskError::Transient(_)));

        for code in [429, 500, 503] {
            assert!(
                matches!(TaskError::from(status(code)), TaskError::Transient(_)),
                "{code}"
            );
        }

        for code in [400, 401, 403, 404] {
            assert!(
                matches!(TaskError::from(status(code)), TaskError::Permanent(_)),
                "{code}"
            );
        }

        let invalid = Error::InvalidOutput {
            reason: "no valid action line".to_owned(),
        };
        assert!(matches!(TaskError::from(invalid), TaskError::Permanent(_)));
    }
}
