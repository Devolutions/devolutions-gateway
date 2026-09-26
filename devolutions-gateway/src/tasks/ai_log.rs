//! `ai-log` task: describes what the user did in one session and stores the result as a new log of that session.

use devolutions_gateway_ai::{AiClient, BuildError, Provider};
use secrecy::SecretString;
use url::Url;
use uuid::Uuid;

use super::{BackgroundTask, Persistence, Progress, StartError};
use crate::DgwState;

pub struct AiLogTarget {
    pub session_id: Uuid,
}

/// AI settings used by an `ai-log` task.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiLogParams {
    pub provider: AiProvider,
    /// Model identifier, passed to the provider as is.
    pub model: String,
    /// Required by every provider; kept in memory for this task only.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub api_key: Option<SecretString>,
    /// Overrides the provider default; required for `openai-compatible`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub base_url: Option<Url>,
    /// Upper bound of tokens in each AI answer.
    pub max_output_tokens: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
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

/// Progress of a running `ai-log` task.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "kebab-case", tag = "step")]
pub enum AiLogSubstate {
    #[default]
    Preparing,
}

#[derive(Debug, Serialize)]
pub enum AiLogOutput {}

#[derive(Debug)]
pub struct AiLogTask {
    #[expect(dead_code, reason = "read by the ai-log runner, which comes in a later change")]
    session_id: Uuid,
    #[expect(dead_code, reason = "read by the ai-log runner, which comes in a later change")]
    client: AiClient,
    #[expect(dead_code, reason = "read by the ai-log runner, which comes in a later change")]
    max_output_tokens: Option<u32>,
}

impl BackgroundTask for AiLogTask {
    const KIND: &'static str = "ai-log";
    const PERSISTENCE: Persistence = Persistence::InMemory;

    type Params = AiLogParams;
    type Target = AiLogTarget;
    type Substate = AiLogSubstate;
    type Output = AiLogOutput;

    fn prepare(target: AiLogTarget, params: AiLogParams, state: &DgwState) -> Result<Self, StartError> {
        if state.recordings.active_recordings.contains(target.session_id) {
            return Err(StartError::TargetBusy("recording_active"));
        }

        let provider = Provider::from(params.provider);

        let mut builder = AiClient::builder().provider(provider).model(params.model);

        if let Some(api_key) = params.api_key {
            builder = builder.api_key(api_key);
        }

        let endpoint = params.base_url.clone().or_else(|| provider.default_base_url());

        if let Some(base_url) = params.base_url {
            builder = builder.base_url(base_url);
        }

        // Without an endpoint, `build` reports the missing base URL before it needs the HTTP client.
        if let Some(endpoint) = endpoint {
            let proxy_config = state.conf_handle.get_conf().proxy.to_proxy_config();

            let http_client =
                http_client_proxy::get_or_create_cached_client(reqwest::Client::builder(), &endpoint, &proxy_config)
                    .map_err(|error| {
                        error!(%error, "Failed to build the HTTP client for the AI provider");
                        StartError::Internal
                    })?;

            builder = builder.http_client(http_client);
        }

        let client = builder.build().map_err(|error| {
            let code = build_error_code(&error);
            warn!(%error, code, "Invalid AI settings");
            StartError::InvalidParams(code)
        })?;

        Ok(Self {
            session_id: target.session_id,
            client,
            max_output_tokens: params.max_output_tokens,
        })
    }

    async fn run(self, _progress: Progress<AiLogSubstate>) -> anyhow::Result<AiLogOutput> {
        anyhow::bail!("ai-log task not implemented yet")
    }
}

fn build_error_code(error: &BuildError) -> &'static str {
    match error {
        BuildError::MissingModel => "missing_model",
        BuildError::MissingApiKey(_) => "missing_api_key",
        BuildError::MissingBaseUrl(_) => "missing_base_url",
        _ => "invalid_ai_settings",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_KEY: &str = "sk-ai-log-test-secret";

    const CONFIG: &str = r#"{
        "ProvisionerPublicKeyData": {
            "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
        },
        "Listeners": [{ "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }],
        "Proxy": { "Mode": "Off" }
    }"#;

    fn params() -> AiLogParams {
        serde_json::from_value(serde_json::json!({
            "provider": "openai",
            "model": "gpt-test",
            "apiKey": API_KEY,
        }))
        .expect("valid params")
    }

    #[tokio::test]
    async fn refuses_a_session_that_is_still_recording() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");
        let session_id = Uuid::new_v4();
        state.recordings.active_recordings.insert(session_id);

        let error = AiLogTask::prepare(AiLogTarget { session_id }, params(), &state).expect_err("session is busy");

        assert_eq!(error, StartError::TargetBusy("recording_active"));
    }

    #[tokio::test]
    async fn debug_never_shows_the_api_key() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");

        let params = params();
        assert!(!format!("{params:?}").contains(API_KEY));

        let task = AiLogTask::prepare(
            AiLogTarget {
                session_id: Uuid::new_v4(),
            },
            params,
            &state,
        )
        .expect("valid task");
        assert!(!format!("{task:?}").contains(API_KEY));
    }

    #[test]
    fn build_errors_map_to_stable_codes() {
        assert_eq!(build_error_code(&BuildError::MissingModel), "missing_model");
        assert_eq!(
            build_error_code(&BuildError::MissingApiKey(Provider::OpenAi)),
            "missing_api_key"
        );
        assert_eq!(
            build_error_code(&BuildError::MissingBaseUrl(Provider::OpenAiCompatible)),
            "missing_base_url"
        );
    }
}
