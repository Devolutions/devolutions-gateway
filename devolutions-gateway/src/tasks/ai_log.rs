//! `ai-log` task: describes what the user did in one session and stores the result as a new log of that session.

use devolutions_gateway_ai::{AiClient, BuildError, Provider};
use secrecy::SecretString;
use url::Url;
use uuid::Uuid;

use super::{EphemeralTask, RetryPolicy, SECRETS_LOST_ERROR, StartError, TaskCtx, TaskError, TaskKind};
use crate::DgwState;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

/// The persisted part of [`AiLogParams`]: everything but the API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiLogSettings {
    pub provider: AiProvider,
    pub model: String,
    pub base_url: Option<Url>,
    pub max_output_tokens: Option<u32>,
}

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

pub enum AiLogTask {}

impl TaskKind for AiLogTask {
    const KIND: &'static str = "ai-log";
    const RETRY: RetryPolicy = RetryPolicy::JOB_QUEUE;

    type Target = AiLogTarget;
    type Params = AiLogSettings;
    type Substate = AiLogSubstate;
    type Output = AiLogOutput;

    async fn run(ctx: TaskCtx<Self>) -> Result<AiLogOutput, TaskError> {
        let Some(api_key) = ctx.secrets() else {
            return Err(TaskError::Permanent(SECRETS_LOST_ERROR.to_owned()));
        };

        let _client = build_client(&ctx.params, Some(api_key), &ctx.state)
            .map_err(|error| TaskError::Permanent(error.message()))?;

        Err(TaskError::Permanent("ai-log task not implemented yet".to_owned()))
    }
}

impl EphemeralTask for AiLogTask {
    type Secrets = SecretString;
    type Request = AiLogParams;

    fn prepare(
        target: &AiLogTarget,
        request: AiLogParams,
        state: &DgwState,
    ) -> Result<(AiLogSettings, SecretString), StartError> {
        if state.recordings.active_recordings.contains(target.session_id) {
            return Err(StartError::TargetBusy("recording_active"));
        }

        let AiLogParams {
            provider,
            model,
            api_key,
            base_url,
            max_output_tokens,
        } = request;

        let settings = AiLogSettings {
            provider,
            model,
            base_url,
            max_output_tokens,
        };

        build_client(&settings, api_key.as_ref(), state).map_err(|error| match error {
            ClientError::Build(error) => {
                let code = build_error_code(&error);
                warn!(%error, code, "Invalid AI settings");
                StartError::InvalidParams(code)
            }
            ClientError::HttpClient(error) => {
                error!(%error, "Failed to build the HTTP client for the AI provider");
                StartError::Internal
            }
        })?;

        let api_key = api_key.ok_or(StartError::InvalidParams("missing_api_key"))?;

        Ok((settings, api_key))
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

fn build_client(
    settings: &AiLogSettings,
    api_key: Option<&SecretString>,
    state: &DgwState,
) -> Result<AiClient, ClientError> {
    let provider = Provider::from(settings.provider);

    let mut builder = AiClient::builder().provider(provider).model(settings.model.clone());

    if let Some(api_key) = api_key {
        builder = builder.api_key(api_key.clone());
    }

    let endpoint = settings.base_url.clone().or_else(|| provider.default_base_url());

    if let Some(base_url) = settings.base_url.clone() {
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

fn build_error_code(error: &BuildError) -> &'static str {
    match error {
        BuildError::MissingModel => "missing_model",
        BuildError::MissingApiKey(_) => "missing_api_key",
        BuildError::MissingBaseUrl(_) => "missing_base_url",
        _ => "invalid_ai_settings",
    }
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the ai-log runner, which comes in a later change")
)]
fn classify_ai_error(error: &devolutions_gateway_ai::Error) -> TaskError {
    let message = error.to_string();

    if error.is_transient() {
        TaskError::Transient(message)
    } else {
        TaskError::Permanent(message)
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

    fn target() -> AiLogTarget {
        AiLogTarget {
            session_id: Uuid::new_v4(),
        }
    }

    #[tokio::test]
    async fn refuses_a_session_that_is_still_recording() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");
        let target = target();
        state.recordings.active_recordings.insert(target.session_id);

        let error = AiLogTask::prepare(&target, params(), &state).expect_err("session is busy");

        assert_eq!(error, StartError::TargetBusy("recording_active"));
    }

    #[tokio::test]
    async fn persisted_settings_never_hold_the_api_key() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");

        let params = params();
        assert!(!format!("{params:?}").contains(API_KEY));

        let (settings, api_key) = AiLogTask::prepare(&target(), params, &state).expect("valid task");

        let persisted = serde_json::to_string(&settings).expect("serializable settings");
        assert_eq!(
            persisted,
            r#"{"provider":"openai","model":"gpt-test","baseUrl":null,"maxOutputTokens":null}"#
        );
        assert!(!format!("{settings:?}").contains(API_KEY));
        assert!(!format!("{api_key:?}").contains(API_KEY));
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

    #[test]
    fn rate_limits_server_and_network_errors_are_transient() {
        let status = |status| devolutions_gateway_ai::Error::Status {
            status,
            message: "failed".to_owned(),
            code: None,
            retry_after: None,
        };

        let network = devolutions_gateway_ai::Error::Transport {
            message: "connection refused".to_owned(),
        };
        assert!(matches!(classify_ai_error(&network), TaskError::Transient(_)));

        for code in [429, 500, 503] {
            assert!(
                matches!(classify_ai_error(&status(code)), TaskError::Transient(_)),
                "{code}"
            );
        }

        for code in [400, 401, 403, 404] {
            assert!(
                matches!(classify_ai_error(&status(code)), TaskError::Permanent(_)),
                "{code}"
            );
        }

        assert!(matches!(
            classify_ai_error(&devolutions_gateway_ai::Error::InvalidOutput {
                reason: "no valid action line".to_owned()
            }),
            TaskError::Permanent(_)
        ));
    }
}
