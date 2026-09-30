//! `ai-log` task: describes what the user did in one session and stores the result as a new log of that session.

use secrecy::SecretString;
use url::Url;
use uuid::Uuid;

use super::ai::{AiProvider, AiSettings};
use super::{EphemeralTask, RetryPolicy, SECRETS_LOST_ERROR, TaskCtx, TaskError, TaskErrorCode, TaskKind};
use crate::DgwState;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiLogTarget {
    pub session_id: Uuid,
}

/// AI settings used by an `ai-log` task: the body of `POST /jet/tasks` for a TASK token of kind `ai-log`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiLogParams {
    pub provider: AiProvider,
    /// Model identifier, passed to the provider as is.
    pub model: String,
    /// Kept in memory for this task only.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub api_key: SecretString,
    /// Overrides the provider default; required for `openai-compatible`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub base_url: Option<Url>,
    /// Upper bound of tokens in each AI answer.
    pub max_output_tokens: Option<u32>,
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
    type Params = AiSettings;
    type Substate = AiLogSubstate;
    type Output = AiLogOutput;

    async fn run(ctx: TaskCtx<Self>) -> Result<AiLogOutput, TaskError> {
        let Some(api_key) = ctx.secrets() else {
            return Err(TaskError::Permanent(SECRETS_LOST_ERROR.to_owned()));
        };

        let _client = ctx.params.client(api_key, &ctx.state)?;

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
    ) -> Result<(AiSettings, SecretString), TaskErrorCode> {
        if state.recordings.active_recordings.contains(target.session_id) {
            return Err(TaskErrorCode::RecordingActive);
        }

        let AiLogParams {
            provider,
            model,
            api_key,
            base_url,
            max_output_tokens,
        } = request;

        let settings = AiSettings {
            provider,
            model,
            base_url,
            max_output_tokens,
        };

        settings.check(&api_key, state)?;

        Ok((settings, api_key))
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

        assert_eq!(error, TaskErrorCode::RecordingActive);
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

    #[tokio::test]
    async fn invalid_ai_settings_are_refused_with_a_code() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");
        let mut params = params();
        params.model = " ".to_owned();

        let error = AiLogTask::prepare(&target(), params, &state).expect_err("empty model");

        assert_eq!(error, TaskErrorCode::MissingModel);
    }
}
