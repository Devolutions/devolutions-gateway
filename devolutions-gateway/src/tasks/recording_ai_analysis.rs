//! `recording.ai-analysis` task: describes what the user did in one session and stores the result as a new log of that session.

use secrecy::SecretString;
use uuid::Uuid;

use super::ai::AiSettings;
use super::{
    EphemeralParts, EphemeralTask, RetryPolicy, SECRETS_LOST_ERROR, TaskCtx, TaskError, TaskErrorCode, TaskKind,
};
use crate::DgwState;
use crate::token::RecordingAiAnalysisPayload;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingAiAnalysisTarget {
    pub session_id: Uuid,
}

/// Credentials of a `recording.ai-analysis` task: the body of `POST /jet/tasks` for a TASK token of kind `recording.ai-analysis`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingAiAnalysisCredentials {
    /// API key of the AI provider, kept in memory for this task only.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub api_key: SecretString,
}

/// Progress of a running `recording.ai-analysis` task.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "kebab-case", tag = "step")]
pub enum RecordingAiAnalysisSubstate {
    #[default]
    Preparing,
}

#[derive(Debug, Serialize)]
pub enum RecordingAiAnalysisOutput {}

pub enum RecordingAiAnalysisTask {}

impl TaskKind for RecordingAiAnalysisTask {
    const KIND: &'static str = "recording.ai-analysis";
    const RETRY: RetryPolicy = RetryPolicy::JOB_QUEUE;

    type Payload = RecordingAiAnalysisPayload;
    type Target = RecordingAiAnalysisTarget;
    type Params = AiSettings;
    type Substate = RecordingAiAnalysisSubstate;
    type Output = RecordingAiAnalysisOutput;

    async fn run(ctx: TaskCtx<Self>) -> Result<RecordingAiAnalysisOutput, TaskError> {
        let Some(api_key) = ctx.secrets() else {
            return Err(TaskError::Permanent(SECRETS_LOST_ERROR.to_owned()));
        };

        let _client = ctx.params.client(&ctx.state, api_key)?;

        Err(TaskError::Permanent(
            "recording.ai-analysis task not implemented yet".to_owned(),
        ))
    }
}

impl EphemeralTask for RecordingAiAnalysisTask {
    /// API key of the AI provider.
    type Secrets = SecretString;
    type Request = RecordingAiAnalysisCredentials;

    fn prepare(
        state: &DgwState,
        payload: RecordingAiAnalysisPayload,
        request: RecordingAiAnalysisCredentials,
    ) -> Result<EphemeralParts<Self>, TaskErrorCode> {
        let RecordingAiAnalysisPayload {
            session_id,
            provider,
            model,
            base_url,
            max_output_tokens,
        } = payload;

        if state.recordings.active_recordings.contains(session_id) {
            return Err(TaskErrorCode::RecordingActive);
        }

        let settings = AiSettings {
            provider,
            model,
            base_url,
            max_output_tokens,
        };

        settings.check(state, &request.api_key)?;

        Ok(EphemeralParts {
            target: RecordingAiAnalysisTarget { session_id },
            params: settings,
            secrets: request.api_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_KEY: &str = "sk-recording.ai-analysis-test-secret";

    const CONFIG: &str = r#"{
        "ProvisionerPublicKeyData": {
            "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
        },
        "Listeners": [{ "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }],
        "Proxy": { "Mode": "Off" }
    }"#;

    fn payload() -> RecordingAiAnalysisPayload {
        serde_json::from_value(serde_json::json!({
            "session_id": Uuid::new_v4(),
            "provider": "openai",
            "model": "gpt-test",
        }))
        .expect("valid payload")
    }

    fn api_key() -> RecordingAiAnalysisCredentials {
        serde_json::from_value(serde_json::json!({ "apiKey": API_KEY })).expect("valid credentials")
    }

    #[tokio::test]
    async fn refuses_a_session_that_is_still_recording() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");
        let payload = payload();
        state.recordings.active_recordings.insert(payload.session_id);

        let error = RecordingAiAnalysisTask::prepare(&state, payload, api_key())
            .err()
            .expect("session is busy");

        assert_eq!(error, TaskErrorCode::RecordingActive);
    }

    #[tokio::test]
    async fn persisted_settings_never_hold_the_api_key() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");
        let payload = payload();
        let session_id = payload.session_id;

        let EphemeralParts {
            target,
            params: settings,
            secrets: api_key,
        } = RecordingAiAnalysisTask::prepare(&state, payload, api_key()).expect("valid task");

        assert_eq!(target.session_id, session_id);
        let persisted = serde_json::to_string(&settings).expect("serializable settings");
        assert_eq!(
            persisted,
            r#"{"provider":"openai","model":"gpt-test","baseUrl":null,"maxOutputTokens":null}"#
        );
        assert!(!format!("{settings:?}").contains(API_KEY));
        assert!(!format!("{api_key:?}").contains(API_KEY));
    }

    #[test]
    fn credentials_hide_the_api_key_and_refuse_unknown_fields() {
        assert!(!format!("{:?}", api_key()).contains(API_KEY));

        let misplaced = serde_json::from_value::<RecordingAiAnalysisCredentials>(
            serde_json::json!({ "apiKey": API_KEY, "model": "x" }),
        );
        assert!(misplaced.is_err());
    }

    #[tokio::test]
    async fn invalid_ai_settings_are_refused_with_a_code() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");
        let mut payload = payload();
        payload.model = " ".to_owned();

        let error = RecordingAiAnalysisTask::prepare(&state, payload, api_key())
            .err()
            .expect("empty model");

        assert_eq!(error, TaskErrorCode::MissingModel);
    }
}
