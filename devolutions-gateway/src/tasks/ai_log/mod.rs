//! `ai-log` task: describes what the user did in one session and stores the result as a new log of that session.
//!
//! The task works in steps, keeping its files in the task workspace:
//! 1. stream the terminal recordings into transcript chunk files (`chunk-NNNN.txt`);
//! 2. ask the AI about each chunk and save its actions as a checkpoint (`chunk-NNNN.actions.jsonl`);
//!    a retry skips the chunks that already have one;
//! 3. merge the checkpoints into a `.slog` file and add it to the session.

mod checkpoint;
mod slog;
mod transcript;

use std::collections::VecDeque;
use std::fs::File;
use std::io::BufWriter;

use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_ai::AiClient;
use devolutions_gateway_ai::session_actions::Action;
use secrecy::SecretString;
use url::Url;
use uuid::Uuid;

use super::ai::{AiProvider, AiSettings};
use super::{EphemeralTask, RetryPolicy, SECRETS_LOST_ERROR, TaskCtx, TaskError, TaskErrorCode, TaskKind};
use crate::DgwState;
use crate::artifacts::ArtifactKind;
use crate::recording::{FinishedRecording, RecordingMessageSender};

/// Input tokens sent in one AI request, estimated at 4 characters per token.
pub const MAX_INPUT_TOKENS_PER_REQUEST: usize = 100_000;

const CHARS_PER_TOKEN: usize = 4;

/// Longest transcript chunk, in bytes; it bounds the memory used by the task.
const MAX_CHUNK_LEN: usize = MAX_INPUT_TOKENS_PER_REQUEST * CHARS_PER_TOKEN;

/// A truncated AI answer for a transcript part shorter than this fails the task instead of splitting the part again.
const MIN_SPLIT_LEN: usize = 2_000;

pub const TRUNCATED_ERROR: &str =
    "AI answer was cut at the output token limit, even for a short part of the transcript";

/// Written once every chunk file is complete; holds the number of chunks.
const CHUNKS_DONE_FILE: &str = "chunks.done";

const LOG_FILE: &str = "log.slog";

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
    /// Transcript chunks sent to the AI provider so far, out of `total`.
    Describing { done: usize, total: usize },
}

/// Result of a successful `ai-log` task.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiLogOutput {
    /// Name of the new log in the session manifest, such as `ai-analysis-0.slog`.
    pub file_name: String,
}

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

        let client = ctx.params.client(&ctx.state, api_key)?;

        let session_id = ctx.target.session_id;

        let recording = match ctx.state.recordings.get_finished(session_id).await {
            Ok(Ok(recording)) => recording,
            Ok(Err(error)) => return Err(TaskError::Permanent(format!("{error:#}"))),
            Err(error) => return Err(TaskError::Permanent(format!("failed to read the recording: {error:#}"))),
        };

        let start_time = recording.manifest.start_time();
        let duration = recording.manifest.duration();
        let workspace = ctx.workspace.clone();

        let total = blocking(write_chunks(recording, workspace.clone())).await?;

        info!(session.id = %session_id, chunks = total, "Describe the session actions");

        for index in 0..total {
            let checkpoint = checkpoint::path(&workspace, index);

            if checkpoint.exists() {
                debug!(session.id = %session_id, index, "Chunk already described");
                continue;
            }

            ctx.progress
                .set(&AiLogSubstate::Describing { done: index, total })
                .await;

            let chunk = tokio::fs::read_to_string(transcript::chunk_path(&workspace, index))
                .await
                .map_err(|error| workspace_error(&error))?;

            let actions = describe_chunk(&client, ctx.params.max_output_tokens, &chunk).await?;

            blocking(move || checkpoint::write(&checkpoint, &actions).map_err(|error| workspace_error(&error))).await?;
        }

        ctx.progress
            .set(&AiLogSubstate::Describing { done: total, total })
            .await;

        let log_path = workspace.join(LOG_FILE);
        let model = ctx.params.model.clone();
        let actions = blocking({
            let log_path = log_path.clone();
            move || merge_checkpoints(&workspace, total, start_time, duration, &model, &log_path)
        })
        .await?;

        let file_name = add_log(&ctx.state.recordings, session_id, &log_path)
            .await
            .map_err(|error| TaskError::Permanent(format!("failed to add the log: {error:#}")))?;

        info!(session.id = %session_id, file_name, actions, "Session log generated");

        Ok(AiLogOutput { file_name })
    }
}

async fn add_log(recordings: &RecordingMessageSender, session_id: Uuid, log_path: &Utf8Path) -> anyhow::Result<String> {
    let artifact_path = recordings.add_artifact(session_id, ArtifactKind::AiAnalysis).await?;
    tokio::fs::copy(log_path, &artifact_path).await?;
    Ok(artifact_path
        .file_name()
        .expect("artifact paths end with a file name")
        .to_owned())
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, TaskError> + Send + 'static,
) -> Result<T, TaskError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| TaskError::Permanent("task step panicked".to_owned()))?
}

fn workspace_error(error: &dyn std::fmt::Display) -> TaskError {
    TaskError::Permanent(format!("task workspace error: {error:#}"))
}

/// Splits the transcript into chunk files once; a retry reuses them.
fn write_chunks(recording: FinishedRecording, workspace: Utf8PathBuf) -> impl FnOnce() -> Result<usize, TaskError> {
    move || {
        let done = workspace.join(CHUNKS_DONE_FILE);

        if let Some(total) = std::fs::read_to_string(&done).ok().and_then(|total| total.parse().ok()) {
            return Ok(total);
        }

        std::fs::create_dir_all(&workspace).map_err(|error| workspace_error(&error))?;

        let total = transcript::write_chunks(&recording, &workspace, MAX_CHUNK_LEN).map_err(|error| match error {
            transcript::TranscriptError::Write(error) => workspace_error(&error),
            error => TaskError::Permanent(error.to_string()),
        })?;

        std::fs::write(&done, total.to_string()).map_err(|error| workspace_error(&error))?;

        Ok(total)
    }
}

/// Asks the AI about one chunk; a truncated answer is asked again as two halves.
async fn describe_chunk(
    client: &AiClient,
    max_output_tokens: Option<u32>,
    chunk: &str,
) -> Result<Vec<Action>, TaskError> {
    let mut parts = VecDeque::from([chunk]);
    let mut actions = Vec::new();

    while let Some(part) = parts.pop_front() {
        let mut request = client.describe_session_actions(part);

        if let Some(max_output_tokens) = max_output_tokens {
            request = request.max_output_tokens(max_output_tokens);
        }

        match request.send().await {
            Ok(response) => actions.extend(response.output),
            Err(devolutions_gateway_ai::Error::Truncated { .. }) => {
                let Some((first, second)) = split_in_half(part) else {
                    return Err(TaskError::Permanent(TRUNCATED_ERROR.to_owned()));
                };

                debug!(part_len = part.len(), "AI answer truncated; asking again in two halves");
                parts.push_front(second);
                parts.push_front(first);
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(actions)
}

/// Cuts `part` on the line boundary closest to its middle, unless it is too short to split.
fn split_in_half(part: &str) -> Option<(&str, &str)> {
    if part.len() < MIN_SPLIT_LEN {
        return None;
    }

    let bytes = part.as_bytes();
    let middle = part.len() / 2;

    let before = bytes[..middle]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map(|end| end + 1);
    let after = bytes[middle..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|end| middle + end + 1);

    let cut = match (before, after) {
        (Some(before), Some(after)) if middle - before <= after - middle => before,
        (_, Some(after)) if after < part.len() => after,
        (Some(before), _) => before,
        _ => return None,
    };

    Some(part.split_at(cut))
}

/// Writes the `.slog` from the checkpoints, and returns the number of actions.
fn merge_checkpoints(
    workspace: &Utf8Path,
    total: usize,
    start_time: i64,
    duration: i64,
    model: &str,
    log_path: &Utf8Path,
) -> Result<usize, TaskError> {
    let log_error = |error: anyhow::Error| TaskError::Permanent(format!("failed to write the log: {error:#}"));

    let out = File::create(log_path).map_err(|error| workspace_error(&error))?;
    let mut log = slog::SlogWriter::start(BufWriter::new(out), start_time, model).map_err(log_error)?;
    let mut count = 0;

    // Chunks follow each other in time, so only the actions of one chunk need sorting.
    for index in 0..total {
        let mut actions =
            checkpoint::read(&checkpoint::path(workspace, index)).map_err(|error| workspace_error(&error))?;
        actions.sort_by_key(|action| action.offset);

        for action in &actions {
            log.action(action).map_err(log_error)?;
        }

        count += actions.len();
    }

    log.finish(duration)
        .map_err(log_error)?
        .into_inner()
        .map_err(|error| workspace_error(&error.into_error()))?
        .sync_all()
        .map_err(|error| workspace_error(&error))?;

    Ok(count)
}

impl EphemeralTask for AiLogTask {
    type Secrets = SecretString;
    type Request = AiLogParams;

    fn prepare(
        state: &DgwState,
        target: &AiLogTarget,
        request: AiLogParams,
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

        settings.check(state, &api_key)?;

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

        let error = AiLogTask::prepare(&state, &target, params()).expect_err("session is busy");

        assert_eq!(error, TaskErrorCode::RecordingActive);
    }

    #[tokio::test]
    async fn persisted_settings_never_hold_the_api_key() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");

        let params = params();
        assert!(!format!("{params:?}").contains(API_KEY));

        let (settings, api_key) = AiLogTask::prepare(&state, &target(), params).expect("valid task");

        let persisted = serde_json::to_string(&settings).expect("serializable settings");
        assert_eq!(
            persisted,
            r#"{"provider":"openai","model":"gpt-test","baseUrl":null,"maxOutputTokens":null}"#
        );
        assert!(!format!("{settings:?}").contains(API_KEY));
        assert!(!format!("{api_key:?}").contains(API_KEY));
    }

    #[test]
    fn describing_substate_reports_chunk_progress() {
        let substate = serde_json::to_value(AiLogSubstate::Describing { done: 1, total: 3 }).expect("serializable");

        assert_eq!(
            substate,
            serde_json::json!({ "step": "describing", "done": 1, "total": 3 })
        );
    }

    #[test]
    fn halves_are_cut_on_the_line_boundary_closest_to_the_middle() {
        let line = format!("[1.0] {}\n", "a".repeat(94));
        let part = line.repeat(30);

        let (first, second) = split_in_half(&part).expect("long enough");

        assert_eq!(first.len(), 15 * line.len());
        assert_eq!(second.len(), 15 * line.len());

        let uneven = format!("{line}{}", "b".repeat(1900));
        let (first, second) = split_in_half(&uneven).expect("long enough");
        assert_eq!(first, line);
        assert_eq!(second, "b".repeat(1900));

        assert!(split_in_half(&line.repeat(3)).is_none(), "too short");
        assert!(split_in_half(&"c".repeat(MIN_SPLIT_LEN * 2)).is_none(), "one line");
    }

    #[tokio::test]
    async fn invalid_ai_settings_are_refused_with_a_code() {
        let (state, _handles) = DgwState::mock(CONFIG).expect("mock state");
        let mut params = params();
        params.model = " ".to_owned();

        let error = AiLogTask::prepare(&state, &target(), params).expect_err("empty model");

        assert_eq!(error, TaskErrorCode::MissingModel);
    }
}
