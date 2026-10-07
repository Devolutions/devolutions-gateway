//! AI analysis (`recording.ai-analysis`): describes what the user did in one recorded session, and adds the result to
//! the session as a new log.
//!
//! [`start`] records the Task and queues its job. The job runs the analysis of the AI crate,
//! [`AiClient::analyze_recording`](devolutions_gateway_ai::AiClient::analyze_recording), which keeps its working files
//! next to the session manifest so that a retry resumes where the last attempt stopped, then adds the log to the
//! session. The working files go away when the Task ends.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Weak};

use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_ai::Usage;
use devolutions_gateway_ai::recording_analysis::{self, Progress, RecordingFile, RecordingManifest};
use devolutions_gateway_ai::session_actions::PROMPT_VERSION;
use provisioner_task::{CreateOutcome, NewProvisionerTask, ProvisionerTask};
use secrecy::SecretString;
use serde_json::json;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::AttemptError;
use super::ai::{AiProvider, AiSettings, AiSettingsError, ClientError};
use super::ai_key_store::AiAccess;
use crate::DgwState;
use crate::artifacts::ArtifactKind;
use crate::recording::{FinishedRecordingError, JrecManifest, RecordingMessageSender};

pub const KIND: &str = "recording.ai-analysis";

/// Time an AI analysis gets from its creation to its end, waiting and retries included.
pub const TASK_DEADLINE: time::Duration = time::Duration::hours(2);

/// Time one attempt of an AI analysis gets.
pub const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

const KEY_LOST: &str = "the API key is no longer available, such as after a Gateway restart";

/// Tokens counted by the AI provider, as kept in Task results.
///
/// It mirrors [`Usage`], so a change in the AI crate never changes what we store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenUsage {
    input_tokens: u64,
    output_tokens: u64,
}

impl From<Usage> for TokenUsage {
    fn from(usage: Usage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        }
    }
}

/// What a caller asks for when it starts an AI analysis.
#[derive(Debug)]
pub struct StartRequest {
    /// Chosen by the caller, so it can ask again safely.
    pub task_id: Uuid,
    pub session_id: Uuid,
    pub settings: AiSettings,
    pub api_key: SecretString,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StartOutcome {
    /// A new Task is recorded and its job is queued.
    Created(ProvisionerTask),
    /// The same request came in before; nothing new runs.
    Existing(ProvisionerTask),
    /// The Task ID is already used for something else.
    IdConflict(ProvisionerTask),
    /// Another AI analysis of this session is not finished yet.
    TargetBusy { active_task_id: Uuid },
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    InvalidSettings(AiSettingsError),
    /// The session is still recording, so there is nothing complete to analyse yet.
    #[error("session is still recording")]
    RecordingActive,
    /// The session has no recording to analyse.
    #[error("session has no recording")]
    RecordingNotFound,
    #[error(transparent)]
    Internal(anyhow::Error),
}

/// What an AI analysis Task records as its parameters: the AI settings without the API key and the base URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    provider: AiProvider,
    model: String,
    max_output_tokens: Option<u32>,
}

/// Result payload of a successful AI analysis.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Analysis {
    /// Name of the new log in the session manifest, such as `ai-analysis-0.slog`.
    file_name: String,
    /// Model that wrote the log, as reported by the AI provider; the requested model when it reports none.
    model: String,
    /// Tokens the AI provider counted for the log, answers cut and asked again included.
    ///
    /// Absent when the provider did not report them for every request.
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<TokenUsage>,
    prompt_version: &'static str,
}

/// Records an AI analysis Task and queues the job that runs it.
///
/// Only a new Task keeps the API key and queues a job; asking again for a known Task changes nothing, even while its
/// session is recording again.
pub async fn start(state: &DgwState, request: StartRequest) -> Result<StartOutcome, StartError> {
    let StartRequest {
        task_id,
        session_id,
        settings,
        api_key,
    } = request;

    let conf = state.conf_handle.get_conf();

    match settings.client(&conf, &api_key) {
        Ok(_) => {}
        Err(ClientError::Build(error)) => {
            debug!(%error, "Invalid AI settings");
            return Err(StartError::InvalidSettings(AiSettingsError::from(&error)));
        }
        Err(ClientError::HttpClient(error)) => {
            return Err(StartError::Internal(
                anyhow::Error::new(error).context("build the HTTP client for the AI provider"),
            ));
        }
    }

    let params = Params {
        provider: settings.provider,
        model: settings.model,
        max_output_tokens: settings.max_output_tokens,
    };
    let params = serde_json::to_value(params)
        .context("serialize the AI analysis parameters")
        .map_err(StartError::Internal)?;

    let now = OffsetDateTime::now_utc();
    let target = session_id.to_string();

    // A repeated request gets its Task back whatever its session does now, so the ID is looked up first.
    let known = state
        .provisioner_tasks
        .get(task_id, now)
        .await
        .map_err(StartError::Internal)?;

    if let Some(task) = known {
        let same_request = task.kind == KIND && task.target == target && task.params == params;
        return Ok(if same_request {
            StartOutcome::Existing(task)
        } else {
            StartOutcome::IdConflict(task)
        });
    }

    if state.recordings.active_recordings.contains(session_id) {
        return Err(StartError::RecordingActive);
    }

    match state.recordings.get_finished(session_id).await {
        Ok(_) => {}
        Err(FinishedRecordingError::Recording) => return Err(StartError::RecordingActive),
        Err(FinishedRecordingError::NotFound) => return Err(StartError::RecordingNotFound),
        Err(FinishedRecordingError::Other(error)) => {
            return Err(StartError::Internal(error.context("read the recording")));
        }
    }

    let outcome = state
        .provisioner_tasks
        .create(
            NewProvisionerTask {
                id: task_id,
                kind: KIND.to_owned(),
                target,
                params,
                deadline_at: now + TASK_DEADLINE,
            },
            now,
        )
        .await
        .map_err(StartError::Internal)?;

    let task = match outcome {
        CreateOutcome::Created(task) => task,
        CreateOutcome::Existing(task) => return Ok(StartOutcome::Existing(task)),
        CreateOutcome::IdConflict(task) => return Ok(StartOutcome::IdConflict(task)),
        CreateOutcome::TargetBusy(active) => {
            return Ok(StartOutcome::TargetBusy {
                active_task_id: active.id,
            });
        }
    };

    // The job may run as soon as it is queued, so the key must be in place first.
    state.ai_keys.insert(
        task_id,
        AiAccess {
            api_key,
            base_url: settings.base_url,
        },
        task.deadline_at,
    );

    if let Err(error) = state
        .job_queue_handle
        .enqueue(RecordingAiAnalysisJob::new(task_id, state.clone()))
        .await
    {
        error!(task.id = %task_id, error = format!("{error:#}"), "Failed to queue the AI analysis");
        fail(
            state,
            task_id,
            Some(session_id),
            failure("not queued", &format!("{error:#}"), 0),
        )
        .await;
        return Err(StartError::Internal(error));
    }

    info!(task.id = %task_id, session.id = %session_id, "AI analysis queued");

    Ok(StartOutcome::Created(task))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobDef {
    task_id: Uuid,
}

/// Runs one attempt of an AI analysis Task; the job queue runs it again while it asks for a retry.
pub struct RecordingAiAnalysisJob {
    task_id: Uuid,
    state: DgwState,
    attempt_timeout: std::time::Duration,
}

impl RecordingAiAnalysisJob {
    pub const NAME: &'static str = "recording-ai-analysis";

    pub fn new(task_id: Uuid, state: DgwState) -> Self {
        Self {
            task_id,
            state,
            attempt_timeout: ATTEMPT_TIMEOUT,
        }
    }

    pub fn read_json(json: &str, state: DgwState) -> anyhow::Result<Self> {
        let def: JobDef = serde_json::from_str(json).context("failed to deserialize RecordingAiAnalysisJob")?;
        Ok(Self::new(def.task_id, state))
    }
}

#[async_trait]
impl job_queue::Job for RecordingAiAnalysisJob {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(&JobDef { task_id: self.task_id }).context("failed to serialize RecordingAiAnalysisJob")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        run_attempt(&self.state, self.task_id, self.attempt_timeout).await
    }
}

/// Returns an error only to ask the job queue for another attempt.
async fn run_attempt(state: &DgwState, task_id: Uuid, attempt_timeout: std::time::Duration) -> anyhow::Result<()> {
    let tasks = &state.provisioner_tasks;
    let now = OffsetDateTime::now_utc();

    let started = tasks
        .start_attempt(task_id, json!({ "step": "preparing" }), now)
        .await?;

    // A finished Task is still read: its session tells which working files to remove.
    let Some(task) = tasks.get(task_id, now).await? else {
        debug!(task.id = %task_id, "AI analysis Task is unknown, so this attempt does not run");
        end(state, task_id, None).await;
        return Ok(());
    };

    let attempts = task.attempts;

    let (session_id, params) = match parse_task(&task) {
        Ok(parsed) => parsed,
        Err(error) => {
            error!(task.id = %task_id, error = format!("{error:#}"), "Invalid AI analysis Task");
            fail(
                state,
                task_id,
                None,
                failure("invalid task", &format!("{error:#}"), attempts),
            )
            .await;
            return Ok(());
        }
    };

    if !started {
        debug!(task.id = %task_id, "AI analysis is over, so this attempt does not run");
        end(state, task_id, Some(session_id)).await;
        return Ok(());
    }

    let Some(access) = state.ai_keys.get(task_id, now) else {
        warn!(task.id = %task_id, attempts, "AI analysis lost its API key");
        fail(
            state,
            task_id,
            Some(session_id),
            failure("key lost", KEY_LOST, attempts),
        )
        .await;
        return Ok(());
    };

    let settings = AiSettings {
        provider: params.provider,
        model: params.model,
        base_url: access.base_url,
        max_output_tokens: params.max_output_tokens,
    };

    info!(task.id = %task_id, session.id = %session_id, attempts, "AI analysis attempt started");

    let cancel = CancellationToken::new();

    // The attempt has its own Tokio task, so a panic fails the Task instead of leaving it running.
    let mut handle = tokio::spawn(analyze(
        state.clone(),
        task_id,
        session_id,
        settings,
        access.api_key,
        cancel.clone(),
    ));

    let joined = match tokio::time::timeout(attempt_timeout, &mut handle).await {
        Ok(joined) => joined,
        Err(_) => {
            // Aborting cannot stop its blocking steps, so the attempt is cancelled and awaited instead: the next
            // attempt never shares the working files with it.
            cancel.cancel();
            handle.await
        }
    };

    let outcome = match joined {
        Ok(Err(AttemptError::Cancelled)) => Err(AttemptError::Transient(format!(
            "the attempt took longer than {attempt_timeout:?}"
        ))),
        Ok(outcome) => outcome,
        Err(_) => Err(AttemptError::Permanent("the attempt panicked".to_owned())),
    };

    match outcome {
        Ok(analysis) => {
            // An error here must not ask for a retry: the log is already added to the session.
            match tasks.succeed(task_id, json!(analysis), OffsetDateTime::now_utc()).await {
                Ok(true) => info!(
                    task.id = %task_id,
                    session.id = %session_id,
                    attempts,
                    file = %analysis.file_name,
                    model = %analysis.model,
                    usage = ?analysis.usage,
                    "AI analysis succeeded"
                ),
                Ok(false) => warn!(
                    task.id = %task_id,
                    session.id = %session_id,
                    file = %analysis.file_name,
                    "AI analysis added its log after its Task had ended, such as past its deadline; the Task keeps its earlier end"
                ),
                Err(error) => error!(
                    task.id = %task_id,
                    file = %analysis.file_name,
                    error = format!("{error:#}"),
                    "Failed to record the AI analysis result"
                ),
            }

            end(state, task_id, Some(session_id)).await;
        }
        Err(AttemptError::Transient(details)) if attempts < crate::job_queue::MAX_ATTEMPTS => {
            warn!(task.id = %task_id, attempts, %details, "AI analysis attempt failed; it will be retried");
            anyhow::bail!("AI analysis attempt failed: {details}");
        }
        Err(AttemptError::Transient(details)) => {
            warn!(task.id = %task_id, attempts, %details, "AI analysis failed after its last attempt");
            fail(
                state,
                task_id,
                Some(session_id),
                failure("attempts exhausted", &details, attempts),
            )
            .await;
        }
        Err(AttemptError::Permanent(details)) => {
            warn!(task.id = %task_id, attempts, %details, "AI analysis failed");
            fail(
                state,
                task_id,
                Some(session_id),
                failure("permanent error", &details, attempts),
            )
            .await;
        }
        Err(AttemptError::Cancelled) => unreachable!("a cancelled attempt is reported as a timeout above"),
    }

    Ok(())
}

fn parse_task(task: &ProvisionerTask) -> anyhow::Result<(Uuid, Params)> {
    let session_id = Uuid::parse_str(&task.target).context("invalid session ID")?;
    let params = serde_json::from_value(task.params.clone()).context("invalid parameters")?;
    Ok((session_id, params))
}

fn failure(reason: &str, details: &str, attempts: u32) -> serde_json::Value {
    json!({ "reason": reason, "details": details, "attempts": attempts })
}

async fn fail(state: &DgwState, task_id: Uuid, session_id: Option<Uuid>, payload: serde_json::Value) {
    if let Err(error) = state
        .provisioner_tasks
        .fail(task_id, payload, OffsetDateTime::now_utc())
        .await
    {
        error!(task.id = %task_id, error = format!("{error:#}"), "Failed to record the AI analysis failure");
    }

    end(state, task_id, session_id).await;
}

/// Drops what an AI analysis keeps only while it runs: its API key and the working files of its session.
async fn end(state: &DgwState, task_id: Uuid, session_id: Option<Uuid>) {
    state.ai_keys.remove(task_id);

    let Some(session_id) = session_id else {
        return;
    };

    let manifest_path = manifest_path(state, session_id);
    let _session = lock_session(session_id).await;

    if let Err(error) = recording_analysis::discard(&manifest_path).await {
        warn!(task.id = %task_id, session.id = %session_id, %error, "Failed to remove the AI analysis working files");
    }
}

fn manifest_path(state: &DgwState, session_id: Uuid) -> Utf8PathBuf {
    state
        .conf_handle
        .get_conf()
        .recording_path
        .join(session_id.to_string())
        .join("recording.json")
}

/// Waits until no other AI analysis of the session runs.
///
/// The working files belong to the session, and a Task that ended past its deadline may still run an attempt while
/// another Task of the session starts.
async fn lock_session(session_id: Uuid) -> tokio::sync::OwnedMutexGuard<()> {
    static LOCKS: LazyLock<parking_lot::Mutex<HashMap<Uuid, Weak<tokio::sync::Mutex<()>>>>> =
        LazyLock::new(Default::default);

    let lock = {
        let mut locks = LOCKS.lock();
        locks.retain(|_, lock| lock.strong_count() > 0);

        match locks.get(&session_id).and_then(Weak::upgrade) {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(session_id, Arc::downgrade(&lock));
                lock
            }
        }
    };

    lock.lock_owned().await
}

async fn report_progress(state: &DgwState, task_id: Uuid, progress: Progress) {
    let payload = json!({
        "step": "describing",
        "done": progress.described_chunks,
        "total": progress.total_chunks,
    });

    if let Err(error) = state.provisioner_tasks.update_running(task_id, payload).await {
        warn!(task.id = %task_id, error = format!("{error:#}"), "Failed to record the AI analysis progress");
    }
}

/// What the AI crate needs from the session manifest.
fn analysis_manifest(manifest: &JrecManifest) -> RecordingManifest {
    RecordingManifest {
        start_time: manifest.start_time(),
        duration: manifest.duration(),
        files: manifest
            .files()
            .iter()
            .map(|file| RecordingFile {
                file_name: file.file_name().to_owned(),
                start_time: file.start_time(),
            })
            .collect(),
    }
}

async fn analyze(
    state: DgwState,
    task_id: Uuid,
    session_id: Uuid,
    settings: AiSettings,
    api_key: SecretString,
    cancel: CancellationToken,
) -> Result<Analysis, AttemptError> {
    let conf = state.conf_handle.get_conf();

    let client = settings
        .client(&conf, &api_key)
        .map_err(|error| AttemptError::Permanent(error.to_string()))?;

    let _session = lock_session(session_id).await;

    let recording = state
        .recordings
        .get_finished(session_id)
        .await
        .map_err(|error| AttemptError::Permanent(format!("{error:#}")))?;

    let manifest = analysis_manifest(&recording.manifest);
    let manifest_path = recording.manifest_path();

    let mut request = client
        .analyze_recording(&manifest, &manifest_path)
        .cancellation(cancel)
        .on_progress(|progress| report_progress(&state, task_id, progress));

    if let Some(max_output_tokens) = settings.max_output_tokens {
        request = request.max_output_tokens(max_output_tokens);
    }

    let analysis = request.send().await?;

    let file_name = add_log(&state.recordings, session_id, &analysis.log_path)
        .await
        .map_err(|error| AttemptError::Permanent(format!("failed to add the log: {error:#}")))?;

    debug!(task.id = %task_id, file = %file_name, actions = analysis.actions, "Session log added");

    Ok(Analysis {
        file_name,
        model: analysis.model,
        usage: analysis.usage.map(TokenUsage::from),
        prompt_version: PROMPT_VERSION,
    })
}

/// Adds the complete log the analysis left next to the manifest to the session.
async fn add_log(recordings: &RecordingMessageSender, session_id: Uuid, log_path: &Utf8Path) -> anyhow::Result<String> {
    let artifact_path = recordings.add_artifact(session_id, ArtifactKind::AiAnalysis).await?;

    // The log is in the session folder, so a rename moves it in at once and the session never holds a partial one.
    tokio::fs::rename(log_path, &artifact_path)
        .await
        .with_context(|| format!("move the log to {artifact_path}"))?;

    Ok(artifact_path
        .file_name()
        .context("artifact path has no file name")?
        .to_owned())
}
