//! AI analysis (`recording-ai-analysis`): describes what the user did in one recorded session, and adds the result to
//! the session as a new log.
//!
//! [`start`] checks the request and records the Task through the
//! [`ProvisionerTaskRunner`](super::runner::ProvisionerTaskRunner).
//! Each attempt runs the analysis of the AI crate,
//! [`AiClient::analyze_recording`](devolutions_gateway_ai::AiClient::analyze_recording), which keeps its working files
//! next to the session manifest so that a retry resumes where the last attempt stopped, then adds the log to the session.
//! The API key and the working files go away when the Task ends.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Weak};

use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_ai::recording_analysis::{
    self, Progress, RecordingAnalysisEvent, RecordingFile, RecordingManifest, Recordings, RecordingsError,
};
use devolutions_gateway_ai::{Language, Usage};
use provisioner_task::{CreateOutcome, ProvisionerTaskRecord};
use secrecy::SecretString;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::AttemptError;
use super::ai::{AiAccess, AiProvider, AiSettings, AiSettingsError, ClientError};
use super::runner::{Attempt, DynProvisionerTaskJobQueue, ProvisionerTask};
use crate::DgwState;
use crate::artifacts::ArtifactKind;
use crate::config::ConfHandle;
use crate::recording::{FinishedRecordingError, JrecManifest, RecordingMessageSender, RemuxJob, remux_pending};
use crate::secret_store::{SecretId, SecretStore};
use crate::token::AccessScope;

pub const KIND: &str = "recording-ai-analysis";

/// Time from the creation of an AI analysis during which its attempts may start, waiting and retries included.
pub const ATTEMPT_START_WINDOW: time::Duration = time::Duration::hours(2);

/// Time one attempt of an AI analysis gets.
pub const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Time between two checks for a remux of the session.
const REMUX_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

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
    /// Language of the analysis; English when absent.
    pub language: Option<Language>,
    pub api_key: SecretString,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StartOutcome {
    /// A new Task is recorded and its job is queued.
    Created(ProvisionerTaskRecord),
    /// The same request came in before; nothing new runs.
    Existing(ProvisionerTaskRecord),
    /// The Task ID is already used for something else.
    IdConflict(ProvisionerTaskRecord),
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

/// What an AI analysis Task records as its parameters: the AI settings without the API key and the base URL, and the
/// language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    provider: AiProvider,
    model: String,
    max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    language: Option<Language>,
}

/// Result payload of a successful AI analysis.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    /// Name of the new log in the session manifest, such as `ai-analysis-0.slog`.
    file_name: String,
    /// Model that wrote the log, as reported by the AI provider; the requested model when it reports none.
    model: String,
    /// Tokens the AI provider counted for the log, answers cut and asked again included.
    ///
    /// Absent when the provider did not report them for every request.
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<TokenUsage>,
    /// Versions of the prompts that wrote the log, such as
    /// `session-actions-3f9a1c2b7e4d0a51+session-summary-8b20e9a4c1f70d36`.
    prompt_version: String,
}

/// Records an AI analysis Task, whose job the [`ProvisionerTaskRunner`](super::runner::ProvisionerTaskRunner) queues.
///
/// Only a new Task keeps the API key; asking again for a known Task changes nothing, even while its session is
/// recording again.
pub async fn start(state: &DgwState, request: StartRequest) -> Result<StartOutcome, StartError> {
    let StartRequest {
        task_id,
        session_id,
        settings,
        language,
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
        language,
    };
    let target = session_id.to_string();

    // A repeated request gets its Task back whatever its session does now, so the ID is looked up first.
    let known = state
        .provisioner_tasks
        .get(task_id, OffsetDateTime::now_utc())
        .await
        .map_err(StartError::Internal)?;

    if let Some(record) = known {
        let params = serde_json::to_value(&params)
            .context("serialize the AI analysis parameters")
            .map_err(StartError::Internal)?;
        let same_request = record.kind == KIND && record.target == target && record.params == params;
        return Ok(if same_request {
            StartOutcome::Existing(record)
        } else {
            StartOutcome::IdConflict(record)
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

    let access = AiAccess {
        api_key,
        base_url: settings.base_url,
    };

    let outcome = state
        .provisioner_tasks
        .create::<RecordingAiAnalysis>(task_id, target, &params, |record| {
            // The job may run as soon as it is queued, so the key must be in place first.
            state
                .secrets
                .insert(SecretId(record.id), &access.to_secret()?, record.deadline_at)
        })
        .await
        .map_err(StartError::Internal)?;

    Ok(match outcome {
        CreateOutcome::Created(task) => {
            debug!(task.id = %task_id, session.id = %session_id, "AI analysis queued");
            StartOutcome::Created(task)
        }
        CreateOutcome::Existing(task) => StartOutcome::Existing(task),
        CreateOutcome::IdConflict(task) => StartOutcome::IdConflict(task),
        CreateOutcome::TargetBusy(active) => StartOutcome::TargetBusy {
            active_task_id: active.id,
        },
    })
}

/// The `recording-ai-analysis` provisioner task.
pub struct RecordingAiAnalysis {
    conf_handle: ConfHandle,
    recordings: RecordingMessageSender,
    secrets: SecretStore,
    job_queue: DynProvisionerTaskJobQueue,
    attempt_timeout: std::time::Duration,
}

impl RecordingAiAnalysis {
    pub fn new(
        conf_handle: ConfHandle,
        recordings: RecordingMessageSender,
        secrets: SecretStore,
        job_queue: DynProvisionerTaskJobQueue,
    ) -> Self {
        Self {
            conf_handle,
            recordings,
            secrets,
            job_queue,
            attempt_timeout: ATTEMPT_TIMEOUT,
        }
    }

    fn manifest_path(&self, session_id: Uuid) -> Utf8PathBuf {
        self.conf_handle
            .get_conf()
            .recording_path
            .join(session_id.to_string())
            .join("recording.json")
    }
}

#[async_trait]
impl ProvisionerTask for RecordingAiAnalysis {
    const KIND: &'static str = KIND;

    const START_SCOPE: AccessScope = AccessScope::RecordingAiAnalysisStart;

    const READ_SCOPE: AccessScope = AccessScope::RecordingAiAnalysisRead;

    type Params = Params;

    type Output = Analysis;

    fn attempt_start_window(&self) -> time::Duration {
        ATTEMPT_START_WINDOW
    }

    fn attempt_timeout(&self) -> std::time::Duration {
        self.attempt_timeout
    }

    async fn run(&self, attempt: &Attempt, params: Params) -> Result<Analysis, AttemptError> {
        let session_id = Uuid::parse_str(&attempt.target).map_err(|error| AttemptError::Failed {
            reason: "invalid task",
            details: format!("invalid session ID: {error}"),
        })?;

        // Waiting for an earlier analysis of the session counts in the attempt time, so a timeout cancels it too.
        let _session = tokio::select! {
            session = lock_session(session_id) => session,
            () = attempt.cancel.cancelled() => return Err(AttemptError::Cancelled),
        };

        // A new Task is a hard restart, so the session loses its earlier analysis even when the Task then fails, such as
        // on a lost key. Every attempt clears, since an earlier one may have ended before it could.
        self.clear_earlier_analysis(attempt, session_id).await?;

        let secret = self
            .secrets
            .get(SecretId(attempt.task_id))
            .map_err(|error| AttemptError::Permanent(format!("{error:#}")))?;

        let Some(secret) = secret else {
            warn!(task.id = %attempt.task_id, attempts = attempt.attempts, "AI analysis lost its API key");
            return Err(AttemptError::Failed {
                reason: "key lost",
                details: KEY_LOST.to_owned(),
            });
        };

        let access = AiAccess::from_secret(&secret).map_err(|error| AttemptError::Permanent(format!("{error:#}")))?;

        let settings = AiSettings {
            provider: params.provider,
            model: params.model,
            base_url: access.base_url,
            max_output_tokens: params.max_output_tokens,
        };

        self.analyze(attempt, session_id, settings, params.language, access.api_key)
            .await
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) {
        self.secrets.remove(SecretId(record.id));

        let Ok(session_id) = Uuid::parse_str(&record.target) else {
            return;
        };

        let manifest_path = self.manifest_path(session_id);
        let _session = lock_session(session_id).await;

        if let Err(error) = recording_analysis::discard(&manifest_path, Some(&record.id.to_string())).await {
            warn!(task.id = %record.id, session.id = %session_id, %error, "Failed to remove the AI analysis working files");
        }
    }
}

impl RecordingAiAnalysis {
    /// Removes the analysis an earlier Task added to the session, and on the first attempt the working files any
    /// analysis left; later attempts are job retries, which resume from their own working files.
    async fn clear_earlier_analysis(&self, attempt: &Attempt, session_id: Uuid) -> Result<(), AttemptError> {
        let cleared = async {
            self.recordings
                .clear_artifacts(session_id, ArtifactKind::AiAnalysis)
                .await?;

            if attempt.attempts == 1 {
                recording_analysis::discard(&self.manifest_path(session_id), None).await?;
            }

            anyhow::Ok(())
        };

        cleared
            .await
            .map_err(|error| AttemptError::Permanent(format!("failed to remove the earlier AI analysis: {error:#}")))
    }

    /// Runs the analysis while the caller holds the lock of the session.
    async fn analyze(
        &self,
        attempt: &Attempt,
        session_id: Uuid,
        settings: AiSettings,
        language: Option<Language>,
        api_key: SecretString,
    ) -> Result<Analysis, AttemptError> {
        let conf = self.conf_handle.get_conf();

        let client = settings
            .client(&conf, &api_key)
            .map_err(|error| AttemptError::Permanent(error.to_string()))?;

        let recording = self
            .recordings
            .get_finished(session_id)
            .await
            .map_err(|error| AttemptError::Permanent(format!("{error:#}")))?;

        let manifest =
            analysis_manifest(&recording.manifest).map_err(|error| AttemptError::Permanent(error.to_string()))?;
        let manifest_path = recording.manifest_path();

        self.wait_for_remux(attempt, &recording.dir).await?;

        let mut request = client
            .analyze_recording(&manifest, &manifest_path)
            .owner(attempt.task_id.to_string())
            .cancellation(attempt.cancel.clone());

        if let Some(max_output_tokens) = settings.max_output_tokens {
            request = request.max_output_tokens(max_output_tokens);
        }

        if let Some(language) = language {
            request = request.language(language);
        }

        let mut events = request.start();
        let mut recorded: Option<(&'static str, u64)> = None;

        let analysis = loop {
            match events.recv().await {
                Some(RecordingAnalysisEvent::Progress(progress)) => {
                    // Reading sends an event every half second, so while reading the Task is updated only when the percent
                    // changes.
                    let shown = match progress {
                        Progress::Reading { .. } => (progress.stage(), u64::from(progress.percent())),
                        _ => (progress.stage(), progress.done_and_total().map_or(0, |(done, _)| done)),
                    };
                    if recorded != Some(shown) {
                        recorded = Some(shown);
                        attempt.report_progress(progress_payload(&progress)).await;
                    }
                }
                Some(RecordingAnalysisEvent::Complete(analysis)) => break analysis,
                Some(RecordingAnalysisEvent::Failure(error)) => return Err(error.into()),
                Some(_) => {}
                None => {
                    return Err(AttemptError::Permanent(
                        "the AI analysis stopped unexpectedly".to_owned(),
                    ));
                }
            }
        };

        let file_name = add_log(&self.recordings, session_id, &analysis.log_path)
            .await
            .map_err(|error| AttemptError::Permanent(format!("failed to add the log: {error:#}")))?;

        debug!(task.id = %attempt.task_id, file = %file_name, actions = analysis.actions, "Session log added");

        Ok(Analysis {
            file_name,
            model: analysis.model,
            usage: analysis.usage.map(TokenUsage::from),
            prompt_version: analysis.prompt_version,
        })
    }
}

impl RecordingAiAnalysis {
    /// Waits until no remux job of the session is stored, since a remux replaces a video that would be read.
    async fn wait_for_remux(&self, attempt: &Attempt, dir: &Utf8Path) -> Result<(), AttemptError> {
        loop {
            let jobs = self
                .job_queue
                .stored_jobs(RemuxJob::NAME)
                .await
                .map_err(|error| AttemptError::Transient(format!("failed to list the remux jobs: {error:#}")))?;

            if !remux_pending(&jobs, dir) {
                return Ok(());
            }

            debug!(task.id = %attempt.task_id, %dir, "Waiting for the remux of the session");

            tokio::select! {
                () = tokio::time::sleep(REMUX_POLL_INTERVAL) => {}
                () = attempt.cancel.cancelled() => return Err(AttemptError::Cancelled),
            }
        }
    }
}

/// The payload of a running AI analysis Task: its progress, for whoever asks about it.
fn progress_payload(progress: &Progress) -> serde_json::Value {
    let (done, total) = progress.done_and_total().unzip();

    json!({
        "step": progress.stage(),
        "done": done,
        "total": total,
    })
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

/// What the AI crate needs from the session manifest; a session without recordings, or with both terminal and video ones,
/// cannot be analyzed.
fn analysis_manifest(manifest: &JrecManifest) -> Result<RecordingManifest, RecordingsError> {
    let recordings = Recordings::from_files(manifest.files().iter().map(|file| RecordingFile {
        file_name: file.file_name().to_owned(),
        start_time: file.start_time(),
    }))?;

    Ok(RecordingManifest {
        start_time: manifest.start_time(),
        duration: manifest.duration(),
        recordings,
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
