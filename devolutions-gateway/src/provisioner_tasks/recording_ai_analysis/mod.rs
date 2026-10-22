//! AI analysis (`recording-ai-analysis`): describes what the user did in one recorded session, and puts the result in
//! the session as its log, in place of the earlier one.
//!
//! [`start`] checks the request and records the Task through the
//! [`ProvisionerTaskRunner`](super::runner::ProvisionerTaskRunner).
//! Each attempt runs the analysis of the AI crate,
//! [`AiClient::analyze_recording`](devolutions_gateway_ai::AiClient::analyze_recording), which keeps its working files
//! next to the session manifest so that a retry resumes where the last attempt stopped, then leaves the log in the
//! session folder, unlisted, under a name of its own Task.
//! Once the runner records the success, the end of the Task lists that log in the manifest in place of the earlier one;
//! a Task that fails removes it instead.
//! The API key and the working files go away when the Task ends.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Weak};

use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_ai::Language;
use devolutions_gateway_ai::recording_analysis::{
    self, Progress, RecordingAnalysisEvent, RecordingFile, RecordingManifest, Recordings, RecordingsError, UsageSoFar,
};
use provisioner_task::{CreateOutcome, ProvisionerTaskRecord, ProvisionerTaskState};
use secrecy::SecretString;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ai::{AiAccess, AiProvider, AiSettings, AiSettingsError, ClientError};
use super::runner::{Attempt, DynProvisionerTaskJobQueue, ProvisionerTask};
use super::{AttemptError, Permanent, Recoverable};
use crate::DgwState;
use crate::artifacts::ArtifactKind;
use crate::config::ConfHandle;
use crate::recording::{FinishedRecordingError, JrecManifest, RecordingMessageSender, RemuxJob, remux_pending};
use crate::secret_store::{SecretId, SecretStore};
use crate::token::AccessScope;

pub const KIND: &str = "recording-ai-analysis";

/// Time from the creation of an AI analysis until it must start.
pub const START_WINDOW: time::Duration = time::Duration::hours(2);

/// Time a running AI analysis may go without progress before it fails.
pub const PROGRESS_TIMEOUT: time::Duration = time::Duration::minutes(30);

/// Time between two checks for a remux of the session.
const REMUX_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Tokens the AI provider counted for a Task, over all its attempts, as kept in its payloads.
///
/// It mirrors [`UsageSoFar`], so a change in the AI crate never changes what we store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenUsage {
    input_tokens: u64,
    output_tokens: u64,
    /// Requests whose tokens the provider did not report, so the two counts are short of what it billed.
    unreported_requests: u64,
}

impl TokenUsage {
    /// The usage in a payload of the Task; none before its first attempt.
    fn of(payload: &serde_json::Value) -> Self {
        payload
            .get("usage")
            .and_then(|usage| serde_json::from_value(usage.clone()).ok())
            .unwrap_or_default()
    }

    /// This usage, with that of the attempt running now.
    fn with(self, attempt: UsageSoFar) -> Self {
        Self {
            input_tokens: self.input_tokens.saturating_add(attempt.input_tokens),
            output_tokens: self.output_tokens.saturating_add(attempt.output_tokens),
            unreported_requests: self.unreported_requests.saturating_add(attempt.unreported_requests),
        }
    }
}

/// Payload of a running AI analysis Task: how far it is, and the tokens it used so far.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Running {
    /// `preparing` until the analysis reports its stage: `reading`, `describing` or `writing`.
    step: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    done: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u64>,
    usage: TokenUsage,
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
    /// Tokens the AI provider counted for the Task, over all its attempts.
    usage: TokenUsage,
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
    progress_timeout: time::Duration,
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
            progress_timeout: PROGRESS_TIMEOUT,
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

/// Where a Task leaves its log until its success is recorded: in the session folder, but not in the manifest, under a
/// name of its own, so the end of another Task leaves it alone.
fn unlisted_log_path(manifest_path: &Utf8Path, task_id: Uuid) -> Utf8PathBuf {
    manifest_path.with_file_name(format!(".ai-analysis-{task_id}.slog"))
}

/// Removes the logs that earlier Tasks of the session left unlisted, so the late end of an earlier Task finds nothing to
/// list over a newer analysis.
async fn remove_unlisted_logs(manifest_path: &Utf8Path) -> std::io::Result<()> {
    let Some(dir) = manifest_path.parent() else {
        return Ok(());
    };
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let is_unlisted_log = name
            .to_str()
            .and_then(|name| name.strip_prefix(".ai-analysis-"))
            .and_then(|name| name.strip_suffix(".slog"))
            .is_some_and(|task_id| Uuid::parse_str(task_id).is_ok());

        if is_unlisted_log {
            match tokio::fs::remove_file(entry.path()).await {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
    }

    Ok(())
}

#[async_trait]
impl ProvisionerTask for RecordingAiAnalysis {
    const KIND: &'static str = KIND;

    const START_SCOPE: AccessScope = AccessScope::RecordingAiAnalysisStart;

    const READ_SCOPE: AccessScope = AccessScope::RecordingAiAnalysisRead;

    type Params = Params;

    type Output = Analysis;

    fn start_window(&self) -> time::Duration {
        START_WINDOW
    }

    fn progress_timeout(&self) -> time::Duration {
        self.progress_timeout
    }

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value {
        json!(Running {
            step: "preparing",
            done: None,
            total: None,
            usage: TokenUsage::of(last),
        })
    }

    fn failed_payload(&self, error: &Permanent, last: &serde_json::Value) -> serde_json::Value {
        json!({ "error": error, "usage": TokenUsage::of(last) })
    }

    async fn run(&self, attempt: &Attempt, params: Params) -> Result<Analysis, AttemptError> {
        let session_id = Uuid::parse_str(&attempt.target).map_err(|error| {
            warn!(task.id = %attempt.task_id, %error, "Invalid session ID");
            AttemptError::Permanent(Permanent::InvalidTask)
        })?;

        // UNTESTED: the key lives until the deadline, which this attempt start moved, so a retry hours after the Task was
        // created still finds it; every move of the deadline must move the key's expiry too.
        self.secrets.set_expiry(SecretId(attempt.task_id), attempt.deadline());

        // Waiting for an earlier analysis of the session is no progress, so the deadline cancels it too.
        let _session = tokio::select! {
            session = lock_session(session_id) => session,
            () = attempt.cancel.cancelled() => return Err(AttemptError::Permanent(Permanent::DeadlinePassed)),
        };

        // A new Task never resumes from what an earlier analysis left, while its retries resume from their own files.
        if attempt.attempts == 1 {
            let manifest_path = self.manifest_path(session_id);

            recording_analysis::discard(&manifest_path, None)
                .await
                .map_err(|error| {
                    error!(task.id = %attempt.task_id, %error, "Failed to remove the earlier AI analysis working files");
                    AttemptError::Permanent(Permanent::Internal)
                })?;

            remove_unlisted_logs(&manifest_path).await.map_err(|error| {
                error!(task.id = %attempt.task_id, %error, "Failed to remove the earlier unlisted AI analysis logs");
                AttemptError::Permanent(Permanent::Internal)
            })?;
        }

        let secret = self.secrets.get(SecretId(attempt.task_id)).map_err(|error| {
            error!(task.id = %attempt.task_id, error = format!("{error:#}"), "Failed to read the API key");
            AttemptError::Permanent(Permanent::Internal)
        })?;

        let Some(secret) = secret else {
            warn!(task.id = %attempt.task_id, attempts = attempt.attempts, "AI analysis lost its API key");
            return Err(AttemptError::Permanent(Permanent::KeyLost));
        };

        let access = AiAccess::from_secret(&secret).map_err(|error| {
            error!(task.id = %attempt.task_id, error = format!("{error:#}"), "Failed to read the API key");
            AttemptError::Permanent(Permanent::Internal)
        })?;

        let settings = AiSettings {
            provider: params.provider,
            model: params.model,
            base_url: access.base_url,
            max_output_tokens: params.max_output_tokens,
        };

        self.analyze(attempt, session_id, settings, params.language, access.api_key)
            .await
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        self.secrets.remove(SecretId(record.id));

        let Ok(session_id) = Uuid::parse_str(&record.target) else {
            return Ok(());
        };

        let manifest_path = self.manifest_path(session_id);
        let log_path = unlisted_log_path(&manifest_path, record.id);
        let _session = lock_session(session_id).await;

        if record.state == ProvisionerTaskState::Succeeded {
            // The success is recorded, so the log takes the place of the earlier analysis.
            self.recordings
                .replace_artifacts(session_id, ArtifactKind::AiAnalysis, &log_path)
                .await
                .context("list the AI analysis log in the session")?;
        } else {
            match tokio::fs::remove_file(&log_path).await {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(anyhow::Error::new(error).context(format!("remove {log_path}")));
                }
                _ => {}
            }
        }

        recording_analysis::discard(&manifest_path, Some(&record.id.to_string()))
            .await
            .context("remove the AI analysis working files")
    }
}

impl RecordingAiAnalysis {
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

        let client = settings.client(&conf, &api_key).map_err(|error| {
            error!(task.id = %attempt.task_id, %error, "Failed to build the AI client");
            AttemptError::Permanent(Permanent::Internal)
        })?;

        let recording = self
            .recordings
            .get_finished(session_id)
            .await
            .map_err(|error| match error {
                FinishedRecordingError::NotFound => AttemptError::Permanent(Permanent::NoRecording),
                error => {
                    error!(task.id = %attempt.task_id, error = format!("{error:#}"), "Failed to read the recording");
                    AttemptError::Permanent(Permanent::Internal)
                }
            })?;

        let manifest = analysis_manifest(&recording.manifest).map_err(|error| match error {
            RecordingsError::Mixed => AttemptError::Permanent(Permanent::MixedRecording),
            _ => AttemptError::Permanent(Permanent::NoRecording),
        })?;
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

        let earlier = TokenUsage::of(&attempt.payload);
        let mut usage = earlier;
        let mut events = request.start();
        let mut recorded = None;

        let analysis = loop {
            match events.recv().await {
                Some(RecordingAnalysisEvent::Progress(progress)) => {
                    // Reading sends an event every half second, so while reading the Task is updated only when the percent
                    // changes.
                    let done = match progress {
                        Progress::Reading { .. } => u64::from(progress.percent()),
                        _ => progress.done_and_total().map_or(0, |(done, _)| done),
                    };
                    let attempt_usage = match progress {
                        Progress::Describing { usage, .. } => Some(usage),
                        _ => None,
                    };
                    let shown = (progress.stage(), done, attempt_usage);

                    if recorded != Some(shown) {
                        recorded = Some(shown);

                        if let Some(attempt_usage) = attempt_usage {
                            usage = earlier.with(attempt_usage);
                        }

                        attempt.report_progress(progress_payload(&progress, usage)).await;
                        self.secrets.set_expiry(SecretId(attempt.task_id), attempt.deadline());
                    }
                }
                Some(RecordingAnalysisEvent::Complete(analysis)) => break analysis,
                Some(RecordingAnalysisEvent::Failure(error)) => {
                    warn!(task.id = %attempt.task_id, %error, "AI analysis attempt failed");
                    return Err(error.into());
                }
                Some(_) => {}
                None => {
                    error!(task.id = %attempt.task_id, "The AI analysis stopped unexpectedly");
                    return Err(AttemptError::Permanent(Permanent::Panicked));
                }
            }
        };

        // The log stays out of the manifest until the runner records the success, so a Task that fails never replaces
        // the earlier analysis.
        let log_path = unlisted_log_path(&manifest_path, attempt.task_id);
        tokio::fs::rename(&analysis.log_path, &log_path)
            .await
            .map_err(|error| {
                error!(task.id = %attempt.task_id, %error, "Failed to keep the AI analysis log");
                AttemptError::Permanent(Permanent::Internal)
            })?;

        debug!(task.id = %attempt.task_id, actions = analysis.actions, "AI analysis log written");

        Ok(Analysis {
            file_name: ArtifactKind::AiAnalysis.file_name(0),
            model: analysis.model,
            usage: earlier.with(analysis.usage),
            prompt_version: analysis.prompt_version,
        })
    }
}

impl RecordingAiAnalysis {
    /// Waits until no remux job of the session is stored, since a remux replaces a video that would be read.
    async fn wait_for_remux(&self, attempt: &Attempt, dir: &Utf8Path) -> Result<(), AttemptError> {
        loop {
            let jobs = self.job_queue.stored_jobs(RemuxJob::NAME).await.map_err(|error| {
                warn!(task.id = %attempt.task_id, error = format!("{error:#}"), "Failed to list the remux jobs");
                AttemptError::Recoverable(Recoverable::Storage)
            })?;

            if !remux_pending(&jobs, dir) {
                return Ok(());
            }

            debug!(task.id = %attempt.task_id, %dir, "Waiting for the remux of the session");

            tokio::select! {
                () = tokio::time::sleep(REMUX_POLL_INTERVAL) => {}
                () = attempt.cancel.cancelled() => return Err(AttemptError::Permanent(Permanent::DeadlinePassed)),
            }
        }
    }
}

/// The payload of a running AI analysis Task: its progress, for whoever asks about it, and the tokens it used so far.
fn progress_payload(progress: &Progress, usage: TokenUsage) -> serde_json::Value {
    let (done, total) = progress.done_and_total().unzip();

    json!(Running {
        step: progress.stage(),
        done,
        total,
        usage,
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
