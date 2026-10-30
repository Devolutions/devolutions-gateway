//! AI analysis (`recording-ai-analysis`): describes what the user did in one recorded session, and puts the result in
//! the session as its log, in place of the earlier one.
//!
//! [`start`] checks the request and records the Task with [`create`](super::create).
//! Each attempt runs the analysis of the AI crate,
//! [`AiClient::analyze_recording`](devolutions_gateway_ai::AiClient::analyze_recording), which keeps its working files
//! next to the session manifest so that a retry resumes where the last attempt stopped, then leaves the log in the
//! session folder.
//! The step that records the success lists that log in the manifest in place of the earlier one, so a succeeded Task
//! always has its log listed; a Task that fails removes it instead.
//! The API key and the working files go away when the Task ends.

mod failure;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Weak};

use anyhow::Context as _;
use async_trait::async_trait;
use camino::Utf8PathBuf;
use devolutions_gateway_ai::Language;
use devolutions_gateway_ai::recording_analysis::{
    self, Progress, RecordingAnalysisEvent, RecordingFile, RecordingManifest, Recordings, RecordingsError, UsageSoFar,
};
use provisioner_task::{CreateOutcome, ProvisionerTaskRecord};
use secrecy::SecretString;
use serde_json::json;
use uuid::Uuid;

pub use self::failure::{AnalysisError, BadAnswer, Failure, Recoverable};
use super::ai::{AiAccess, AiProvider, AiSettings, AiSettingsError, ClientError};
use super::{Attempt, Permanent, ProvisionerTask};
use crate::DgwState;
use crate::artifacts::ArtifactKind;
use crate::config::ConfHandle;
use crate::job_queue::InMemoryJobDependencies;
use crate::recording::{FinishedRecordingError, JrecManifest, RecordingMessageSender};
use crate::secret_store::{SecretId, SecretStore};

pub const KIND: &str = "recording-ai-analysis";

/// Time from the creation of an AI analysis until it must start.
pub const START_WINDOW: time::Duration = time::Duration::hours(2);

/// Time a running AI analysis may go without progress before it fails.
pub const PROGRESS_TIMEOUT: time::Duration = time::Duration::minutes(30);

/// Time to wait after the first recoverable failure, doubled after each next one.
pub const FIRST_RETRY_DELAY: time::Duration = time::Duration::seconds(30);

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
    /// Where the analysis left the log, until the success lists it under `file_name`.
    #[serde(skip)]
    log_path: Utf8PathBuf,
}

/// Records an AI analysis Task and stores its job.
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
        .get(task_id)
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

    let secrets = state.secrets.clone();
    let outcome = state
        .provisioner_tasks
        .create(
            RecordingAiAnalysis::new(
                state.conf_handle.clone(),
                state.recordings.clone(),
                state.secrets.clone(),
            ),
            task_id,
            target,
            &params,
            move |record| {
                // The job may run as soon as the Task is recorded, so the key must be in place first.
                secrets.insert(SecretId(record.id), &access.to_secret()?, record.deadline_at)
            },
        )
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

/// Returns the Task with this ID, of any kind; one past its deadline is failed first.
pub async fn get(state: &DgwState, task_id: Uuid) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
    state.provisioner_tasks.get(task_id).await
}

/// The `recording-ai-analysis` provisioner task.
pub struct RecordingAiAnalysis {
    conf_handle: ConfHandle,
    recordings: RecordingMessageSender,
    secrets: SecretStore,
    progress_timeout: time::Duration,
    first_retry_delay: time::Duration,
}

impl RecordingAiAnalysis {
    fn new(conf_handle: ConfHandle, recordings: RecordingMessageSender, secrets: SecretStore) -> Self {
        Self {
            conf_handle,
            recordings,
            secrets,
            progress_timeout: PROGRESS_TIMEOUT,
            first_retry_delay: FIRST_RETRY_DELAY,
        }
    }

    pub(crate) fn from_dependencies(dependencies: &InMemoryJobDependencies) -> Self {
        Self::new(
            dependencies.conf_handle.clone(),
            dependencies.recordings.clone(),
            dependencies.secrets.clone(),
        )
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

    const START_WINDOW: time::Duration = START_WINDOW;

    type Params = Params;

    type Output = Analysis;

    type Failure = Failure;

    type Recoverable = Recoverable;

    fn progress_timeout(&self) -> time::Duration {
        self.progress_timeout
    }

    fn retry_delay(&self, attempts: u32) -> time::Duration {
        self.first_retry_delay * 2u32.pow(attempts.saturating_sub(1))
    }

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value {
        json!(Running {
            step: "preparing",
            done: None,
            total: None,
            usage: TokenUsage::of(last),
        })
    }

    fn failed_payload(&self, error: &Permanent<Failure, Recoverable>, last: &serde_json::Value) -> serde_json::Value {
        json!({ "error": error, "usage": TokenUsage::of(last) })
    }

    async fn run(&self, attempt: &Attempt, params: Params) -> Result<Analysis, AnalysisError> {
        let session_id = Uuid::parse_str(&attempt.target).map_err(|error| {
            warn!(task.id = %attempt.task_id, %error, "Invalid session ID");
            AnalysisError::Permanent(Permanent::InvalidTask)
        })?;

        // UNTESTED: the key lives until the deadline, which this attempt start moved, so a retry hours after the Task was
        // created still finds it; every move of the deadline must move the key's expiry too.
        self.secrets.set_expiry(SecretId(attempt.task_id), attempt.deadline());

        // Waiting for an earlier analysis of the session is no progress, so the deadline cancels it too.
        let _session = tokio::select! {
            session = lock_session(session_id) => session,
            () = attempt.cancel.cancelled() => return Err(AnalysisError::Permanent(Permanent::DeadlinePassed)),
        };

        // A new Task never resumes from what an earlier analysis left, while its retries resume from their own files.
        if attempt.attempts == 1 {
            recording_analysis::discard(&self.manifest_path(session_id), None)
                .await
                .map_err(|error| {
                    error!(task.id = %attempt.task_id, %error, "Failed to remove the earlier AI analysis working files");
                    AnalysisError::Permanent(Permanent::Internal)
                })?;
        }

        let secret = self.secrets.get(SecretId(attempt.task_id)).map_err(|error| {
            error!(task.id = %attempt.task_id, error = format!("{error:#}"), "Failed to read the API key");
            AnalysisError::Permanent(Permanent::Internal)
        })?;

        let Some(secret) = secret else {
            warn!(task.id = %attempt.task_id, attempts = attempt.attempts, "AI analysis lost its API key");
            return Err(AnalysisError::of_kind(Failure::KeyLost));
        };

        let access = AiAccess::from_secret(&secret).map_err(|error| {
            error!(task.id = %attempt.task_id, error = format!("{error:#}"), "Failed to read the API key");
            AnalysisError::Permanent(Permanent::Internal)
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

    async fn publish(&self, record: &ProvisionerTaskRecord, output: &Analysis) -> anyhow::Result<()> {
        let session_id = Uuid::parse_str(&record.target).context("parse the session ID")?;

        // Nothing else runs on the session meanwhile: a newer Task of the session cannot start before this one ends.
        self.recordings
            .replace_artifacts(session_id, ArtifactKind::AiAnalysis, &output.log_path)
            .await
            .with_context(|| format!("list {}", output.log_path))
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        self.secrets.remove(SecretId(record.id));

        let Ok(session_id) = Uuid::parse_str(&record.target) else {
            return Ok(());
        };

        let _session = lock_session(session_id).await;

        recording_analysis::discard(&self.manifest_path(session_id), Some(&record.id.to_string()))
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
    ) -> Result<Analysis, AnalysisError> {
        let conf = self.conf_handle.get_conf();

        let client = settings.client(&conf, &api_key).map_err(|error| {
            error!(task.id = %attempt.task_id, %error, "Failed to build the AI client");
            AnalysisError::Permanent(Permanent::Internal)
        })?;

        let recording = self
            .recordings
            .get_finished(session_id)
            .await
            .map_err(|error| match error {
                FinishedRecordingError::NotFound => AnalysisError::of_kind(Failure::NoRecording),
                error => {
                    error!(task.id = %attempt.task_id, error = format!("{error:#}"), "Failed to read the recording");
                    AnalysisError::Permanent(Permanent::Internal)
                }
            })?;

        let manifest = analysis_manifest(&recording.manifest).map_err(|error| match error {
            RecordingsError::Mixed => AnalysisError::of_kind(Failure::MixedRecording),
            _ => AnalysisError::of_kind(Failure::NoRecording),
        })?;
        let manifest_path = recording.manifest_path();

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
                    return Err(AnalysisError::Permanent(Permanent::Panicked));
                }
            }
        };

        debug!(task.id = %attempt.task_id, actions = analysis.actions, "AI analysis log written");

        Ok(Analysis {
            file_name: ArtifactKind::AiAnalysis.file_name(0),
            model: analysis.model,
            usage: earlier.with(analysis.usage),
            prompt_version: analysis.prompt_version,
            log_path: analysis.log_path,
        })
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
