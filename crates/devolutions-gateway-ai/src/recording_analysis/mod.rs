//! Purpose: describe what the user did in a recorded session, with [`AiClient::analyze_recording`].
//!
//! It builds on [`session_actions`](crate::session_actions): the terminal recordings of the session become a timed
//! transcript, the transcript is cut into chunks small enough for one request, and the actions found in every chunk
//! are merged into a Session Recording Log (`.slog`).
//!
//! The work keeps its files next to the manifest, in `.ai-analysis/`:
//! 1. `analysis.json`: the model, the prompt version and the chunk size the other files were made with;
//! 2. the transcript chunks, `chunk-NNNN.txt`, then `chunks.done` once they are all written, see [`transcript`];
//! 3. what the AI answered for each chunk, `chunk-NNNN.json`, see [`checkpoint`], so that analysing the recording again
//!    after a failure only asks about the chunks left;
//! 4. the log merged from them, see [`slog`].
//!
//! A successful analysis moves the log next to the manifest, as `.ai-analysis.slog`, and removes the rest.

mod checkpoint;
mod slog;
mod transcript;

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufWriter};
use std::pin::Pin;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use self::checkpoint::DescribedChunk;
use self::transcript::TranscriptError;
use crate::session_actions::PROMPT_VERSION;
use crate::{AiClient, Error, Usage};

/// Input tokens sent in one AI request, estimated at 4 characters per token.
const MAX_INPUT_TOKENS_PER_REQUEST: usize = 100_000;

const CHARS_PER_TOKEN: usize = 4;

/// Longest transcript chunk, in bytes; it bounds the memory an analysis uses.
const MAX_CHUNK_LEN: usize = MAX_INPUT_TOKENS_PER_REQUEST * CHARS_PER_TOKEN;

/// A truncated AI answer for a transcript part shorter than this fails the analysis instead of splitting the part again.
const MIN_SPLIT_LEN: usize = 2_000;

/// Folder of the working files, next to the manifest.
const WORKSPACE_DIR: &str = ".ai-analysis";

/// Name of the finished log, next to the manifest.
const LOG_FILE: &str = ".ai-analysis.slog";

const SETTINGS_FILE: &str = "analysis.json";

/// Written once every chunk file is complete; holds the number of chunks.
const CHUNKS_DONE_FILE: &str = "chunks.done";

const WORKSPACE_LOG_FILE: &str = "log.slog";

/// What [`AiClient::analyze_recording`] needs from the manifest of a recorded session, `recording.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingManifest {
    /// Start of the session, in Unix seconds.
    pub start_time: i64,
    /// Length of the session, in seconds.
    pub duration: i64,
    /// Recordings of the session, in the order of the manifest.
    pub files: Vec<RecordingFile>,
}

/// One recording of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingFile {
    /// Name of the file, in the folder of the manifest.
    pub file_name: String,
    /// Start of the recording, in Unix seconds.
    pub start_time: i64,
}

/// How far an analysis got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Transcript chunks the AI already described.
    pub described_chunks: usize,
    pub total_chunks: usize,
}

/// A finished analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordingAnalysis {
    /// The log, next to the manifest: move it where it belongs, or remove it with [`discard`].
    pub log_path: Utf8PathBuf,
    /// Actions in the log.
    pub actions: usize,
    /// Model the log names: the first one the provider reported, or the requested one when it reported none.
    pub model: String,
    /// Tokens the provider counted for the whole analysis, answers cut and asked again included.
    ///
    /// `None` when the provider did not report them for every request.
    pub usage: Option<Usage>,
}

/// Error returned when an analysis fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordingAnalysisError {
    /// The session has recordings, but none that can be read as a terminal session, such as only videos.
    #[error("unsupported recording type: {0}")]
    Unsupported(&'static str),
    /// The session has no recording at all.
    #[error("session has no terminal recording")]
    NoTerminalRecording,
    #[error("failed to read {file_name}: {reason}")]
    InvalidRecording { file_name: String, reason: String },
    /// A request to the AI failed.
    #[error(transparent)]
    Ai(#[from] Error),
    /// The answer was cut short even for a part of the transcript too short to split again.
    #[error("AI answer was cut at the output token limit, even for a short part of the transcript")]
    Truncated,
    /// The working files could not be written or read.
    #[error("AI analysis files: {0}")]
    Files(String),
    /// The analysis stopped because its cancellation token was cancelled.
    #[error("AI analysis cancelled")]
    Cancelled,
}

impl RecordingAnalysisError {
    /// Returns `true` when analysing the recording again later may succeed, such as after a rate limit.
    ///
    /// The chunks already described are not asked about again.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Ai(error) if error.is_transient())
    }
}

/// Removes what [`AiClient::analyze_recording`] left next to `manifest_path`: its working files and a log nobody moved.
///
/// Call it once the analysis of the recording is over for good; a successful analysis already removed its working
/// files.
pub async fn discard(manifest_path: &Utf8Path) -> io::Result<()> {
    let dir = recording_dir(manifest_path);

    match tokio::fs::remove_dir_all(dir.join(WORKSPACE_DIR)).await {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }

    match tokio::fs::remove_file(dir.join(LOG_FILE)).await {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

impl AiClient {
    /// Describes what the user did in a recorded session, as a Session Recording Log.
    ///
    /// `manifest_path` is the path of the session manifest, `recording.json`, and `manifest` what it holds.
    /// The recordings are read from the folder of the manifest, and the working files are kept there too.
    /// Analysing a recording again after a failure resumes from the chunks already described, as long as the model and
    /// the prompt are the same; otherwise it starts over.
    /// Only one analysis of a recording may run at a time.
    pub fn analyze_recording<'a>(
        &'a self,
        manifest: &'a RecordingManifest,
        manifest_path: &'a Utf8Path,
    ) -> AnalyzeRecording<'a> {
        AnalyzeRecording {
            client: self,
            manifest,
            manifest_path,
            max_output_tokens: None,
            on_progress: None,
            cancel: CancellationToken::new(),
        }
    }
}

type ProgressFn<'a> = Box<dyn FnMut(Progress) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> + Send + 'a>;

/// Request built by [`AiClient::analyze_recording`].
#[must_use = "the analysis runs only by `send`"]
pub struct AnalyzeRecording<'a> {
    client: &'a AiClient,
    manifest: &'a RecordingManifest,
    manifest_path: &'a Utf8Path,
    max_output_tokens: Option<u32>,
    on_progress: Option<ProgressFn<'a>>,
    cancel: CancellationToken,
}

impl fmt::Debug for AnalyzeRecording<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalyzeRecording")
            .field("client", self.client)
            .field("manifest_path", &self.manifest_path)
            .field("max_output_tokens", &self.max_output_tokens)
            .finish_non_exhaustive()
    }
}

impl<'a> AnalyzeRecording<'a> {
    /// Upper bound of tokens in each AI answer, see
    /// [`DescribeSessionActions::max_output_tokens`](crate::session_actions::DescribeSessionActions::max_output_tokens).
    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    /// Called before each chunk the AI is asked about, then once all are described.
    pub fn on_progress<F, Fut>(mut self, mut on_progress: F) -> Self
    where
        F: FnMut(Progress) -> Fut + Send + 'a,
        Fut: Future<Output = ()> + Send + 'a,
    {
        self.on_progress = Some(Box::new(move |progress| Box::pin(on_progress(progress))));
        self
    }

    /// Stops the analysis soon after `cancel` is cancelled, with [`RecordingAnalysisError::Cancelled`].
    ///
    /// Dropping the future also stops it, but a step that writes files may still be running then; after a cancellation
    /// the analysis has stopped for sure, so the next one never shares the working files with it.
    pub fn cancellation(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Runs the analysis and returns the log.
    pub async fn send(mut self) -> Result<RecordingAnalysis, RecordingAnalysisError> {
        let dir = recording_dir(self.manifest_path).to_owned();
        let workspace = dir.join(WORKSPACE_DIR);
        let cancel = self.cancel.clone();

        let settings = WorkspaceSettings {
            prompt_version: PROMPT_VERSION.to_owned(),
            model: self.client.model().to_owned(),
            chunk_len: MAX_CHUNK_LEN,
        };

        let total = blocking({
            let manifest = self.manifest.clone();
            let dir = dir.clone();
            let workspace = workspace.clone();
            let cancel = cancel.clone();
            move || prepare(&manifest, &dir, &workspace, &settings, &cancel)
        })
        .await?;

        info!(chunks = total, "Describe the session actions");

        for index in 0..total {
            if cancel.is_cancelled() {
                return Err(RecordingAnalysisError::Cancelled);
            }

            let checkpoint = checkpoint::path(&workspace, index);

            if checkpoint.exists() {
                debug!(index, "Chunk already described");
                continue;
            }

            self.report(index, total).await;

            let chunk = tokio::fs::read_to_string(transcript::chunk_path(&workspace, index))
                .await
                .map_err(|error| files_error(&error))?;

            let described = tokio::select! {
                () = cancel.cancelled() => return Err(RecordingAnalysisError::Cancelled),
                described = describe_chunk(self.client, self.max_output_tokens, &chunk) => described?,
            };

            debug!(
                index,
                actions = described.actions.len(),
                model = ?described.model,
                usage = ?described.usage,
                "Chunk described"
            );

            blocking(move || checkpoint::write(&checkpoint, &described).map_err(|error| files_error(&error))).await?;
        }

        self.report(total, total).await;

        let merged = blocking({
            let workspace = workspace.clone();
            let start_time = self.manifest.start_time;
            let duration = self.manifest.duration;
            let requested_model = self.client.model().to_owned();
            let cancel = cancel.clone();
            move || merge_checkpoints(&workspace, total, start_time, duration, &requested_model, &cancel)
        })
        .await?;

        // Once the log leaves the working files, the analysis is done even if cancelled, so this is the last check.
        if cancel.is_cancelled() {
            return Err(RecordingAnalysisError::Cancelled);
        }

        let log_path = dir.join(LOG_FILE);
        tokio::fs::rename(workspace.join(WORKSPACE_LOG_FILE), &log_path)
            .await
            .map_err(|error| files_error(&error))?;

        if let Err(error) = tokio::fs::remove_dir_all(&workspace).await {
            warn!(%error, path = %workspace, "Failed to remove the AI analysis working files");
        }

        Ok(RecordingAnalysis {
            log_path,
            actions: merged.actions,
            model: merged.model,
            usage: merged.usage,
        })
    }

    async fn report(&mut self, described_chunks: usize, total_chunks: usize) {
        if let Some(on_progress) = &mut self.on_progress {
            on_progress(Progress {
                described_chunks,
                total_chunks,
            })
            .await;
        }
    }
}

/// Asks the AI about one chunk; a truncated answer is asked again as two halves.
async fn describe_chunk(
    client: &AiClient,
    max_output_tokens: Option<u32>,
    chunk: &str,
) -> Result<DescribedChunk, RecordingAnalysisError> {
    let mut parts = VecDeque::from([chunk]);
    let mut described = DescribedChunk {
        actions: Vec::new(),
        model: None,
        usage: Some(Usage::default()),
    };

    while let Some(part) = parts.pop_front() {
        let mut request = client.describe_session_actions(part);

        if let Some(max_output_tokens) = max_output_tokens {
            request = request.max_output_tokens(max_output_tokens);
        }

        match request.send().await {
            Ok(response) => {
                described.actions.extend(response.output);
                described.model = described.model.or(response.model);
                described.usage = add_usage(described.usage, response.usage);
            }
            Err(Error::Truncated { usage }) => {
                described.usage = add_usage(described.usage, usage);

                let Some((first, second)) = split_in_half(part) else {
                    return Err(RecordingAnalysisError::Truncated);
                };

                debug!(part_len = part.len(), "AI answer truncated; asking again in two halves");
                parts.push_front(second);
                parts.push_front(first);
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(described)
}

/// What the working files were made with; files made with other settings are never reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceSettings {
    prompt_version: String,
    model: String,
    chunk_len: usize,
}

fn recording_dir(manifest_path: &Utf8Path) -> &Utf8Path {
    match manifest_path.parent() {
        Some(dir) if !dir.as_str().is_empty() => dir,
        _ => Utf8Path::new("."),
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, RecordingAnalysisError> + Send + 'static,
) -> Result<T, RecordingAnalysisError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| RecordingAnalysisError::Files("an AI analysis step panicked".to_owned()))?
}

fn files_error(error: &dyn fmt::Display) -> RecordingAnalysisError {
    RecordingAnalysisError::Files(format!("{error:#}"))
}

/// Gets the working files ready and returns the number of chunks: the transcript is written once, and kept for
/// another analysis with the same settings.
fn prepare(
    manifest: &RecordingManifest,
    dir: &Utf8Path,
    workspace: &Utf8Path,
    settings: &WorkspaceSettings,
    cancel: &CancellationToken,
) -> Result<usize, RecordingAnalysisError> {
    let saved = std::fs::read(workspace.join(SETTINGS_FILE))
        .ok()
        .and_then(|saved| serde_json::from_slice::<WorkspaceSettings>(&saved).ok());

    if saved.as_ref() == Some(settings) {
        let done = std::fs::read_to_string(workspace.join(CHUNKS_DONE_FILE)).ok();

        if let Some(total) = done.and_then(|total| total.parse().ok()) {
            return Ok(total);
        }
    } else if workspace.exists() {
        info!(path = %workspace, "Discard the working files of another AI analysis");
        std::fs::remove_dir_all(workspace).map_err(|error| files_error(&error))?;
    }

    std::fs::create_dir_all(workspace).map_err(|error| files_error(&error))?;

    let settings = serde_json::to_vec(settings).map_err(|error| files_error(&error))?;
    std::fs::write(workspace.join(SETTINGS_FILE), settings).map_err(|error| files_error(&error))?;

    let total =
        transcript::write_chunks(manifest, dir, workspace, MAX_CHUNK_LEN, cancel).map_err(|error| match error {
            TranscriptError::Unsupported(file_type) => RecordingAnalysisError::Unsupported(file_type),
            TranscriptError::NoTerminalRecording => RecordingAnalysisError::NoTerminalRecording,
            TranscriptError::Invalid { file_name, reason } => {
                RecordingAnalysisError::InvalidRecording { file_name, reason }
            }
            TranscriptError::Write(error) => files_error(&error),
            TranscriptError::Cancelled => RecordingAnalysisError::Cancelled,
        })?;

    std::fs::write(workspace.join(CHUNKS_DONE_FILE), total.to_string()).map_err(|error| files_error(&error))?;

    Ok(total)
}

/// Sums token counts; the total is unknown as soon as one count is.
fn add_usage(total: Option<Usage>, more: Option<Usage>) -> Option<Usage> {
    Some(total? + more?)
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

/// What [`merge_checkpoints`] wrote.
struct MergedLog {
    actions: usize,
    model: String,
    usage: Option<Usage>,
}

/// Writes the log from the checkpoints, into the working files.
///
/// The log names the first model reported for a chunk, or `requested_model` when the provider reported none.
fn merge_checkpoints(
    workspace: &Utf8Path,
    total: usize,
    start_time: i64,
    duration: i64,
    requested_model: &str,
    cancel: &CancellationToken,
) -> Result<MergedLog, RecordingAnalysisError> {
    let log_error = |error: anyhow::Error| files_error(&format!("failed to write the log: {error:#}"));
    let read = |index| checkpoint::read(&checkpoint::path(workspace, index)).map_err(|error| files_error(&error));

    // `session.start` names the model, so it is read before the log is written.
    let mut model = None;
    for index in 0..total {
        model = read(index)?.model;
        if model.is_some() {
            break;
        }
    }
    let model = model.unwrap_or_else(|| requested_model.to_owned());

    let out = File::create(workspace.join(WORKSPACE_LOG_FILE)).map_err(|error| files_error(&error))?;
    let mut log = slog::SlogWriter::start(BufWriter::new(out), start_time, &model).map_err(log_error)?;
    let mut actions = 0;
    let mut usage = Some(Usage::default());

    // Chunks follow each other in time, so only the actions of one chunk need sorting.
    for index in 0..total {
        if cancel.is_cancelled() {
            return Err(RecordingAnalysisError::Cancelled);
        }

        let mut described = read(index)?;
        described.actions.sort_by_key(|action| action.offset);

        for action in &described.actions {
            log.action(action).map_err(log_error)?;
        }

        actions += described.actions.len();
        usage = add_usage(usage, described.usage);
    }

    log.finish(duration)
        .map_err(log_error)?
        .into_inner()
        .map_err(|error| files_error(&error.into_error()))?
        .sync_all()
        .map_err(|error| files_error(&error))?;

    Ok(MergedLog { actions, model, usage })
}

#[cfg(test)]
mod tests;
