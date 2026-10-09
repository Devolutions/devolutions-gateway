//! Purpose: describe what the user did in a recorded session, with [`AiClient::analyze_recording`].
//!
//! A session is recorded as a terminal or as a video, never both, see [`Recordings`]:
//! - terminal recordings (asciicast and TRP) become a timed transcript, see [`transcript`], described with
//!   [`session_actions`](crate::session_actions);
//! - video recordings (WebM) become the screenshots where the screen changed, see [`video`], described with
//!   [`screen_actions`](crate::screen_actions).
//!
//! The model cites the transcript line or the screenshot that shows each action, and the action gets its time: the
//! model never writes times.
//!
//! The input is cut into chunks small enough for one request, and the actions found in every chunk are merged into a
//! Session Recording Log (`.slog`). The work keeps its files next to the manifest, in `.ai-analysis/`:
//! 1. `analysis.json`: the model, the prompt versions and the chunk sizes the other files were made with;
//! 2. the transcript chunks `transcript-NNNN.txt` and the screenshots `FNNNNN.png`, then `plan.json`, the list of
//!    chunks, once they are all written;
//! 3. what the AI answered for each chunk, `chunk-NNNN.json`, see [`checkpoint`], so that analysing the recording again
//!    after a failure only asks about the chunks left;
//! 4. the log merged from them, see [`slog`].
//!
//! A successful analysis moves the log next to the manifest, as `.ai-analysis.slog`, and removes the rest.

mod checkpoint;
mod recordings;
mod slog;
mod transcript;
mod video;

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use self::checkpoint::DescribedChunk;
pub use self::recordings::{
    RecordingFile, Recordings, RecordingsError, TerminalFormat, TerminalRecording, VideoRecording, WrongRecordingKind,
};
use self::transcript::TranscriptError;
use self::video::VideoError;
use crate::screen_actions::Screenshot;
use crate::{AiClient, Error, Usage};

/// Input tokens sent in one AI request, estimated at 4 characters per token.
const MAX_INPUT_TOKENS_PER_REQUEST: usize = 100_000;

const CHARS_PER_TOKEN: usize = 4;

/// Longest transcript chunk, in bytes; it bounds the memory an analysis uses.
const MAX_CHUNK_LEN: usize = MAX_INPUT_TOKENS_PER_REQUEST * CHARS_PER_TOKEN;

/// A truncated AI answer for a transcript part shorter than this fails the analysis instead of splitting the part again.
const MIN_SPLIT_LEN: usize = 2_000;

/// Screenshots sent in one AI request.
const MAX_SCREENSHOTS_PER_REQUEST: usize = 40;

/// Bytes of screenshots sent in one AI request; providers limit the size of a request, such as 32 MB for Anthropic.
const MAX_SCREENSHOT_BYTES_PER_REQUEST: usize = 16 * 1024 * 1024;

/// Folder of the working files, next to the manifest.
const WORKSPACE_DIR: &str = ".ai-analysis";

/// Name of the finished log, next to the manifest.
const LOG_FILE: &str = ".ai-analysis.slog";

const SETTINGS_FILE: &str = "analysis.json";

/// Written once every chunk file is complete; lists the chunks.
const PLAN_FILE: &str = "plan.json";

const WORKSPACE_LOG_FILE: &str = "log.slog";

/// What [`AiClient::analyze_recording`] needs from the manifest of a recorded session, `recording.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingManifest {
    /// Start of the session, in Unix seconds.
    pub start_time: i64,
    /// Length of the session, in seconds.
    pub duration: i64,
    /// Recordings of the session, in the order of the manifest, such as from [`Recordings::from_files`].
    pub recordings: Recordings,
}
/// How far an analysis got, in [`RecordingAnalysisEvent::Progress`].
///
/// The stages come in order: [`Reading`](Self::Reading), [`Describing`](Self::Describing), then
/// [`Writing`](Self::Writing). An analysis that resumes from its working files skips reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Progress {
    /// Reading the recordings, before the AI is asked anything, such as decoding a video and keeping its screenshots:
    /// bytes of the recording files read so far, out of their total size.
    ///
    /// Sent every half second while it lasts.
    Reading { read_bytes: u64, total_bytes: u64 },
    /// Asking the AI: chunks already described, out of all chunks.
    ///
    /// Sent before each chunk, then once all are described.
    Describing {
        described_chunks: usize,
        total_chunks: usize,
    },
    /// Writing the log from the answers.
    Writing,
}

impl Progress {
    /// Name of the stage, `reading`, `describing` or `writing`, stable enough to be stored.
    pub fn stage(&self) -> &'static str {
        match self {
            Self::Reading { .. } => "reading",
            Self::Describing { .. } => "describing",
            Self::Writing => "writing",
        }
    }

    /// Work done in the stage and the work it has in all, in bytes while reading and in chunks while describing;
    /// `None` while writing.
    pub fn done_and_total(&self) -> Option<(u64, u64)> {
        match *self {
            Self::Reading {
                read_bytes,
                total_bytes,
            } => Some((read_bytes, total_bytes)),
            Self::Describing {
                described_chunks,
                total_chunks,
            } => Some((
                u64::try_from(described_chunks).unwrap_or(u64::MAX),
                u64::try_from(total_chunks).unwrap_or(u64::MAX),
            )),
            Self::Writing => None,
        }
    }

    /// Part of the stage done, from 0 to 100.
    pub fn percent(&self) -> u8 {
        match self.done_and_total() {
            Some((done, total)) if total > 0 => {
                u8::try_from(done.min(total).saturating_mul(100) / total).unwrap_or(100)
            }
            Some(_) => 0,
            None => 100,
        }
    }
}

/// A short sentence for people following the analysis, such as `asking the AI: 2 of 5 chunks described`.
impl fmt::Display for Progress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Reading {
                read_bytes,
                total_bytes,
            } => write!(
                f,
                "reading the recordings: {:.1} of {:.1} MB ({}%)",
                megabytes(read_bytes),
                megabytes(total_bytes),
                self.percent()
            ),
            Self::Describing {
                described_chunks,
                total_chunks,
            } => write!(
                f,
                "asking the AI: {described_chunks} of {total_chunks} chunks described"
            ),
            Self::Writing => f.write_str("writing the log"),
        }
    }
}

#[expect(clippy::cast_precision_loss, reason = "shown with one decimal")]
fn megabytes(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}
/// Time between two [`Progress::Reading`] events.
const PREPARING_PROGRESS_INTERVAL: Duration = Duration::from_millis(500);

/// A finished analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordingAnalysis {
    /// The log, next to the manifest: move it where it belongs, or remove it with [`discard`].
    pub log_path: Utf8PathBuf,
    /// Actions in the log.
    pub actions: usize,
    /// Model the log names: the first one the provider reported, or the requested one when it reported none.
    pub model: String,
    /// Version of the prompt used, such as `session-actions-3`; the log names it too.
    pub prompt_version: String,
    /// Tokens the provider counted for the whole analysis, answers cut and asked again included.
    ///
    /// `None` when the provider did not report them for every request.
    pub usage: Option<Usage>,
}

/// Error returned when an analysis fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordingAnalysisError {
    /// The manifest lists no recording.
    #[error("session has no terminal or video recording")]
    NoRecording,
    /// The session has video recordings, but XMF, which decodes them, is not loaded.
    #[error("video decoding is not available: XMF is not loaded")]
    VideoDecoderUnavailable,
    #[error("failed to read {file_name}: {reason}")]
    InvalidRecording { file_name: String, reason: String },
    /// A request to the AI failed.
    #[error(transparent)]
    Ai(#[from] Error),
    /// The answer was cut short even for a part of the input too small to split again.
    #[error("AI answer was cut at the output token limit, even for a small part of the recording")]
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
    /// Video recordings need XMF, loaded with `cadeau::xmf::init`.
    /// Analysing a recording again after a failure resumes from the chunks already described, as long as the model and
    /// the prompts are the same; otherwise it starts over.
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
            cancel: CancellationToken::new(),
        }
    }
}

/// Request built by [`AiClient::analyze_recording`].
#[must_use = "the analysis runs only by `start`"]
pub struct AnalyzeRecording<'a> {
    client: &'a AiClient,
    manifest: &'a RecordingManifest,
    manifest_path: &'a Utf8Path,
    max_output_tokens: Option<u32>,
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

impl AnalyzeRecording<'_> {
    /// Upper bound of tokens in each AI answer, see
    /// [`DescribeSessionActions::max_output_tokens`](crate::session_actions::DescribeSessionActions::max_output_tokens).
    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    /// Stops the analysis soon after `cancel` is cancelled, with [`RecordingAnalysisError::Cancelled`].
    ///
    /// Dropping the receiver of the events cancels the analysis too.
    pub fn cancellation(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Starts the analysis on the Tokio runtime and returns its events.
    ///
    /// The events are [`RecordingAnalysisEvent::Progress`] while it runs, then [`RecordingAnalysisEvent::Complete`]
    /// or [`RecordingAnalysisEvent::Failure`], which is always the last one. Progress events are dropped while the
    /// channel is full, so a slow reader only misses some of them; the last event is never dropped.
    /// The channel ending without a last event means the analysis panicked.
    ///
    /// Dropping the receiver cancels the analysis.
    pub fn start(self) -> mpsc::Receiver<RecordingAnalysisEvent> {
        let (events, receiver) = mpsc::channel(EVENT_BUFFER);
        let finished = CancellationToken::new();

        // A receiver that went away means nobody waits for the result anymore.
        tokio::spawn({
            let events = events.clone();
            let cancel = self.cancel.clone();
            let finished = finished.clone();
            async move {
                tokio::select! {
                    () = events.closed() => cancel.cancel(),
                    () = finished.cancelled() => {}
                }
            }
        });

        let run = Run {
            client: self.client.clone(),
            manifest: self.manifest.clone(),
            manifest_path: self.manifest_path.to_owned(),
            max_output_tokens: self.max_output_tokens,
            cancel: self.cancel,
            events,
        };

        tokio::spawn(async move {
            let last = match run.run().await {
                Ok(analysis) => RecordingAnalysisEvent::Complete(analysis),
                Err(error) => RecordingAnalysisEvent::Failure(error),
            };
            finished.cancel();
            let _ = run.events.send(last).await;
        });

        receiver
    }
}

/// An event of an analysis started with [`AnalyzeRecording::start`].
#[derive(Debug)]
#[non_exhaustive]
pub enum RecordingAnalysisEvent {
    /// The analysis goes on.
    Progress(Progress),
    /// The analysis succeeded; it is the last event.
    Complete(RecordingAnalysis),
    /// The analysis failed; it is the last event.
    Failure(RecordingAnalysisError),
}

/// Events waiting for the reader before progress events are dropped.
const EVENT_BUFFER: usize = 16;

/// A started analysis.
struct Run {
    client: AiClient,
    manifest: RecordingManifest,
    manifest_path: Utf8PathBuf,
    max_output_tokens: Option<u32>,
    cancel: CancellationToken,
    events: mpsc::Sender<RecordingAnalysisEvent>,
}

impl Run {
    async fn run(&self) -> Result<RecordingAnalysis, RecordingAnalysisError> {
        let dir = recording_dir(&self.manifest_path).to_owned();
        let workspace = dir.join(WORKSPACE_DIR);
        let cancel = self.cancel.clone();

        let settings = WorkspaceSettings {
            prompt_version: self.manifest.recordings.prompt_version().to_owned(),
            model: self.client.model().to_owned(),
            chunk_len: MAX_CHUNK_LEN,
        };

        let total_bytes = self.manifest.recordings.total_bytes(&dir);
        let read_bytes = Arc::new(AtomicU64::new(0));

        let mut preparing = tokio::task::spawn_blocking({
            let manifest = self.manifest.clone();
            let dir = dir.clone();
            let workspace = workspace.clone();
            let cancel = cancel.clone();
            let read_bytes = Arc::clone(&read_bytes);
            move || prepare(&manifest, &dir, &workspace, &settings, &read_bytes, &cancel)
        });
        // The first event of an analysis is always the start of the reading, however quickly the files are read.
        self.report(Progress::Reading {
            read_bytes: 0,
            total_bytes,
        });
        let mut ticks = tokio::time::interval_at(
            tokio::time::Instant::now() + PREPARING_PROGRESS_INTERVAL,
            PREPARING_PROGRESS_INTERVAL,
        );

        // Decoding a long video takes a while, so the bytes read so far are reported until it is done.
        let plan = loop {
            tokio::select! {
                prepared = &mut preparing => {
                    break prepared
                        .map_err(|_| RecordingAnalysisError::Files("an AI analysis step panicked".to_owned()))??;
                }
                _ = ticks.tick() => {
                    self.report(Progress::Reading {
                        read_bytes: read_bytes.load(Ordering::Relaxed),
                        total_bytes,
                    });
                }
            }
        };
        let total = plan.len();
        info!(chunks = total, "Describe the session actions");

        for (index, chunk) in plan.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(RecordingAnalysisError::Cancelled);
            }

            let checkpoint = checkpoint::path(&workspace, index);

            if checkpoint.exists() {
                debug!(index, "Chunk already described");
                continue;
            }

            self.report(Progress::Describing {
                described_chunks: index,
                total_chunks: total,
            });

            let described = match chunk {
                Chunk::Transcript { file } => {
                    let transcript = tokio::fs::read_to_string(workspace.join(file))
                        .await
                        .map_err(|error| files_error(&error))?;

                    tokio::select! {
                        () = cancel.cancelled() => return Err(RecordingAnalysisError::Cancelled),
                        described = describe_transcript(&self.client, self.max_output_tokens, &transcript) => described?,
                    }
                }
                Chunk::Screenshots { frames, context } => {
                    let frames = read_screenshots(&workspace, frames).await?;
                    let context = match context {
                        Some(context) => read_screenshots(&workspace, std::slice::from_ref(context)).await?.pop(),
                        None => None,
                    };

                    tokio::select! {
                        () = cancel.cancelled() => return Err(RecordingAnalysisError::Cancelled),
                        described = describe_screenshots(&self.client, self.max_output_tokens, &frames, context.as_ref()) => described?,
                    }
                }
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

        self.report(Progress::Describing {
            described_chunks: total,
            total_chunks: total,
        });
        self.report(Progress::Writing);

        let prompt_version = self.manifest.recordings.prompt_version().to_owned();
        let merged = blocking({
            let workspace = workspace.clone();
            let start_time = self.manifest.start_time;
            let duration = self.manifest.duration;
            let requested_model = self.client.model().to_owned();
            let prompt_version = prompt_version.clone();
            let cancel = cancel.clone();
            move || {
                merge_checkpoints(
                    &workspace,
                    total,
                    start_time,
                    duration,
                    &requested_model,
                    &prompt_version,
                    &cancel,
                )
            }
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
            prompt_version,
            usage: merged.usage,
        })
    }

    /// Sends a progress event, unless the reader is behind; a reader that went away cancels the analysis.
    fn report(&self, progress: Progress) {
        if let Err(mpsc::error::TrySendError::Closed(_)) =
            self.events.try_send(RecordingAnalysisEvent::Progress(progress))
        {
            self.cancel.cancel();
        }
    }
}
/// Counts the bytes read from a recording, for [`Progress::Reading`].
struct CountingReader<R> {
    inner: R,
    read_bytes: Arc<AtomicU64>,
}

impl<R: io::Read> io::Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read_bytes
            .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(read)
    }
}

/// Opens a recording file, counting the bytes read from it.
fn open_counted(path: &Utf8Path, read_bytes: &Arc<AtomicU64>) -> io::Result<CountingReader<File>> {
    Ok(CountingReader {
        inner: File::open(path)?,
        read_bytes: Arc::clone(read_bytes),
    })
}
/// Asks the AI about one transcript chunk; a truncated answer is asked again as two halves.
async fn describe_transcript(
    client: &AiClient,
    max_output_tokens: Option<u32>,
    chunk: &str,
) -> Result<DescribedChunk, RecordingAnalysisError> {
    let mut parts = VecDeque::from([chunk]);
    let mut described = DescribedChunk::default();

    while let Some(part) = parts.pop_front() {
        let mut request = client.describe_session_actions(part);

        if let Some(max_output_tokens) = max_output_tokens {
            request = request.max_output_tokens(max_output_tokens);
        }

        match request.send().await {
            Ok(response) => described.add(response),
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

/// A screenshot read back from the working files.
struct LoadedScreenshot {
    frame: PlannedFrame,
    png: Vec<u8>,
}

impl LoadedScreenshot {
    fn as_screenshot(&self, context: bool) -> Screenshot<'_> {
        Screenshot {
            id: &self.frame.id,
            offset: Duration::from_millis(self.frame.offset_ms),
            png: &self.png,
            context,
        }
    }
}

async fn read_screenshots(
    workspace: &Utf8Path,
    frames: &[PlannedFrame],
) -> Result<Vec<LoadedScreenshot>, RecordingAnalysisError> {
    let mut loaded = Vec::with_capacity(frames.len());

    for frame in frames {
        let png = tokio::fs::read(video::frame_path(workspace, &frame.id))
            .await
            .map_err(|error| files_error(&error))?;
        loaded.push(LoadedScreenshot {
            frame: frame.clone(),
            png,
        });
    }

    Ok(loaded)
}

/// Asks the AI about one chunk of screenshots, in parts that fit in a request; a truncated answer is asked again as
/// two halves.
///
/// Each part starts with the screenshot before it as context: `context` for the first part.
async fn describe_screenshots(
    client: &AiClient,
    max_output_tokens: Option<u32>,
    frames: &[LoadedScreenshot],
    context: Option<&LoadedScreenshot>,
) -> Result<DescribedChunk, RecordingAnalysisError> {
    let mut parts = VecDeque::from(split_by_size(frames));
    let mut described = DescribedChunk::default();

    while let Some(part) = parts.pop_front() {
        let before = match part.start {
            0 => context,
            start => frames.get(start - 1),
        };

        let screenshots = before
            .map(|before| before.as_screenshot(true))
            .into_iter()
            .chain(frames[part.clone()].iter().map(|frame| frame.as_screenshot(false)))
            .collect::<Vec<_>>();

        let mut request = client.describe_screen_actions(&screenshots);

        if let Some(max_output_tokens) = max_output_tokens {
            request = request.max_output_tokens(max_output_tokens);
        }

        match request.send().await {
            Ok(response) => described.add(response),
            Err(Error::Truncated { usage }) => {
                described.usage = add_usage(described.usage, usage);

                if part.len() < 2 {
                    return Err(RecordingAnalysisError::Truncated);
                }

                let middle = part.start + part.len() / 2;
                debug!(
                    screenshots = part.len(),
                    "AI answer truncated; asking again in two halves"
                );
                parts.push_front(middle..part.end);
                parts.push_front(part.start..middle);
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(described)
}

/// Cuts `frames` into consecutive parts of at most [`MAX_SCREENSHOT_BYTES_PER_REQUEST`] bytes, each with one
/// screenshot at least.
fn split_by_size(frames: &[LoadedScreenshot]) -> Vec<Range<usize>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut bytes = 0;

    for (index, frame) in frames.iter().enumerate() {
        if index > start && bytes + frame.png.len() > MAX_SCREENSHOT_BYTES_PER_REQUEST {
            parts.push(start..index);
            start = index;
            bytes = 0;
        }
        bytes += frame.png.len();
    }

    if start < frames.len() {
        parts.push(start..frames.len());
    }

    parts
}

/// What the working files were made with; files made with other settings are never reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceSettings {
    prompt_version: String,
    model: String,
    chunk_len: usize,
}

/// A part of the input the AI is asked about in one go.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
enum Chunk {
    /// A transcript chunk file.
    Transcript { file: String },
    /// Screenshots, with the one before them for context.
    Screenshots {
        frames: Vec<PlannedFrame>,
        context: Option<PlannedFrame>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedFrame {
    id: String,
    /// Elapsed time since the start of the session.
    offset_ms: u64,
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

/// Gets the working files ready and returns the chunks: the transcript or the screenshots are made once, and kept for
/// another analysis with the same settings.
fn prepare(
    manifest: &RecordingManifest,
    dir: &Utf8Path,
    workspace: &Utf8Path,
    settings: &WorkspaceSettings,
    read_bytes: &Arc<AtomicU64>,
    cancel: &CancellationToken,
) -> Result<Vec<Chunk>, RecordingAnalysisError> {
    if manifest.recordings.is_empty() {
        return Err(RecordingAnalysisError::NoRecording);
    }

    let saved = std::fs::read(workspace.join(SETTINGS_FILE))
        .ok()
        .and_then(|saved| serde_json::from_slice::<WorkspaceSettings>(&saved).ok());

    if saved.as_ref() == Some(settings) {
        let plan = std::fs::read(workspace.join(PLAN_FILE))
            .ok()
            .and_then(|plan| serde_json::from_slice::<Vec<Chunk>>(&plan).ok());

        if let Some(plan) = plan {
            return Ok(plan);
        }
    } else if workspace.exists() {
        info!(path = %workspace, "Discard the working files of another AI analysis");
        std::fs::remove_dir_all(workspace).map_err(|error| files_error(&error))?;
    }

    std::fs::create_dir_all(workspace).map_err(|error| files_error(&error))?;

    let settings = serde_json::to_vec(settings).map_err(|error| files_error(&error))?;
    std::fs::write(workspace.join(SETTINGS_FILE), settings).map_err(|error| files_error(&error))?;

    let plan = match &manifest.recordings {
        Recordings::Terminal(recordings) => {
            plan_transcript(recordings, manifest.start_time, dir, workspace, read_bytes, cancel)?
        }
        Recordings::Video(recordings) => {
            plan_screenshots(recordings, manifest.start_time, dir, workspace, read_bytes, cancel)?
        }
    };
    let saved_plan = serde_json::to_vec(&plan).map_err(|error| files_error(&error))?;
    std::fs::write(workspace.join(PLAN_FILE), saved_plan).map_err(|error| files_error(&error))?;

    Ok(plan)
}

/// Writes the transcript chunks of terminal recordings.
fn plan_transcript(
    recordings: &[TerminalRecording],
    session_start: i64,
    dir: &Utf8Path,
    workspace: &Utf8Path,
    read_bytes: &Arc<AtomicU64>,
    cancel: &CancellationToken,
) -> Result<Vec<Chunk>, RecordingAnalysisError> {
    let chunks = transcript::write_chunks(
        &in_time_order(recordings, TerminalRecording::start_time),
        session_start,
        dir,
        workspace,
        MAX_CHUNK_LEN,
        read_bytes,
        cancel,
    )
    .map_err(|error| match error {
        TranscriptError::Invalid { file_name, reason } => {
            RecordingAnalysisError::InvalidRecording { file_name, reason }
        }
        TranscriptError::Write(error) => files_error(&error),
        TranscriptError::Cancelled => RecordingAnalysisError::Cancelled,
    })?;

    Ok((0..chunks)
        .map(|index| Chunk::Transcript {
            file: transcript::chunk_path(workspace, index)
                .file_name()
                .unwrap_or_default()
                .to_owned(),
        })
        .collect())
}

/// Keeps the screenshots of video recordings and groups them by request, each group after the screenshot before it.
fn plan_screenshots(
    recordings: &[VideoRecording],
    session_start: i64,
    dir: &Utf8Path,
    workspace: &Utf8Path,
    read_bytes: &Arc<AtomicU64>,
    cancel: &CancellationToken,
) -> Result<Vec<Chunk>, RecordingAnalysisError> {
    let mut frames = Vec::new();
    let mut next_id = 0;

    for recording in in_time_order(recordings, VideoRecording::start_time) {
        let offset =
            Duration::from_secs(u64::try_from(recording.start_time().saturating_sub(session_start)).unwrap_or(0));

        let kept = video::keep_changed_frames(
            &dir.join(recording.file_name()),
            offset,
            workspace,
            &mut next_id,
            read_bytes,
            cancel,
        )
        .map_err(|error| match error {
            VideoError::DecoderUnavailable => RecordingAnalysisError::VideoDecoderUnavailable,
            VideoError::Invalid(reason) => RecordingAnalysisError::InvalidRecording {
                file_name: recording.file_name().to_owned(),
                reason,
            },
            VideoError::Write(error) => files_error(&error),
            VideoError::Cancelled => RecordingAnalysisError::Cancelled,
        })?;

        info!(file = %recording.file_name(), screenshots = kept.len(), "Screenshots kept from a video");

        frames.extend(kept.into_iter().map(|frame| PlannedFrame {
            id: frame.id,
            offset_ms: u64::try_from(frame.offset.as_millis()).unwrap_or(u64::MAX),
        }));
    }

    Ok(group_screenshots(frames))
}

/// Groups the screenshots of a session, in time order, into requests of at most [`MAX_SCREENSHOTS_PER_REQUEST`], each
/// after the last screenshot of the group before it; a session recorded in several videos is grouped as one.
fn group_screenshots(frames: Vec<PlannedFrame>) -> Vec<Chunk> {
    let mut groups = Vec::new();
    let mut previous = None;

    for frames in frames.chunks(MAX_SCREENSHOTS_PER_REQUEST) {
        groups.push(Chunk::Screenshots {
            frames: frames.to_vec(),
            context: previous.clone(),
        });
        previous = frames.last().cloned();
    }

    groups
}

/// The recordings of a session sorted by start time, since a manifest may list them in another order.
fn in_time_order<R: Clone>(recordings: &[R], start_time: impl Fn(&R) -> i64) -> Vec<R> {
    let mut sorted = recordings.to_vec();
    sorted.sort_by_key(|recording| start_time(recording));
    sorted
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

/// Writes the log from the checkpoints, into the working files, with every action in time order.
///
/// The log names the first model reported for a chunk, or `requested_model` when the provider reported none.
fn merge_checkpoints(
    workspace: &Utf8Path,
    total: usize,
    start_time: i64,
    duration: i64,
    requested_model: &str,
    prompt_version: &str,
    cancel: &CancellationToken,
) -> Result<MergedLog, RecordingAnalysisError> {
    let log_error = |error: anyhow::Error| files_error(&format!("failed to write the log: {error:#}"));

    let mut actions = Vec::new();
    let mut model = None;
    let mut usage = Some(Usage::default());

    for index in 0..total {
        if cancel.is_cancelled() {
            return Err(RecordingAnalysisError::Cancelled);
        }

        let described = checkpoint::read(&checkpoint::path(workspace, index)).map_err(|error| files_error(&error))?;
        model = model.or(described.model);
        usage = add_usage(usage, described.usage);
        actions.extend(described.actions);
    }

    // A model may list the actions of a chunk slightly out of order; the sort is stable, so equal times keep their order.
    actions.sort_by_key(|action| action.offset);
    let model = model.unwrap_or_else(|| requested_model.to_owned());

    let out = File::create(workspace.join(WORKSPACE_LOG_FILE)).map_err(|error| files_error(&error))?;
    let mut log =
        slog::SlogWriter::start(BufWriter::new(out), start_time, &model, prompt_version).map_err(log_error)?;

    for action in &actions {
        log.action(action).map_err(log_error)?;
    }

    log.finish(duration)
        .map_err(log_error)?
        .into_inner()
        .map_err(|error| files_error(&error.into_error()))?
        .sync_all()
        .map_err(|error| files_error(&error))?;

    Ok(MergedLog {
        actions: actions.len(),
        model,
        usage,
    })
}

#[cfg(test)]
mod tests;
