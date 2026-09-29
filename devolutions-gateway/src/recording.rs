use core::fmt;
use std::cmp;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use camino::Utf8PathBuf;
use devolutions_gateway_task::{ShutdownSignal, Task};
use futures::future::Either;
use parking_lot::Mutex;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::{fs, io};
use typed_builder::TypedBuilder;
use uuid::Uuid;
use video_streamer::SignalWriter;

use crate::job_queue::JobQueueHandle;
use crate::session::SessionMessageSender;
use crate::token::{JrecTokenClaims, RecordingFileType};

const DISCONNECTED_TTL_EXTRA_LEEWAY: Duration = Duration::from_secs(10);
const BUFFER_WRITER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecFile {
    file_name: String,
    start_time: i64,
    duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecManifest {
    session_id: Uuid,
    start_time: i64,
    duration: i64,
    files: Vec<JrecFile>,
    #[serde(default, skip_serializing_if = "JrecArtifacts::is_empty")]
    artifacts: JrecArtifacts,
}

/// Non-recording artifacts, one list per [`ArtifactKind`]. Each list is append-only, like `files`: names
/// are derived from positions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct JrecArtifacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ai_analysis: Vec<JrecArtifact>,
}

impl JrecArtifacts {
    fn is_empty(&self) -> bool {
        let Self { ai_analysis } = self;
        ai_analysis.is_empty()
    }

    fn of_kind_mut(&mut self, kind: ArtifactKind) -> &mut Vec<JrecArtifact> {
        match kind {
            ArtifactKind::AiAnalysis => &mut self.ai_analysis,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecArtifact {
    file_name: String,
}

/// Kind of a non-recording artifact, used as its key in the manifest `artifacts` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    AiAnalysis,
}

impl ArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::AiAnalysis => "ai-analysis",
        }
    }

    const fn file_type(self) -> RecordingFileType {
        match self {
            ArtifactKind::AiAnalysis => RecordingFileType::SessionRecordingLog,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PushKind {
    Recording,
    Artifact(ArtifactKind),
}

/// What a push of a given kind takes part in, decided once from the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KindPolicy {
    /// Counts as the session recording: `is_recording`, `active_recordings` and the kill when the
    /// session must be recorded.
    recording_policy: bool,
    /// Data and end of stream wake `/shadow` streamers.
    wakes_streamers: bool,
    /// Writes the file and manifest durations.
    tracks_duration: bool,
}

impl PushKind {
    const fn policy(self) -> KindPolicy {
        match self {
            PushKind::Recording => KindPolicy {
                recording_policy: true,
                wakes_streamers: true,
                tracks_duration: true,
            },
            PushKind::Artifact(_) => KindPolicy {
                recording_policy: false,
                wakes_streamers: false,
                tracks_duration: false,
            },
        }
    }
}

impl JrecManifest {
    fn read_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let json = std::fs::read(path)?;
        let manifest = serde_json::from_slice(&json)?;
        Ok(manifest)
    }

    fn save_to_file(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Outcome of a successful push session.
///
/// `Err` from `ClientPush::run` is reserved for unexpected failures. Conditions that the
/// caller is expected to surface to the client (e.g. disk full) are reported as variants of
/// this enum so the caller can choose an appropriate close frame.
#[derive(Debug)]
pub enum PushOutcome {
    /// The recording stream completed normally or was terminated by a shutdown signal.
    Done,
    /// The underlying file write failed because the recording storage volume is full.
    StorageFull,
}

/// Where a push is stored. Artifacts are opaque to Gateway: stored as-is, whatever their content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushTarget {
    kind: PushKind,
    file_type: RecordingFileType,
}

#[derive(Debug, thiserror::Error)]
#[error("{} artifacts must be {} files", kind.as_str(), kind.file_type().extension())]
pub struct UnsupportedArtifactFileType {
    kind: ArtifactKind,
}

impl PushTarget {
    /// Without a kind the stream is a recording, as it was before artifacts existed.
    pub fn new(file_type: RecordingFileType, kind: Option<ArtifactKind>) -> Result<Self, UnsupportedArtifactFileType> {
        let kind = match kind {
            None => PushKind::Recording,
            Some(kind) if kind.file_type() == file_type => PushKind::Artifact(kind),
            Some(kind) => return Err(UnsupportedArtifactFileType { kind }),
        };

        Ok(Self { kind, file_type })
    }

    pub fn kind(self) -> PushKind {
        self.kind
    }
}

#[derive(TypedBuilder)]
pub struct ClientPush<S> {
    recordings: RecordingMessageSender,
    claims: JrecTokenClaims,
    client_stream: S,
    target: PushTarget,
    session_id: Uuid,
    shutdown_signal: ShutdownSignal,
}

impl<S> ClientPush<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn run(self) -> anyhow::Result<PushOutcome> {
        let Self {
            recordings,
            claims,
            mut client_stream,
            target,
            session_id,
            mut shutdown_signal,
        } = self;

        if session_id != claims.jet_aid {
            anyhow::bail!("inconsistent session ID (ID in token: {})", claims.jet_aid);
        }

        let disconnected_ttl = match claims.jet_reuse {
            crate::token::ReconnectionPolicy::Disallowed => Duration::ZERO,
            crate::token::ReconnectionPolicy::Allowed { window_in_seconds } => {
                Duration::from_secs(u64::from(window_in_seconds.get())) + DISCONNECTED_TTL_EXTRA_LEEWAY
            }
        };

        let kind = target.kind();
        let policy = kind.policy();

        let recording_file = match recordings.connect(session_id, target, disconnected_ttl).await {
            Ok(connected) => connected,
            Err(e) => {
                warn!(error = format!("{e:#}"), "Unable to start recording");
                client_stream.shutdown().await.context("shutdown")?;
                return Ok(PushOutcome::Done);
            }
        };

        debug!(path = %recording_file, "Opening file");

        let mut open_options = fs::OpenOptions::new();

        open_options.read(false).write(true).truncate(true).create(true);

        #[cfg(windows)]
        {
            const FILE_SHARE_READ: u32 = 1;

            open_options.share_mode(FILE_SHARE_READ);
        }

        debug!(path = %recording_file, "File opened");

        let res = match open_options.open(&recording_file).await {
            Ok(file) => {
                // Wrap SignalWriter inside a BufWriter to reduce the number of flushes.
                let (file, flush_signal) = SignalWriter::new(file);
                // larger buffer size to reduce the number of flushes
                let mut file = BufWriter::with_capacity(BUFFER_WRITER_SIZE, file);
                let mut shutdown_signal_clone = shutdown_signal.clone();
                let copy_fut = io::copy(&mut client_stream, &mut file);
                let signal_loop = tokio::spawn({
                    let recordings = recordings.clone();
                    async move {
                        loop {
                            tokio::select! {
                                _ = flush_signal.notified() => {
                                    if policy.wakes_streamers {
                                        recordings.new_chunk_appended(session_id)?;
                                    }
                                },
                                _ = shutdown_signal_clone.wait() => {
                                    break;
                                },
                            }
                        }
                        Ok::<_, anyhow::Error>(())
                    }
                });

                let res = tokio::select! {
                    res = copy_fut => {
                        match res {
                            Ok(_) => Ok(PushOutcome::Done),
                            Err(e) if is_storage_full(&e) => {
                                warn!(%session_id, "Recording storage is full; closing push stream");
                                Ok(PushOutcome::StorageFull)
                            }
                            Err(e) => Err(anyhow::Error::new(e).context("JREC streaming to file")),
                        }
                    },
                    _ = shutdown_signal.wait() => {
                        trace!("Received shutdown signal");
                        client_stream.shutdown().await.context("shutdown").map(|_| PushOutcome::Done)
                    },
                };

                signal_loop.abort();

                res
            }
            Err(e) => Err(anyhow::Error::new(e).context(format!("failed to open file at {recording_file}"))),
        };

        info!(?res, "Recording finished");

        recordings.disconnect(session_id, kind).await.context("disconnect")?;

        res
    }
}

/// Returns `true` if the I/O error indicates the storage volume is full.
///
/// Uses `io::ErrorKind::StorageFull` (stable since Rust 1.83) which the standard library maps
/// from the platform-specific code: `ENOSPC` on Unix, `ERROR_DISK_FULL` / `ERROR_HANDLE_DISK_FULL`
/// on Windows.
fn is_storage_full(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::StorageFull)
}

/// A set containing IDs of currently active recordings.
///
/// The ID is inserted at the initial recording
///
/// The purpose of this set is to provide a quick way of checking if a recording
/// is on-going for a given session ID in non-async context.
/// If you are looking for the the detailled recording state, you can use the
/// the `get_state` method provided by `RecordingMessageSender`.
#[derive(Debug)]
pub struct ActiveRecordings(Mutex<HashSet<Uuid>>);

impl ActiveRecordings {
    pub fn contains(&self, id: Uuid) -> bool {
        self.0.lock().contains(&id)
    }

    /// Returns a copy of the internal HashSet
    pub fn cloned(&self) -> HashSet<Uuid> {
        self.0.lock().clone()
    }

    fn insert(&self, id: Uuid) -> usize {
        let mut guard = self.0.lock();
        guard.insert(id);
        guard.len()
    }

    fn remove(&self, id: Uuid) {
        self.0.lock().remove(&id);
    }
}

#[derive(Debug, Clone)]
pub enum OnGoingRecordingState {
    Connected,
    LastSeen { timestamp: i64 },
}

/// An ongoing push, one per (session, kind).
///
/// It holds no manifest copy: pushes of other kinds may update the manifest in the meantime.
#[derive(Debug, Clone)]
struct OnGoingPush {
    state: OnGoingRecordingState,
    manifest_path: Utf8PathBuf,
    file_path: Utf8PathBuf,
    /// Position of the pushed file in its manifest list.
    index: usize,
    session_must_be_recorded: bool,
    disconnected_ttl: Duration,
}

enum RecordingManagerMessage {
    Connect {
        id: Uuid,
        target: PushTarget,
        disconnected_ttl: Duration,
        channel: oneshot::Sender<Utf8PathBuf>,
    },
    Disconnect {
        id: Uuid,
        kind: PushKind,
    },
    GetState {
        id: Uuid,
        channel: oneshot::Sender<Option<OnGoingRecordingState>>,
    },
    IsRecording {
        id: Uuid,
        channel: oneshot::Sender<bool>,
    },
    ListFiles {
        id: Uuid,
        channel: oneshot::Sender<Option<Vec<Utf8PathBuf>>>,
    },
    GetCount {
        channel: oneshot::Sender<usize>,
    },
    UpdateRecordingPolicy {
        id: Uuid,
        session_must_be_recorded: bool,
    },
    SubscribeToSessionEndNotification {
        id: Uuid,
        channel: oneshot::Sender<Arc<Notify>>,
    },
}

impl fmt::Debug for RecordingManagerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordingManagerMessage::Connect {
                id,
                target,
                disconnected_ttl,
                channel: _,
            } => f
                .debug_struct("Connect")
                .field("id", id)
                .field("target", target)
                .field("disconnected_ttl", disconnected_ttl)
                .finish_non_exhaustive(),
            RecordingManagerMessage::Disconnect { id, kind } => f
                .debug_struct("Disconnect")
                .field("id", id)
                .field("kind", kind)
                .finish(),
            RecordingManagerMessage::GetState { id, channel: _ } => {
                f.debug_struct("GetState").field("id", id).finish_non_exhaustive()
            }
            RecordingManagerMessage::IsRecording { id, channel: _ } => {
                f.debug_struct("IsRecording").field("id", id).finish_non_exhaustive()
            }
            RecordingManagerMessage::GetCount { channel: _ } => f.debug_struct("GetCount").finish_non_exhaustive(),
            RecordingManagerMessage::UpdateRecordingPolicy {
                id,
                session_must_be_recorded,
            } => f
                .debug_struct("UpdateRecordingPolicy")
                .field("id", id)
                .field("session_must_be_recorded", session_must_be_recorded)
                .finish(),
            RecordingManagerMessage::SubscribeToSessionEndNotification { id, channel: _ } => {
                f.debug_struct("SubscribeToOngoingRecording").field("id", id).finish()
            }
            RecordingManagerMessage::ListFiles { id, channel: _ } => {
                f.debug_struct("ListFiles").field("id", id).finish()
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecordingMessageSender {
    channel: mpsc::Sender<RecordingManagerMessage>,
    flush_map: Arc<Mutex<HashMap<Uuid, Vec<oneshot::Sender<()>>>>>,
    pub active_recordings: Arc<ActiveRecordings>,
}

impl RecordingMessageSender {
    async fn connect(&self, id: Uuid, target: PushTarget, disconnected_ttl: Duration) -> anyhow::Result<Utf8PathBuf> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::Connect {
                id,
                target,
                disconnected_ttl,
                channel: tx,
            })
            .await
            .ok()
            .context("couldn't send New message")?;
        rx.await
            .context("couldn't receive recording file path for this recording")
    }

    async fn disconnect(&self, id: Uuid, kind: PushKind) -> anyhow::Result<()> {
        self.channel
            .send(RecordingManagerMessage::Disconnect { id, kind })
            .await
            .ok()
            .context("couldn't send Remove message")
    }

    pub async fn get_state(&self, id: Uuid) -> anyhow::Result<Option<OnGoingRecordingState>> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::GetState { id, channel: tx })
            .await
            .ok()
            .context("couldn't send GetState message")?;
        rx.await.context("couldn't receive recording state")
    }

    /// Returns whether a Recording, not an artifact, is being pushed for this session.
    pub async fn is_recording(&self, id: Uuid) -> anyhow::Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::IsRecording { id, channel: tx })
            .await
            .ok()
            .context("couldn't send IsRecording message")?;
        rx.await.context("couldn't receive whether a recording is ongoing")
    }

    pub async fn get_count(&self) -> anyhow::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::GetCount { channel: tx })
            .await
            .ok()
            .context("couldn't send GetCount message")?;
        rx.await.context("couldn't receive ongoing recording count")
    }

    pub async fn update_recording_policy(&self, id: Uuid, session_must_be_recorded: bool) -> anyhow::Result<()> {
        self.channel
            .send(RecordingManagerMessage::UpdateRecordingPolicy {
                id,
                session_must_be_recorded,
            })
            .await
            .ok()
            .context("couldn't send UpdateRecordingPolicy message")
    }

    pub(crate) fn add_new_chunk_listener(&self, recording_id: Uuid, tx: oneshot::Sender<()>) {
        let mut lock = self.flush_map.lock();
        let senders = lock.entry(recording_id);
        let senders = senders.or_default();
        senders.push(tx);
    }

    pub(crate) fn new_chunk_appended(&self, recording_id: Uuid) -> anyhow::Result<()> {
        let senders = { self.flush_map.lock().remove(&recording_id) };

        let Some(senders) = senders else {
            return Ok(());
        };

        for tx in senders {
            let _ = tx.send(());
        }

        Ok(())
    }

    pub(crate) async fn subscribe_to_recording_finish(&self, recording_id: Uuid) -> anyhow::Result<Arc<Notify>> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::SubscribeToSessionEndNotification {
                id: recording_id,
                channel: tx,
            })
            .await?;
        Ok(rx.await?)
    }

    /// Returns `None` when no Recording is being pushed, even if an artifact is.
    pub(crate) async fn list_files(&self, recording_id: Uuid) -> anyhow::Result<Option<Vec<Utf8PathBuf>>> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::ListFiles {
                id: recording_id,
                channel: tx,
            })
            .await?;
        Ok(rx.await?)
    }
}

pub struct RecordingMessageReceiver {
    channel: mpsc::Receiver<RecordingManagerMessage>,
    active_recordings: Arc<ActiveRecordings>,
}

pub fn recording_message_channel() -> (RecordingMessageSender, RecordingMessageReceiver) {
    let ongoing_recordings = Arc::new(ActiveRecordings(Mutex::new(HashSet::new())));

    let (tx, rx) = mpsc::channel(64);

    let handle = RecordingMessageSender {
        channel: tx,
        flush_map: Arc::new(Mutex::new(HashMap::new())),
        active_recordings: Arc::clone(&ongoing_recordings),
    };

    let receiver = RecordingMessageReceiver {
        channel: rx,
        active_recordings: ongoing_recordings,
    };

    (handle, receiver)
}

struct DisconnectedTtl {
    deadline: tokio::time::Instant,
    id: Uuid,
    kind: PushKind,
}

impl PartialEq for DisconnectedTtl {
    fn eq(&self, other: &Self) -> bool {
        self.deadline.eq(&other.deadline) && self.id.eq(&other.id) && self.kind.eq(&other.kind)
    }
}

impl Eq for DisconnectedTtl {}

impl PartialOrd for DisconnectedTtl {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DisconnectedTtl {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.deadline.cmp(&other.deadline) {
            cmp::Ordering::Less => cmp::Ordering::Greater,
            cmp::Ordering::Equal => (self.id, self.kind).cmp(&(other.id, other.kind)),
            cmp::Ordering::Greater => cmp::Ordering::Less,
        }
    }
}

pub struct RecordingManagerTask {
    rx: RecordingMessageReceiver,
    ongoing_recordings: HashMap<(Uuid, PushKind), OnGoingPush>,
    recording_end_notifier: HashMap<Uuid, Arc<Notify>>,
    recordings_path: Utf8PathBuf,
    session_manager_handle: SessionMessageSender,
    job_queue_handle: JobQueueHandle,
}

impl RecordingManagerTask {
    pub fn new(
        rx: RecordingMessageReceiver,
        recordings_path: Utf8PathBuf,
        session_manager_handle: SessionMessageSender,
        job_queue_handle: JobQueueHandle,
    ) -> Self {
        Self {
            rx,
            ongoing_recordings: HashMap::new(),
            recording_end_notifier: HashMap::new(),
            recordings_path,
            session_manager_handle,
            job_queue_handle,
        }
    }

    async fn handle_connect(
        &mut self,
        id: Uuid,
        target: PushTarget,
        disconnected_ttl: Duration,
    ) -> anyhow::Result<Utf8PathBuf> {
        const LENGTH_WARNING_THRESHOLD: usize = 1000;

        let kind = target.kind();
        let policy = kind.policy();

        if let Some(ongoing) = self.ongoing_recordings.get(&(id, kind))
            && matches!(ongoing.state, OnGoingRecordingState::Connected)
        {
            anyhow::bail!("concurrent push of the same kind for the same session is not supported");
        }

        let recording_path = self.recordings_path.join(id.to_string());
        let manifest_path = recording_path.join("recording.json");

        let start_time = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut manifest = if recording_path.exists() {
            debug!(path = %recording_path, "Recording directory already exists");

            JrecManifest::read_from_file(&manifest_path).context("read manifest from disk")?
        } else {
            debug!(path = %recording_path, "Create recording directory");

            fs::create_dir_all(&recording_path)
                .await
                .with_context(|| format!("failed to create recording path: {recording_path}"))?;

            // The session timing belongs to the recordings, so the first Recording push sets it.
            JrecManifest {
                session_id: id,
                start_time: 0,
                duration: 0,
                files: Vec::new(),
                artifacts: JrecArtifacts::default(),
            }
        };

        let extension = target.file_type.extension();

        let (file_name, index) = match kind {
            PushKind::Recording => {
                if manifest.files.is_empty() {
                    manifest.start_time = start_time;
                }

                let index = manifest.files.len();
                let file_name = format!("recording-{index}.{extension}");
                manifest.files.push(JrecFile {
                    start_time,
                    duration: 0,
                    file_name: file_name.clone(),
                });
                (file_name, index)
            }
            PushKind::Artifact(artifact_kind) => {
                let artifacts = manifest.artifacts.of_kind_mut(artifact_kind);
                let index = artifacts.len();
                let file_name = format!("{}-{index}.{extension}", artifact_kind.as_str());
                artifacts.push(JrecArtifact {
                    file_name: file_name.clone(),
                });
                (file_name, index)
            }
        };

        let file_path = recording_path.join(&file_name);

        manifest
            .save_to_file(&manifest_path)
            .context("write manifest to disk")?;

        let active_recording_count = if policy.recording_policy {
            self.rx.active_recordings.insert(id)
        } else {
            0
        };

        // NOTE: the session associated to this recording is not always running through the Devolutions Gateway.
        // It is a normal situation when the Devolutions is used solely as a recording server.
        // In such cases, we can only assume there is no recording policy.
        let session_must_be_recorded = policy.recording_policy
            && self
                .session_manager_handle
                .get_session_info(id)
                .await
                .inspect_err(|error| error!(%error, session.id = %id, "Failed to retrieve session info"))
                .ok()
                .flatten()
                .is_some_and(|info| info.recording_policy);

        self.ongoing_recordings.insert(
            (id, kind),
            OnGoingPush {
                state: OnGoingRecordingState::Connected,
                manifest_path,
                file_path: file_path.clone(),
                index,
                session_must_be_recorded,
                disconnected_ttl,
            },
        );
        let ongoing_recording_count = self.ongoing_recordings.len();

        // Sanity check
        if active_recording_count > LENGTH_WARNING_THRESHOLD || ongoing_recording_count > LENGTH_WARNING_THRESHOLD {
            warn!(
                active_recording_count,
                ongoing_recording_count,
                "length threshold exceeded (either the load is very high or the list is growing uncontrollably)"
            );
        }

        Ok(file_path)
    }

    async fn handle_disconnect(&mut self, id: Uuid, kind: PushKind) -> anyhow::Result<()> {
        let policy = kind.policy();

        let Some(ongoing) = self.ongoing_recordings.get_mut(&(id, kind)) else {
            anyhow::bail!("unknown {kind:?} push for ID {id}");
        };

        if !matches!(ongoing.state, OnGoingRecordingState::Connected) {
            anyhow::bail!("a recording not connected can’t be disconnected (there is probably a bug)");
        }

        let end_time = time::OffsetDateTime::now_utc().unix_timestamp();

        ongoing.state = OnGoingRecordingState::LastSeen { timestamp: end_time };

        if policy.tracks_duration {
            debug!(path = %ongoing.manifest_path, "Write updated manifest to disk");

            let mut manifest = JrecManifest::read_from_file(&ongoing.manifest_path)
                .with_context(|| format!("read manifest at {}", ongoing.manifest_path))?;

            let current_file = manifest.files.get_mut(ongoing.index).with_context(|| {
                format!(
                    "no file at index {} in manifest {}",
                    ongoing.index, ongoing.manifest_path
                )
            })?;
            current_file.duration = end_time - current_file.start_time;

            manifest.duration = end_time - manifest.start_time;

            manifest
                .save_to_file(&ongoing.manifest_path)
                .with_context(|| format!("write manifest at {}", ongoing.manifest_path))?;
        }

        let recording_file_path = ongoing.file_path.clone();

        if policy.wakes_streamers
            && let Some(notify) = self.recording_end_notifier.get(&id)
        {
            notify.notify_waiters();
        }

        info!(%id, "Start video remuxing operation");
        if recording_file_path.extension() == Some(RecordingFileType::WebM.extension()) {
            if cadeau::xmf::is_init() {
                debug!(%recording_file_path, "Enqueue video remuxing operation");

                // Schedule 60 seconds to wait for the streamers to release the file.
                let _ = self
                    .job_queue_handle
                    .schedule(
                        RemuxJob {
                            input_path: recording_file_path,
                        },
                        time::OffsetDateTime::now_utc() + time::Duration::seconds(60),
                    )
                    .await;
            } else {
                debug!("Video remuxing was skipped because XMF native library is not loaded");
            }
        }

        Ok(())
    }

    fn handle_remove(&mut self, id: Uuid, kind: PushKind) {
        let policy = kind.policy();

        if let Some(ongoing) = self.ongoing_recordings.get(&(id, kind)) {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let disconnected_ttl_secs = i64::try_from(ongoing.disconnected_ttl.as_secs()).expect("TTL can’t be so big");

            match ongoing.state {
                // NOTE: Comparing with disconnected_ttl_secs - 1 just in case the sleep returns faster than expected.
                // (I don’t know if this can actually happen in practice, but it’s better to be safe than sorry.)
                OnGoingRecordingState::LastSeen { timestamp } if now >= timestamp + disconnected_ttl_secs - 1 => {
                    debug!(%id, ?kind, "Mark push as terminated");

                    if policy.recording_policy {
                        self.rx.active_recordings.remove(id);
                    }

                    // Check the recording policy of the associated session and kill it if necessary.
                    if policy.recording_policy && ongoing.session_must_be_recorded {
                        tokio::spawn({
                            let session_manager_handle = self.session_manager_handle.clone();

                            async move {
                                let result = session_manager_handle.kill_session(id).await;

                                match result {
                                    Ok(crate::session::KillResult::Success) => {
                                        warn!(
                                            session.id = %id,
                                            reason = "recording policy violated",
                                            "Session killed",
                                        );
                                    }
                                    Ok(crate::session::KillResult::NotFound) => {
                                        trace!(
                                            session.id = %id,
                                            "Associated session is not running, as expected",
                                        );
                                    }
                                    Err(error) => {
                                        error!(
                                            session.id = %id,
                                            %error,
                                            "Couldn’t kill session",
                                        )
                                    }
                                }
                            }
                        });
                    }

                    self.ongoing_recordings.remove(&(id, kind));

                    if policy.wakes_streamers {
                        self.recording_end_notifier.remove(&id);
                    }
                }
                _ => {
                    trace!(%id, ?kind, "Push should not be removed yet");
                }
            }
        }
    }

    fn subscribe(&mut self, id: Uuid) -> anyhow::Result<Arc<Notify>> {
        debug!(%id, "Subscribing to ongoing recording");
        if !self.ongoing_recordings.contains_key(&(id, PushKind::Recording)) {
            anyhow::bail!("unknown recording for ID {id}");
        }

        if let Some(notify) = self.recording_end_notifier.get(&id) {
            Ok(Arc::clone(notify))
        } else {
            let notify = Arc::new(Notify::new());
            self.recording_end_notifier.insert(id, Arc::clone(&notify));
            Ok(notify)
        }
    }

    fn list_recording_files(&self, id: Uuid) -> anyhow::Result<Option<Vec<Utf8PathBuf>>> {
        let Some(recording) = self.ongoing_recordings.get(&(id, PushKind::Recording)) else {
            return Ok(None);
        };

        let recordings_folder = recording
            .manifest_path
            .parent()
            .context("manifest path has no parent")?;

        let manifest = JrecManifest::read_from_file(&recording.manifest_path)
            .with_context(|| format!("read manifest at {}", recording.manifest_path))?;

        let files = manifest
            .files
            .iter()
            .map(|file| recordings_folder.join(&file.file_name))
            .collect();

        Ok(Some(files))
    }
}

#[async_trait]
impl Task for RecordingManagerTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "recording manager";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        recording_manager_task(self, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn recording_manager_task(
    mut manager: RecordingManagerTask,
    mut shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    debug!("Task started");

    let mut disconnected = BinaryHeap::<DisconnectedTtl>::new();

    let next_remove_sleep = tokio::time::sleep_until(tokio::time::Instant::now());
    tokio::pin!(next_remove_sleep);

    // Consume initial sleep
    (&mut next_remove_sleep).await;

    loop {
        tokio::select! {
            () = &mut next_remove_sleep, if !disconnected.is_empty() => {
                let to_remove = disconnected.pop().expect("we check for non-emptiness before entering this block");

                manager.handle_remove(to_remove.id, to_remove.kind);

                // Re-arm the Sleep instance with the next deadline if required
                if let Some(next) = disconnected.peek() {
                    next_remove_sleep.as_mut().reset(next.deadline)
                }
            }
            msg = manager.rx.channel.recv() => {
                let Some(msg) = msg else {
                    warn!("All senders are dead");
                    break;
                };

                debug!(?msg, "Received message");

                match msg {
                    RecordingManagerMessage::Connect { id, target, disconnected_ttl, channel  } => {
                        match manager.handle_connect(id, target, disconnected_ttl).await {
                            Ok(connected) => {
                                let _ = channel.send(connected);
                            }
                            Err(e) => error!(error = format!("{e:#}"), "handle_connect"),
                        }
                    },
                    RecordingManagerMessage::Disconnect { id, kind } => {
                        if let Err(e) = manager.handle_disconnect(id, kind).await {
                            error!(error = format!("{e:#}"), "handle_disconnect");
                        }

                        if let Some(ongoing) = manager.ongoing_recordings.get(&(id, kind)) {
                            let now = tokio::time::Instant::now();
                            let deadline = now + ongoing.disconnected_ttl;

                            disconnected.push(DisconnectedTtl {
                                deadline,
                                id,
                                kind,
                            });

                            // Reset the Sleep instance if the new deadline is sooner or it is already elapsed.
                            if next_remove_sleep.is_elapsed() || deadline < next_remove_sleep.deadline() {
                                next_remove_sleep.as_mut().reset(deadline);
                            }
                        }
                    }
                    RecordingManagerMessage::GetState { id, channel } => {
                        let response = manager
                            .ongoing_recordings
                            .get(&(id, PushKind::Recording))
                            .map(|ongoing| ongoing.state.clone());
                        let _ = channel.send(response);
                    }
                    RecordingManagerMessage::IsRecording { id, channel } => {
                        let is_recording = manager.ongoing_recordings.contains_key(&(id, PushKind::Recording));
                        let _ = channel.send(is_recording);
                    }
                    RecordingManagerMessage::GetCount { channel } => {
                        let _ = channel.send(manager.ongoing_recordings.len());
                    }
                    RecordingManagerMessage::UpdateRecordingPolicy { id, session_must_be_recorded } => {
                        if let Some(ongoing) = manager.ongoing_recordings.get_mut(&(id, PushKind::Recording)) {
                            ongoing.session_must_be_recorded = session_must_be_recorded;
                            trace!(
                                session.id = %id,
                                session_must_be_recorded,
                                "Updated recording policy for session",
                            );
                        }
                    },
                    RecordingManagerMessage::SubscribeToSessionEndNotification {id, channel } => {
                        match manager.subscribe(id) {
                            Ok(notifier) => {
                                let _ = channel.send(notifier);
                            },
                            Err(e) => error!(error = format!("{e:#}"), "subscribe to session end notification"),
                        }
                    },
                    RecordingManagerMessage::ListFiles { id, channel } => {
                        match manager.list_recording_files(id) {
                            Ok(files) => {
                                let _ = channel.send(files);
                            }
                            Err(e) => error!(error = format!("{e:#}"), session.id = %id, "list recording files"),
                        }
                    }
                }
            }
            _ = shutdown_signal.wait() => {
                break;
            }
        }
    }

    debug!("Task is stopping; wait for disconnect messages");

    loop {
        // Here, we await with a timeout because this task holds a handle to the
        // session manager, but the session manager itself also holds a handle to
        // the recording manager. As long as the other end doesn’t drop the handle, the
        // recv future will never resolve. We simply assume there are no leftover messages
        // to process after one second of inactivity.
        let msg = match futures::future::select(
            pin!(manager.rx.channel.recv()),
            pin!(tokio::time::sleep(Duration::from_secs(1))),
        )
        .await
        {
            Either::Left((Some(msg), _)) => msg,
            Either::Left((None, _)) => break,
            Either::Right(_) => break,
        };

        debug!(?msg, "Received message");
        if let RecordingManagerMessage::Disconnect { id, kind } = msg {
            if let Err(e) = manager.handle_disconnect(id, kind).await {
                error!(error = format!("{e:#}"), "handle_disconnect");
            }
            manager.ongoing_recordings.remove(&(id, kind));
        }
    }

    debug!("Task terminated");

    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct RemuxJob {
    input_path: Utf8PathBuf,
}

impl RemuxJob {
    pub const NAME: &'static str = "remux";
}

#[async_trait]
impl job_queue::Job for RemuxJob {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(self).context("failed to serialize RemuxAction")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        remux(core::mem::take(&mut self.input_path)).await;
        Ok(())
    }
}

async fn remux(input_path: Utf8PathBuf) {
    // CPU-intensive operation potentially lasting much more than 100ms.
    match tokio::task::spawn_blocking(move || remux_impl(input_path)).await {
        Err(error) => error!(%error, "Couldn't join the CPU-intensive muxer task"),
        Ok(Err(error)) => error!(error = format!("{error:#}"), "Remux operation failed"),
        Ok(Ok(())) => {}
    }

    return;

    fn remux_impl(input_path: Utf8PathBuf) -> anyhow::Result<()> {
        let input_file_name = input_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid path (not a file): {input_path}"))?;

        let remuxed_file_name = format!("remuxed_{input_file_name}");

        let output_path = input_path
            .parent()
            .context("failed to retrieve parent folder")?
            .join(remuxed_file_name);

        cadeau::xmf::muxer::webm_remux(&input_path, &output_path)
            .with_context(|| format!("failed to remux file {input_path} to {output_path}"))?;

        std::fs::rename(&output_path, &input_path).context("failed to override remuxed file")?;

        debug!(%input_path, "Successfully remuxed video recording");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use devolutions_gateway_task::ShutdownHandle;
    use serde_json::json;

    use super::*;

    const AI_ANALYSIS_KIND: PushKind = PushKind::Artifact(ArtifactKind::AiAnalysis);

    const MASTER_MANIFEST: &str = r#"{
  "sessionId": "22fcd533-5e72-4db7-aa0f-29952dbbca9f",
  "startTime": 1,
  "duration": 5,
  "files": [
    {
      "fileName": "recording-0.webm",
      "startTime": 1,
      "duration": 5
    }
  ]
}"#;

    fn webm() -> PushTarget {
        PushTarget::new(RecordingFileType::WebM, None).expect("webm recording")
    }

    fn slog_recording() -> PushTarget {
        PushTarget::new(RecordingFileType::SessionRecordingLog, None).expect("slog recording")
    }

    fn ai_analysis() -> PushTarget {
        PushTarget::new(RecordingFileType::SessionRecordingLog, Some(ArtifactKind::AiAnalysis)).expect("ai-analysis")
    }

    struct Harness {
        _dir: tempfile::TempDir,
        recordings_path: Utf8PathBuf,
        sender: RecordingMessageSender,
        kills: mpsc::UnboundedReceiver<Uuid>,
        _shutdown_handle: ShutdownHandle,
    }

    impl Harness {
        fn start() -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            let recordings_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");
            let (sender, receiver) = recording_message_channel();
            let (session_manager_handle, kills) = crate::session::spawn_fake_session_manager();
            let (job_queue_handle, _) = JobQueueHandle::new();
            let task = RecordingManagerTask::new(
                receiver,
                recordings_path.clone(),
                session_manager_handle,
                job_queue_handle,
            );
            let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
            tokio::spawn(recording_manager_task(task, shutdown_signal));

            Self {
                _dir: dir,
                recordings_path,
                sender,
                kills,
                _shutdown_handle: shutdown_handle,
            }
        }

        fn manifest_path(&self, id: Uuid) -> Utf8PathBuf {
            self.recordings_path.join(id.to_string()).join("recording.json")
        }

        fn write_manifest(&self, id: Uuid, json: &str) {
            std::fs::create_dir_all(self.recordings_path.join(id.to_string())).expect("create recording dir");
            std::fs::write(self.manifest_path(id), json).expect("write manifest");
        }

        fn read_manifest(&self, id: Uuid) -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(self.manifest_path(id)).expect("read manifest"))
                .expect("parse manifest")
        }

        async fn try_connect(&self, id: Uuid, target: PushTarget) -> anyhow::Result<Utf8PathBuf> {
            self.sender.connect(id, target, Duration::ZERO).await
        }

        async fn connect_with_ttl(&self, id: Uuid, target: PushTarget, disconnected_ttl: Duration) -> String {
            let path = self
                .sender
                .connect(id, target, disconnected_ttl)
                .await
                .expect("connect");
            path.file_name().expect("file name").to_owned()
        }

        async fn connect(&self, id: Uuid, target: PushTarget) -> String {
            self.connect_with_ttl(id, target, Duration::ZERO).await
        }

        async fn disconnect(&self, id: Uuid, kind: PushKind) {
            self.sender.disconnect(id, kind).await.expect("disconnect");
            // Messages are processed in order, so this waits for the disconnect to be handled.
            self.sender.get_count().await.expect("sync with manager");
        }

        async fn push(&self, id: Uuid, target: PushTarget) -> String {
            let file_name = self.connect(id, target).await;
            self.disconnect(id, target.kind()).await;
            file_name
        }

        async fn must_be_recorded(&self, id: Uuid) {
            self.sender
                .update_recording_policy(id, true)
                .await
                .expect("update recording policy");
        }

        async fn wait_until_no_push(&self) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while self.sender.get_count().await.expect("count") != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("expired pushes are removed");
        }

        async fn next_kill(&mut self) -> Uuid {
            tokio::time::timeout(Duration::from_secs(5), self.kills.recv())
                .await
                .expect("a kill request")
                .expect("session manager alive")
        }

        fn start_client_push(
            &self,
            id: Uuid,
            target: PushTarget,
        ) -> (
            io::DuplexStream,
            tokio::task::JoinHandle<anyhow::Result<PushOutcome>>,
            ShutdownHandle,
        ) {
            let claims = serde_json::from_value(json!({
                "jet_aid": id,
                "jet_rop": "push",
                "exp": i64::MAX,
                "jti": Uuid::new_v4(),
            }))
            .expect("claims");
            let (client, server) = io::duplex(1024);
            let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
            let push = tokio::spawn(
                ClientPush::builder()
                    .recordings(self.sender.clone())
                    .claims(claims)
                    .client_stream(server)
                    .target(target)
                    .session_id(id)
                    .shutdown_signal(shutdown_signal)
                    .build()
                    .run(),
            );
            (client, push, shutdown_handle)
        }
    }

    #[tokio::test]
    async fn slog_recording_stays_in_files() {
        let harness = Harness::start();
        let id = Uuid::new_v4();

        let first = harness.push(id, slog_recording()).await;
        harness.push(id, webm()).await;
        let third = harness.push(id, slog_recording()).await;

        assert_eq!(first, "recording-0.slog");
        assert_eq!(third, "recording-2.slog");
        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["files"][2]["fileName"], "recording-2.slog");
        assert!(manifest.get("artifacts").is_none());
    }

    #[tokio::test]
    async fn ai_analysis_goes_to_artifacts() {
        let harness = Harness::start();
        let id = Uuid::new_v4();

        harness.push(id, webm()).await;
        let first_artifact = harness.push(id, ai_analysis()).await;
        let second_artifact = harness.push(id, ai_analysis()).await;

        assert_eq!(first_artifact, "ai-analysis-0.slog");
        assert_eq!(second_artifact, "ai-analysis-1.slog");
        let manifest = harness.read_manifest(id);
        let files = manifest["files"].as_array().expect("files");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["fileName"], "recording-0.webm");
        assert_eq!(
            manifest["artifacts"],
            json!({ "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }, { "fileName": "ai-analysis-1.slog" }] })
        );
    }

    #[tokio::test]
    async fn artifact_first_leaves_session_timing_to_the_recording() {
        let harness = Harness::start();
        let id = Uuid::new_v4();

        let artifact = harness.push(id, ai_analysis()).await;

        assert_eq!(artifact, "ai-analysis-0.slog");
        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["files"], json!([]));
        assert_eq!(manifest["startTime"], 0);
        assert_eq!(manifest["duration"], 0);
        assert_eq!(
            manifest["artifacts"],
            json!({ "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }] })
        );

        assert_eq!(harness.connect(id, webm()).await, "recording-0.webm");
        let manifest = harness.read_manifest(id);
        assert_ne!(manifest["startTime"], 0);
        assert_eq!(manifest["startTime"], manifest["files"][0]["startTime"]);
    }

    #[tokio::test]
    async fn artifact_push_keeps_recording_timing() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.write_manifest(id, MASTER_MANIFEST);

        harness.push(id, ai_analysis()).await;

        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["startTime"], 1);
        assert_eq!(manifest["duration"], 5);
        assert_eq!(manifest["files"][0]["duration"], 5);

        harness.connect(id, webm()).await;
        assert_eq!(harness.read_manifest(id)["startTime"], 1);
    }

    #[tokio::test]
    async fn recording_reconnect_keeps_artifacts() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.push(id, webm()).await;
        harness.push(id, ai_analysis()).await;

        let file_name = harness.connect(id, webm()).await;
        assert_eq!(file_name, "recording-1.webm");
        assert_eq!(
            harness.read_manifest(id)["artifacts"],
            json!({ "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }] })
        );

        harness.disconnect(id, PushKind::Recording).await;
        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["files"][1]["fileName"], "recording-1.webm");
        assert_eq!(
            manifest["artifacts"],
            json!({ "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }] })
        );
    }

    #[tokio::test]
    async fn shadow_streams_ongoing_recording() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.connect(id, webm()).await;

        let files = harness.sender.list_files(id).await.expect("list files");

        let files = files.expect("a Recording is being pushed");
        let file_names: Vec<_> = files.iter().filter_map(|path| path.file_name()).collect();
        assert_eq!(file_names, ["recording-0.webm"]);
    }

    #[tokio::test]
    async fn shadow_refuses_while_only_an_artifact_is_pushed() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.connect(id, ai_analysis()).await;

        assert!(harness.sender.list_files(id).await.expect("list files").is_none());
        assert!(harness.sender.get_state(id).await.expect("get state").is_none());
        assert!(!harness.sender.active_recordings.contains(id));
    }

    #[tokio::test]
    async fn artifact_chunks_do_not_wake_streamers() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        let (tx, mut woken) = oneshot::channel();
        harness.sender.add_new_chunk_listener(id, tx);

        let (mut client, push, _shutdown_handle) = harness.start_client_push(id, ai_analysis());
        client.write_all(b"chunk").await.expect("write chunk");
        drop(client);
        push.await.expect("join push").expect("push");
        harness.sender.get_count().await.expect("sync with manager");

        let artifact_path = harness.recordings_path.join(id.to_string()).join("ai-analysis-0.slog");
        assert_eq!(std::fs::read(artifact_path).expect("read artifact"), b"chunk");
        assert_eq!(woken.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    }

    #[tokio::test]
    async fn slog_recording_chunks_wake_streamers() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        let (tx, mut woken) = oneshot::channel();
        harness.sender.add_new_chunk_listener(id, tx);

        let (mut client, push, _shutdown_handle) = harness.start_client_push(id, slog_recording());

        // The push flushes, and so signals, whenever it runs out of input.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                client.write_all(b"chunk").await.expect("write chunk");
                tokio::select! {
                    _ = &mut woken => break,
                    () = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
            }
        })
        .await
        .expect("streamers woken");

        drop(client);
        push.await.expect("join push").expect("push");
    }

    #[test]
    fn only_the_recording_kind_takes_part_in_the_recording_policy() {
        assert_eq!(
            PushKind::Recording.policy(),
            KindPolicy {
                recording_policy: true,
                wakes_streamers: true,
                tracks_duration: true,
            }
        );
        assert_eq!(
            AI_ANALYSIS_KIND.policy(),
            KindPolicy {
                recording_policy: false,
                wakes_streamers: false,
                tracks_duration: false,
            }
        );
    }

    #[test]
    fn ai_analysis_must_be_slog() {
        let error = PushTarget::new(RecordingFileType::WebM, Some(ArtifactKind::AiAnalysis)).expect_err("webm");
        assert_eq!(error.to_string(), "ai-analysis artifacts must be slog files");
    }

    #[test]
    fn artifact_kind_names_match_their_serde_names() {
        let kind = ArtifactKind::AiAnalysis;
        let parsed: ArtifactKind = serde_json::from_value(json!(kind.as_str())).expect("parse kind");
        assert_eq!(parsed, kind);
    }

    #[tokio::test]
    async fn only_a_recording_push_counts_as_recording() {
        let harness = Harness::start();
        let artifact_only = Uuid::new_v4();
        let recorded = Uuid::new_v4();

        harness.connect(artifact_only, ai_analysis()).await;
        harness.connect(recorded, webm()).await;
        harness.connect(recorded, ai_analysis()).await;
        harness.disconnect(recorded, AI_ANALYSIS_KIND).await;

        assert!(!harness.sender.is_recording(artifact_only).await.expect("is recording"));
        assert!(harness.sender.is_recording(recorded).await.expect("is recording"));
        assert!(!harness.sender.is_recording(Uuid::new_v4()).await.expect("is recording"));
        assert!(!harness.sender.active_recordings.contains(artifact_only));
        assert!(harness.sender.active_recordings.contains(recorded));
    }

    #[tokio::test]
    async fn artifact_push_does_not_disarm_the_recording_ttl_kill() {
        let mut harness = Harness::start();
        let id = Uuid::new_v4();
        harness.connect_with_ttl(id, webm(), Duration::from_secs(1)).await;
        harness.must_be_recorded(id).await;
        harness.disconnect(id, PushKind::Recording).await;

        harness.push(id, ai_analysis()).await;

        assert!(matches!(
            harness.sender.get_state(id).await.expect("get state"),
            Some(OnGoingRecordingState::LastSeen { .. })
        ));
        assert!(harness.sender.is_recording(id).await.expect("is recording"));
        assert_eq!(harness.next_kill().await, id);
    }

    #[tokio::test]
    async fn artifact_ttl_expiry_never_kills_the_session() {
        let mut harness = Harness::start();
        let artifact_only = Uuid::new_v4();
        let recorded = Uuid::new_v4();

        harness.connect(artifact_only, ai_analysis()).await;
        harness.must_be_recorded(artifact_only).await;
        harness.disconnect(artifact_only, AI_ANALYSIS_KIND).await;
        harness.wait_until_no_push().await;

        harness.connect(recorded, webm()).await;
        harness.must_be_recorded(recorded).await;
        harness.disconnect(recorded, PushKind::Recording).await;

        // Kill requests reach the session manager in the order they were issued.
        assert_eq!(harness.next_kill().await, recorded);
    }

    #[tokio::test]
    async fn recording_and_artifact_push_at_the_same_time() {
        let harness = Harness::start();
        let id = Uuid::new_v4();

        harness.connect(id, webm()).await;
        assert_eq!(harness.connect(id, ai_analysis()).await, "ai-analysis-0.slog");
        assert!(harness.try_connect(id, webm()).await.is_err());
        assert!(harness.try_connect(id, ai_analysis()).await.is_err());

        harness.disconnect(id, AI_ANALYSIS_KIND).await;
        assert!(matches!(
            harness.sender.get_state(id).await.expect("get state"),
            Some(OnGoingRecordingState::Connected)
        ));

        harness.disconnect(id, PushKind::Recording).await;
        harness.connect(id, ai_analysis()).await;
        assert_eq!(harness.connect(id, webm()).await, "recording-1.webm");
    }

    #[tokio::test]
    async fn concurrent_pushes_keep_each_others_manifest_entries() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        let expected_artifacts = json!({ "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }] });

        harness.connect(id, webm()).await;
        harness.connect(id, ai_analysis()).await;
        harness.disconnect(id, PushKind::Recording).await;
        assert_eq!(harness.read_manifest(id)["artifacts"], expected_artifacts);

        harness.connect(id, webm()).await;
        harness.disconnect(id, AI_ANALYSIS_KIND).await;
        harness.disconnect(id, PushKind::Recording).await;

        let manifest = harness.read_manifest(id);
        let file_names: Vec<_> = manifest["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|file| file["fileName"].clone())
            .collect();
        assert_eq!(file_names, [json!("recording-0.webm"), json!("recording-1.webm")]);
        assert_eq!(manifest["artifacts"], expected_artifacts);
    }

    #[test]
    fn manifest_without_artifacts_round_trips_byte_for_byte() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("recording.json");
        std::fs::write(&path, MASTER_MANIFEST).expect("write manifest");

        let manifest = JrecManifest::read_from_file(&path).expect("read manifest");
        manifest.save_to_file(&path).expect("save manifest");

        assert_eq!(std::fs::read_to_string(&path).expect("read back"), MASTER_MANIFEST);
    }
}
