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
    /// Append-only, like `files`: artifact names and `CurrentArtifact` indices are derived from positions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    logs: Vec<JrecLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecLog {
    file_name: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushCategory {
    Recording(RecordingFileType),
    /// Opaque to Gateway: stored as-is, whatever its content.
    Log(RecordingFileType),
}

#[derive(TypedBuilder)]
pub struct ClientPush<S> {
    recordings: RecordingMessageSender,
    claims: JrecTokenClaims,
    client_stream: S,
    category: PushCategory,
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
            category,
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

        let (recording_file, artifact) = match recordings.connect(session_id, category, disconnected_ttl).await {
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
                                    // Log data is not media, so it must not wake `/shadow` streamers.
                                    if let CurrentArtifact::Recording(_) = artifact {
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

        recordings.disconnect(session_id).await.context("disconnect")?;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurrentArtifact {
    Recording(usize),
    Log(usize),
}

#[derive(Debug, Clone)]
struct OnGoingRecording {
    state: OnGoingRecordingState,
    manifest: JrecManifest,
    manifest_path: Utf8PathBuf,
    session_must_be_recorded: bool,
    disconnected_ttl: Duration,
    artifact: CurrentArtifact,
}

enum RecordingManagerMessage {
    Connect {
        id: Uuid,
        category: PushCategory,
        disconnected_ttl: Duration,
        channel: oneshot::Sender<(Utf8PathBuf, CurrentArtifact)>,
    },
    Disconnect {
        id: Uuid,
    },
    GetState {
        id: Uuid,
        channel: oneshot::Sender<Option<OnGoingRecordingState>>,
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
                category,
                disconnected_ttl,
                channel: _,
            } => f
                .debug_struct("Connect")
                .field("id", id)
                .field("category", category)
                .field("disconnected_ttl", disconnected_ttl)
                .finish_non_exhaustive(),
            RecordingManagerMessage::Disconnect { id } => f.debug_struct("Disconnect").field("id", id).finish(),
            RecordingManagerMessage::GetState { id, channel: _ } => {
                f.debug_struct("GetState").field("id", id).finish_non_exhaustive()
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
    async fn connect(
        &self,
        id: Uuid,
        category: PushCategory,
        disconnected_ttl: Duration,
    ) -> anyhow::Result<(Utf8PathBuf, CurrentArtifact)> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::Connect {
                id,
                category,
                disconnected_ttl,
                channel: tx,
            })
            .await
            .ok()
            .context("couldn't send New message")?;
        rx.await
            .context("couldn't receive recording file path for this recording")
    }

    async fn disconnect(&self, id: Uuid) -> anyhow::Result<()> {
        self.channel
            .send(RecordingManagerMessage::Disconnect { id })
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

    /// Returns `None` when the ongoing push is a Log: there is no Recording to stream.
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
}

impl PartialEq for DisconnectedTtl {
    fn eq(&self, other: &Self) -> bool {
        self.deadline.eq(&other.deadline) && self.id.eq(&other.id)
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
            cmp::Ordering::Equal => self.id.cmp(&other.id),
            cmp::Ordering::Greater => cmp::Ordering::Less,
        }
    }
}

pub struct RecordingManagerTask {
    rx: RecordingMessageReceiver,
    ongoing_recordings: HashMap<Uuid, OnGoingRecording>,
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
        category: PushCategory,
        disconnected_ttl: Duration,
    ) -> anyhow::Result<(Utf8PathBuf, CurrentArtifact)> {
        const LENGTH_WARNING_THRESHOLD: usize = 1000;

        if let Some(ongoing) = self.ongoing_recordings.get(&id)
            && matches!(ongoing.state, OnGoingRecordingState::Connected)
        {
            anyhow::bail!("concurrent recording for the same session is not supported");
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

            JrecManifest {
                session_id: id,
                start_time,
                duration: 0,
                files: Vec::new(),
                logs: Vec::new(),
            }
        };

        let (file_name, artifact) = match category {
            PushCategory::Recording(file_type) => {
                let idx = manifest.files.len();
                let file_name = format!("recording-{idx}.{}", file_type.extension());
                manifest.files.push(JrecFile {
                    start_time,
                    duration: 0,
                    file_name: file_name.clone(),
                });
                (file_name, CurrentArtifact::Recording(idx))
            }
            PushCategory::Log(file_type) => {
                let idx = manifest.logs.len();
                let file_name = format!("log-{idx}.{}", file_type.extension());
                manifest.logs.push(JrecLog {
                    file_name: file_name.clone(),
                });
                (file_name, CurrentArtifact::Log(idx))
            }
        };

        let recording_file = recording_path.join(&file_name);

        manifest
            .save_to_file(&manifest_path)
            .context("write manifest to disk")?;

        let active_recording_count = self.rx.active_recordings.insert(id);

        // NOTE: the session associated to this recording is not always running through the Devolutions Gateway.
        // It is a normal situation when the Devolutions is used solely as a recording server.
        // In such cases, we can only assume there is no recording policy.
        let session_must_be_recorded = self
            .session_manager_handle
            .get_session_info(id)
            .await
            .inspect_err(|error| error!(%error, session.id = %id, "Failed to retrieve session info"))
            .ok()
            .flatten()
            .map(|info| info.recording_policy)
            .unwrap_or(false);

        self.ongoing_recordings.insert(
            id,
            OnGoingRecording {
                state: OnGoingRecordingState::Connected,
                manifest,
                manifest_path,
                session_must_be_recorded,
                disconnected_ttl,
                artifact,
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

        Ok((recording_file, artifact))
    }

    async fn handle_disconnect(&mut self, id: Uuid) -> anyhow::Result<()> {
        let Some(ongoing) = self.ongoing_recordings.get_mut(&id) else {
            return Err(anyhow::anyhow!("unknown recording for ID {id}"));
        };

        if !matches!(ongoing.state, OnGoingRecordingState::Connected) {
            anyhow::bail!("a recording not connected can’t be disconnected (there is probably a bug)");
        }

        let end_time = time::OffsetDateTime::now_utc().unix_timestamp();

        ongoing.state = OnGoingRecordingState::LastSeen { timestamp: end_time };

        let current_file_name = match ongoing.artifact {
            CurrentArtifact::Recording(idx) => {
                let current_file = &mut ongoing.manifest.files[idx];
                current_file.duration = end_time - current_file.start_time;

                ongoing.manifest.duration = end_time - ongoing.manifest.start_time;

                &current_file.file_name
            }
            CurrentArtifact::Log(idx) => &ongoing.manifest.logs[idx].file_name,
        };

        let recording_file_path = ongoing
            .manifest_path
            .parent()
            .expect("a parent")
            .join(current_file_name);

        debug!(path = %ongoing.manifest_path, "Write updated manifest to disk");

        ongoing
            .manifest
            .save_to_file(&ongoing.manifest_path)
            .with_context(|| format!("write manifest at {}", ongoing.manifest_path))?;

        // Notify all the streamers that recording has ended.
        if let Some(notify) = self.recording_end_notifier.get(&id) {
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

    fn handle_remove(&mut self, id: Uuid) {
        if let Some(ongoing) = self.ongoing_recordings.get(&id) {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let disconnected_ttl_secs = i64::try_from(ongoing.disconnected_ttl.as_secs()).expect("TTL can’t be so big");

            match ongoing.state {
                // NOTE: Comparing with disconnected_ttl_secs - 1 just in case the sleep returns faster than expected.
                // (I don’t know if this can actually happen in practice, but it’s better to be safe than sorry.)
                OnGoingRecordingState::LastSeen { timestamp } if now >= timestamp + disconnected_ttl_secs - 1 => {
                    debug!(%id, "Mark recording as terminated");
                    self.rx.active_recordings.remove(id);

                    // Check the recording policy of the associated session and kill it if necessary.
                    if ongoing.session_must_be_recorded {
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

                    self.ongoing_recordings.remove(&id);
                    self.recording_end_notifier.remove(&id);
                }
                _ => {
                    trace!(%id, "Recording should not be removed yet");
                }
            }
        }
    }

    fn subscribe(&mut self, id: Uuid) -> anyhow::Result<Arc<Notify>> {
        debug!(%id, "Subscribing to ongoing recording");
        if !self.ongoing_recordings.contains_key(&id) {
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

                manager.handle_remove(to_remove.id);

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
                    RecordingManagerMessage::Connect { id, category, disconnected_ttl, channel  } => {
                        match manager.handle_connect(id, category, disconnected_ttl).await {
                            Ok(connected) => {
                                let _ = channel.send(connected);
                            }
                            Err(e) => error!(error = format!("{e:#}"), "handle_connect"),
                        }
                    },
                    RecordingManagerMessage::Disconnect { id } => {
                        if let Err(e) = manager.handle_disconnect(id).await {
                            error!(error = format!("{e:#}"), "handle_disconnect");
                        }

                        if let Some(ongoing) = manager.ongoing_recordings.get(&id) {
                            let now = tokio::time::Instant::now();
                            let deadline = now + ongoing.disconnected_ttl;

                            disconnected.push(DisconnectedTtl {
                                deadline,
                                id,
                            });

                            // Reset the Sleep instance if the new deadline is sooner or it is already elapsed.
                            if next_remove_sleep.is_elapsed() || deadline < next_remove_sleep.deadline() {
                                next_remove_sleep.as_mut().reset(deadline);
                            }
                        }
                    }
                    RecordingManagerMessage::GetState { id, channel } => {
                        let response = manager.ongoing_recordings.get(&id).map(|ongoing| ongoing.state.clone());
                        let _ = channel.send(response);
                    }
                    RecordingManagerMessage::GetCount { channel } => {
                        let _ = channel.send(manager.ongoing_recordings.len());
                    }
                    RecordingManagerMessage::UpdateRecordingPolicy { id, session_must_be_recorded } => {
                        if let Some(ongoing) = manager.ongoing_recordings.get_mut(&id) {
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
                        match manager.ongoing_recordings.get(&id) {
                            Some(recording) if matches!(recording.artifact, CurrentArtifact::Log(_)) => {
                                let _ = channel.send(None);
                            }
                            Some(recording) => {
                                let recordings_folder = recording.manifest_path.parent().expect("a parent");

                                let files = recording
                                    .manifest
                                    .files
                                    .iter()
                                    .map(|file| recordings_folder.join(&file.file_name))
                                    .collect();

                                let _ = channel.send(Some(files));
                            }
                            None => {
                                warn!(%id, "No recording found for provided ID");
                            }
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
        if let RecordingManagerMessage::Disconnect { id } = msg {
            if let Err(e) = manager.handle_disconnect(id).await {
                error!(error = format!("{e:#}"), "handle_disconnect");
            }
            manager.ongoing_recordings.remove(&id);
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

    const WEBM: PushCategory = PushCategory::Recording(RecordingFileType::WebM);
    const SLOG_RECORDING: PushCategory = PushCategory::Recording(RecordingFileType::SessionRecordingLog);
    const SLOG_LOG: PushCategory = PushCategory::Log(RecordingFileType::SessionRecordingLog);

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

    struct Harness {
        _dir: tempfile::TempDir,
        recordings_path: Utf8PathBuf,
        sender: RecordingMessageSender,
        _shutdown_handle: ShutdownHandle,
    }

    impl Harness {
        fn start() -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            let recordings_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");
            let (sender, receiver) = recording_message_channel();
            let (session_manager_handle, _) = crate::session::session_manager_channel();
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

        async fn connect(&self, id: Uuid, category: PushCategory) -> String {
            let (path, _) = self
                .sender
                .connect(id, category, Duration::ZERO)
                .await
                .expect("connect");
            path.file_name().expect("file name").to_owned()
        }

        async fn client_push_wakes_streamers(&self, id: Uuid, category: PushCategory) -> bool {
            let claims = serde_json::from_value(json!({
                "jet_aid": id,
                "jet_rop": "push",
                "exp": i64::MAX,
                "jti": Uuid::new_v4(),
            }))
            .expect("claims");
            let (mut client, server) = io::duplex(1024);
            let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
            let push = tokio::spawn(
                ClientPush::builder()
                    .recordings(self.sender.clone())
                    .claims(claims)
                    .client_stream(server)
                    .category(category)
                    .session_id(id)
                    .shutdown_signal(shutdown_signal)
                    .build()
                    .run(),
            );

            let (tx, mut woken) = oneshot::channel();
            self.sender.add_new_chunk_listener(id, tx);

            // The push flushes, and so signals, whenever it runs out of input.
            let woke = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    client.write_all(b"chunk").await.expect("write chunk");
                    tokio::select! {
                        _ = &mut woken => break,
                        () = tokio::time::sleep(Duration::from_millis(20)) => {}
                    }
                }
            })
            .await
            .is_ok();

            drop(client);
            push.await.expect("join push").expect("push");
            self.sender.get_count().await.expect("sync with manager");
            drop(shutdown_handle);
            woke
        }

        async fn disconnect(&self, id: Uuid) {
            self.sender.disconnect(id).await.expect("disconnect");
            // Messages are processed in order, so this waits for the disconnect to be handled.
            self.sender.get_count().await.expect("sync with manager");
        }

        async fn push(&self, id: Uuid, category: PushCategory) -> String {
            let file_name = self.connect(id, category).await;
            self.disconnect(id).await;
            file_name
        }
    }

    #[tokio::test]
    async fn slog_recording_stays_in_files() {
        let harness = Harness::start();
        let id = Uuid::new_v4();

        let first = harness.push(id, SLOG_RECORDING).await;
        harness.push(id, WEBM).await;
        let third = harness.push(id, SLOG_RECORDING).await;

        assert_eq!(first, "recording-0.slog");
        assert_eq!(third, "recording-2.slog");
        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["files"][2]["fileName"], "recording-2.slog");
        assert!(manifest.get("logs").is_none());
    }

    #[tokio::test]
    async fn log_category_goes_to_logs() {
        let harness = Harness::start();
        let id = Uuid::new_v4();

        harness.push(id, WEBM).await;
        let first_log = harness.push(id, SLOG_LOG).await;
        let second_log = harness.push(id, SLOG_LOG).await;

        assert_eq!(first_log, "log-0.slog");
        assert_eq!(second_log, "log-1.slog");
        let manifest = harness.read_manifest(id);
        let files = manifest["files"].as_array().expect("files");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["fileName"], "recording-0.webm");
        assert_eq!(
            manifest["logs"],
            json!([{ "fileName": "log-0.slog" }, { "fileName": "log-1.slog" }])
        );
    }

    #[tokio::test]
    async fn log_before_any_recording() {
        let harness = Harness::start();
        let id = Uuid::new_v4();

        let log = harness.push(id, SLOG_LOG).await;

        assert_eq!(log, "log-0.slog");
        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["files"], json!([]));
        assert_eq!(manifest["logs"], json!([{ "fileName": "log-0.slog" }]));

        assert_eq!(harness.push(id, WEBM).await, "recording-0.webm");
    }

    #[tokio::test]
    async fn log_push_keeps_recording_durations() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.write_manifest(id, MASTER_MANIFEST);

        harness.push(id, SLOG_LOG).await;

        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["duration"], 5);
        assert_eq!(manifest["files"][0]["duration"], 5);
    }

    #[tokio::test]
    async fn recording_reconnect_keeps_logs() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.push(id, WEBM).await;
        harness.push(id, SLOG_LOG).await;

        let file_name = harness.connect(id, WEBM).await;
        assert_eq!(file_name, "recording-1.webm");
        assert_eq!(harness.read_manifest(id)["logs"], json!([{ "fileName": "log-0.slog" }]));

        harness.disconnect(id).await;
        let manifest = harness.read_manifest(id);
        assert_eq!(manifest["files"][1]["fileName"], "recording-1.webm");
        assert_eq!(manifest["logs"], json!([{ "fileName": "log-0.slog" }]));
    }

    #[tokio::test]
    async fn shadow_streams_ongoing_recording() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.connect(id, WEBM).await;

        let files = harness.sender.list_files(id).await.expect("list files");

        let files = files.expect("a Recording is being pushed");
        let file_names: Vec<_> = files.iter().filter_map(|path| path.file_name()).collect();
        assert_eq!(file_names, ["recording-0.webm"]);
    }

    #[tokio::test]
    async fn shadow_refuses_while_only_a_log_is_pushed() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.push(id, WEBM).await;
        harness.connect(id, SLOG_LOG).await;

        let files = harness.sender.list_files(id).await.expect("list files");

        assert!(files.is_none());
    }

    #[tokio::test]
    async fn log_chunks_do_not_wake_streamers() {
        let harness = Harness::start();
        let id = Uuid::new_v4();
        harness.push(id, WEBM).await;

        assert!(!harness.client_push_wakes_streamers(id, SLOG_LOG).await);
    }

    #[tokio::test]
    async fn slog_recording_chunks_wake_streamers() {
        let harness = Harness::start();

        assert!(
            harness
                .client_push_wakes_streamers(Uuid::new_v4(), SLOG_RECORDING)
                .await
        );
    }

    #[test]
    fn manifest_without_logs_round_trips_byte_for_byte() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("recording.json");
        std::fs::write(&path, MASTER_MANIFEST).expect("write manifest");

        let manifest = JrecManifest::read_from_file(&path).expect("read manifest");
        manifest.save_to_file(&path).expect("save manifest");

        assert_eq!(std::fs::read_to_string(&path).expect("read back"), MASTER_MANIFEST);
    }
}
