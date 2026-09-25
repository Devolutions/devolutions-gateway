use core::fmt;
use std::cmp;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_task::{ShutdownSignal, Task};
use futures::future::Either;
use parking_lot::Mutex;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::{fs, io};
use typed_builder::TypedBuilder;
use uuid::Uuid;
use video_streamer::SignalWriter;

use crate::job_queue::JobQueueHandle;
use crate::session::SessionMessageSender;
use crate::token::{JrecTokenClaims, RecordingFileCategory, RecordingFileType};

const DISCONNECTED_TTL_EXTRA_LEEWAY: Duration = Duration::from_secs(10);
const BUFFER_WRITER_SIZE: usize = 64 * 1024;
const LOG_PUSH_SIZE_LIMIT: u64 = 64 * 1024 * 1024;

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
    /// Released players and streamers treat every entry of `files` as media, so a log recorded next to media goes here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    logs: Vec<JrecFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestList {
    Files,
    Logs,
}

#[derive(Debug, Clone, Copy)]
struct ManifestEntry {
    list: ManifestList,
    idx: usize,
}

impl JrecFile {
    fn file_type(&self) -> Option<RecordingFileType> {
        Utf8Path::new(&self.file_name)
            .extension()
            .and_then(RecordingFileType::from_extension)
    }
}

impl JrecManifest {
    fn has_media(&self) -> bool {
        self.files.iter().any(|file| {
            file.file_type()
                .is_some_and(|file_type| file_type.category() == RecordingFileCategory::Media)
        })
    }

    fn list_for(&self, file_type: RecordingFileType) -> ManifestList {
        match file_type.category() {
            RecordingFileCategory::Media => ManifestList::Files,
            RecordingFileCategory::Log if self.has_media() => ManifestList::Logs,
            RecordingFileCategory::Log => ManifestList::Files,
        }
    }

    fn list_mut(&mut self, list: ManifestList) -> &mut Vec<JrecFile> {
        match list {
            ManifestList::Files => &mut self.files,
            ManifestList::Logs => &mut self.logs,
        }
    }

    fn entry_mut(&mut self, entry: ManifestEntry) -> Option<&mut JrecFile> {
        self.list_mut(entry.list).get_mut(entry.idx)
    }

    fn push_file(&mut self, file_type: RecordingFileType, start_time: i64) -> (ManifestEntry, String) {
        let list = self.list_for(file_type);
        let file_name = format!(
            "recording-{}.{}",
            self.files.len() + self.logs.len(),
            file_type.extension()
        );

        let entries = self.list_mut(list);
        entries.push(JrecFile {
            file_name: file_name.clone(),
            start_time,
            duration: 0,
        });

        let entry = ManifestEntry {
            list,
            idx: entries.len() - 1,
        };

        (entry, file_name)
    }

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
    /// The push reached the size limit of its file type and was closed.
    SizeLimitReached,
}

#[derive(TypedBuilder)]
pub struct ClientPush<S> {
    recordings: RecordingMessageSender,
    claims: JrecTokenClaims,
    client_stream: S,
    file_type: RecordingFileType,
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
            file_type,
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

        let recording_file = match recordings.connect(session_id, file_type, disconnected_ttl).await {
            Ok(recording_file) => recording_file,
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
                let size_limit = push_size_limit(file_type);
                let mut limited_stream = (&mut client_stream).take(size_limit);
                let copy_fut = io::copy(&mut limited_stream, &mut file);
                let is_media = file_type.category() == RecordingFileCategory::Media;
                let signal_loop = tokio::spawn({
                    let recordings = recordings.clone();
                    async move {
                        loop {
                            tokio::select! {
                                _ = flush_signal.notified() => {
                                    // Shadow streamers only follow the media file.
                                    if is_media {
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
                            Ok(written) if written >= size_limit => {
                                warn!(%session_id, %file_type, size_limit, "Recording push reached its size limit; closing push stream");
                                Ok(PushOutcome::SizeLimitReached)
                            }
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
                        limited_stream.get_mut().shutdown().await.context("shutdown").map(|_| PushOutcome::Done)
                    },
                };

                signal_loop.abort();

                res
            }
            Err(e) => Err(anyhow::Error::new(e).context(format!("failed to open file at {recording_file}"))),
        };

        info!(?res, "Recording finished");

        recordings
            .disconnect(session_id, file_type)
            .await
            .context("disconnect")?;

        res
    }
}

fn push_size_limit(file_type: RecordingFileType) -> u64 {
    match file_type.category() {
        RecordingFileCategory::Media => u64::MAX,
        RecordingFileCategory::Log => LOG_PUSH_SIZE_LIMIT,
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

#[derive(Debug, Clone)]
struct OnGoingRecording {
    state: OnGoingRecordingState,
    manifest: JrecManifest,
    manifest_path: Utf8PathBuf,
    session_must_be_recorded: bool,
    disconnected_ttl: Duration,
    /// Manifest entry of the file written by the connected media push.
    media_file: Option<ManifestEntry>,
    /// Manifest entry of the file written by the connected log push.
    log_file: Option<ManifestEntry>,
    /// Once a media push connected, only media pushes drive `state`, the TTL and the recording policy.
    has_media: bool,
}

impl OnGoingRecording {
    fn connected_file_mut(&mut self, category: RecordingFileCategory) -> &mut Option<ManifestEntry> {
        match category {
            RecordingFileCategory::Media => &mut self.media_file,
            RecordingFileCategory::Log => &mut self.log_file,
        }
    }

    fn is_driven_by(&self, category: RecordingFileCategory) -> bool {
        category == RecordingFileCategory::Media || !self.has_media
    }

    fn has_connected_push(&self) -> bool {
        self.media_file.is_some() || self.log_file.is_some()
    }
}

enum RecordingManagerMessage {
    Connect {
        id: Uuid,
        file_type: RecordingFileType,
        disconnected_ttl: Duration,
        channel: oneshot::Sender<Utf8PathBuf>,
    },
    Disconnect {
        id: Uuid,
        file_type: RecordingFileType,
    },
    GetState {
        id: Uuid,
        channel: oneshot::Sender<Option<OnGoingRecordingState>>,
    },
    ListFiles {
        id: Uuid,
        channel: oneshot::Sender<Vec<Utf8PathBuf>>,
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
                file_type,
                disconnected_ttl,
                channel: _,
            } => f
                .debug_struct("Connect")
                .field("id", id)
                .field("file_type", file_type)
                .field("disconnected_ttl", disconnected_ttl)
                .finish_non_exhaustive(),
            RecordingManagerMessage::Disconnect { id, file_type } => f
                .debug_struct("Disconnect")
                .field("id", id)
                .field("file_type", file_type)
                .finish(),
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
        file_type: RecordingFileType,
        disconnected_ttl: Duration,
    ) -> anyhow::Result<Utf8PathBuf> {
        let (tx, rx) = oneshot::channel();
        self.channel
            .send(RecordingManagerMessage::Connect {
                id,
                file_type,
                disconnected_ttl,
                channel: tx,
            })
            .await
            .ok()
            .context("couldn't send New message")?;
        rx.await
            .context("couldn't receive recording file path for this recording")
    }

    async fn disconnect(&self, id: Uuid, file_type: RecordingFileType) -> anyhow::Result<()> {
        self.channel
            .send(RecordingManagerMessage::Disconnect { id, file_type })
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

    pub(crate) async fn list_files(&self, recording_id: Uuid) -> anyhow::Result<Vec<Utf8PathBuf>> {
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
        file_type: RecordingFileType,
        disconnected_ttl: Duration,
    ) -> anyhow::Result<Utf8PathBuf> {
        const LENGTH_WARNING_THRESHOLD: usize = 1000;

        let category = file_type.category();

        if let Some(ongoing) = self.ongoing_recordings.get_mut(&id)
            && ongoing.connected_file_mut(category).is_some()
        {
            anyhow::bail!("concurrent {category} recording for the same session is not supported");
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

        let (manifest_entry, file_name) = manifest.push_file(file_type, start_time);
        let recording_file = recording_path.join(&file_name);

        manifest
            .save_to_file(&manifest_path)
            .context("write manifest to disk")?;

        debug!(%id, %file_type, list = ?manifest_entry.list, %file_name, "Recording file added to manifest");

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

        let ongoing = self.ongoing_recordings.entry(id).or_insert_with(|| OnGoingRecording {
            state: OnGoingRecordingState::Connected,
            manifest: manifest.clone(),
            manifest_path,
            session_must_be_recorded,
            disconnected_ttl,
            media_file: None,
            log_file: None,
            has_media: false,
        });

        ongoing.manifest = manifest;
        *ongoing.connected_file_mut(category) = Some(manifest_entry);

        if category == RecordingFileCategory::Media {
            ongoing.has_media = true;
        }

        if ongoing.is_driven_by(category) {
            ongoing.state = OnGoingRecordingState::Connected;
            ongoing.session_must_be_recorded = session_must_be_recorded;
            ongoing.disconnected_ttl = disconnected_ttl;
        }

        let ongoing_recording_count = self.ongoing_recordings.len();

        // Sanity check
        if active_recording_count > LENGTH_WARNING_THRESHOLD || ongoing_recording_count > LENGTH_WARNING_THRESHOLD {
            warn!(
                active_recording_count,
                ongoing_recording_count,
                "length threshold exceeded (either the load is very high or the list is growing uncontrollably)"
            );
        }

        Ok(recording_file)
    }

    async fn handle_disconnect(&mut self, id: Uuid, file_type: RecordingFileType) -> anyhow::Result<()> {
        let Some(ongoing) = self.ongoing_recordings.get_mut(&id) else {
            return Err(anyhow::anyhow!("unknown recording for ID {id}"));
        };

        let category = file_type.category();

        let Some(manifest_entry) = ongoing.connected_file_mut(category).take() else {
            anyhow::bail!("a {category} recording not connected can’t be disconnected (there is probably a bug)");
        };

        let end_time = time::OffsetDateTime::now_utc().unix_timestamp();

        if ongoing.is_driven_by(category) {
            ongoing.state = OnGoingRecordingState::LastSeen { timestamp: end_time };
        }

        let current_file = ongoing
            .manifest
            .entry_mut(manifest_entry)
            .context("no recording file (this is a bug)")?;
        current_file.duration = end_time - current_file.start_time;

        let recording_file_path = ongoing
            .manifest_path
            .parent()
            .expect("a parent")
            .join(&current_file.file_name);

        ongoing.manifest.duration = end_time - ongoing.manifest.start_time;

        debug!(path = %ongoing.manifest_path, "Write updated manifest to disk");

        ongoing
            .manifest
            .save_to_file(&ongoing.manifest_path)
            .with_context(|| format!("write manifest at {}", ongoing.manifest_path))?;

        // Notify all the streamers that recording has ended.
        if category == RecordingFileCategory::Media
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

    fn handle_remove(&mut self, id: Uuid) {
        if let Some(ongoing) = self.ongoing_recordings.get_mut(&id) {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let disconnected_ttl_secs = i64::try_from(ongoing.disconnected_ttl.as_secs()).expect("TTL can’t be so big");

            match ongoing.state {
                // NOTE: Comparing with disconnected_ttl_secs - 1 just in case the sleep returns faster than expected.
                // (I don’t know if this can actually happen in practice, but it’s better to be safe than sorry.)
                OnGoingRecordingState::LastSeen { timestamp } if now >= timestamp + disconnected_ttl_secs - 1 => {
                    // Check the recording policy of the associated session and kill it if necessary.
                    if core::mem::take(&mut ongoing.session_must_be_recorded) {
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

                    // The log push can outlive the media stream, and its manifest entry is completed on disconnect.
                    if ongoing.has_connected_push() {
                        debug!(%id, "Media stream expired while a log push is still connected");
                        return;
                    }

                    debug!(%id, "Mark recording as terminated");
                    self.rx.active_recordings.remove(id);
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
                    RecordingManagerMessage::Connect { id, file_type, disconnected_ttl, channel  } => {
                        match manager.handle_connect(id, file_type, disconnected_ttl).await {
                            Ok(recording_file) => {
                                let _ = channel.send(recording_file);
                            }
                            Err(e) => error!(error = format!("{e:#}"), "handle_connect"),
                        }
                    },
                    RecordingManagerMessage::Disconnect { id, file_type } => {
                        if let Err(e) = manager.handle_disconnect(id, file_type).await {
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
                            Some(recording) => {
                                let recordings_folder = recording.manifest_path.parent().expect("a parent");

                                let files = recording
                                    .manifest
                                    .files
                                    .iter()
                                    .map(|file| recordings_folder.join(&file.file_name))
                                    .collect();

                                let _ = channel.send(files);
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
        if let RecordingManagerMessage::Disconnect { id, file_type } = msg {
            if let Err(e) = manager.handle_disconnect(id, file_type).await {
                error!(error = format!("{e:#}"), "handle_disconnect");
            }

            if manager
                .ongoing_recordings
                .get(&id)
                .is_some_and(|ongoing| !ongoing.has_connected_push())
            {
                manager.ongoing_recordings.remove(&id);
            }
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

    use super::*;
    use crate::session::session_manager_channel;

    struct Harness {
        manager: RecordingManagerTask,
        kills: mpsc::UnboundedReceiver<Uuid>,
        _recordings_dir: tempfile::TempDir,
    }

    fn harness() -> Harness {
        let recordings_dir = tempfile::tempdir().expect("temp dir");
        let recordings_path = Utf8PathBuf::from_path_buf(recordings_dir.path().to_path_buf()).expect("UTF-8 path");
        let (_, rx) = recording_message_channel();
        let (session_manager_handle, session_manager_rx) = session_manager_channel();
        let kills = session_manager_rx.spawn_mock();
        let (job_queue_handle, _) = JobQueueHandle::new();

        Harness {
            manager: RecordingManagerTask::new(rx, recordings_path, session_manager_handle, job_queue_handle),
            kills,
            _recordings_dir: recordings_dir,
        }
    }

    impl Harness {
        async fn connect(&mut self, id: Uuid, file_type: RecordingFileType) -> anyhow::Result<Utf8PathBuf> {
            self.manager.handle_connect(id, file_type, Duration::ZERO).await
        }

        async fn disconnect(&mut self, id: Uuid, file_type: RecordingFileType) {
            self.manager
                .handle_disconnect(id, file_type)
                .await
                .expect("disconnect connected push");
        }

        fn ongoing(&mut self, id: Uuid) -> &mut OnGoingRecording {
            self.manager.ongoing_recordings.get_mut(&id).expect("ongoing recording")
        }

        fn is_connected(&mut self, id: Uuid) -> bool {
            matches!(self.ongoing(id).state, OnGoingRecordingState::Connected)
        }

        fn is_terminated(&self, id: Uuid) -> bool {
            !self.manager.ongoing_recordings.contains_key(&id) && !self.manager.rx.active_recordings.contains(id)
        }

        fn manifest_file_names(&mut self, id: Uuid) -> (Vec<String>, Vec<String>) {
            let names = |files: &[JrecFile]| files.iter().map(|file| file.file_name.clone()).collect();
            let manifest = &self.ongoing(id).manifest;
            (names(&manifest.files), names(&manifest.logs))
        }

        fn manifest_json_on_disk(&self, id: Uuid) -> serde_json::Value {
            let path = self.manager.recordings_path.join(id.to_string()).join("recording.json");
            serde_json::from_slice(&std::fs::read(path).expect("manifest on disk")).expect("manifest JSON")
        }

        async fn expect_kill(&mut self, id: Uuid) {
            let killed = tokio::time::timeout(Duration::from_secs(5), self.kills.recv())
                .await
                .expect("kill request");
            assert_eq!(killed, Some(id));
        }

        fn expect_no_kill(&mut self) {
            assert!(self.kills.try_recv().is_err(), "unexpected kill request");
        }
    }

    #[tokio::test]
    async fn media_and_log_pushes_are_accepted_concurrently() {
        let mut h = harness();
        let id = Uuid::new_v4();

        let media_file = h.connect(id, RecordingFileType::WebM).await.expect("media push");
        let log_file = h
            .connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log push");

        assert_eq!(media_file.file_name(), Some("recording-0.webm"));
        assert_eq!(log_file.file_name(), Some("recording-1.slog"));
        assert!(h.is_connected(id));

        h.disconnect(id, RecordingFileType::WebM).await;
        h.disconnect(id, RecordingFileType::SessionRecordingLog).await;

        let manifest = h.manifest_json_on_disk(id);
        assert_eq!(manifest["files"][0]["fileName"], "recording-0.webm");
        assert_eq!(manifest["files"].as_array().map(Vec::len), Some(1));
        assert_eq!(manifest["logs"][0]["fileName"], "recording-1.slog");
        assert_eq!(manifest["logs"].as_array().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn second_media_push_is_rejected() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::WebM).await.expect("first media push");
        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log push");

        for file_type in [
            RecordingFileType::WebM,
            RecordingFileType::TRP,
            RecordingFileType::Asciicast,
        ] {
            assert!(
                h.connect(id, file_type).await.is_err(),
                "{file_type} push must be rejected"
            );
        }

        assert_eq!(
            h.manifest_file_names(id),
            (vec!["recording-0.webm".to_owned()], vec!["recording-1.slog".to_owned()])
        );
        assert!(h.is_connected(id));
    }

    #[tokio::test]
    async fn second_log_push_is_rejected() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::TRP).await.expect("media push");
        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("first log push");

        assert!(h.connect(id, RecordingFileType::SessionRecordingLog).await.is_err());

        assert_eq!(
            h.manifest_file_names(id),
            (vec!["recording-0.trp".to_owned()], vec!["recording-1.slog".to_owned()])
        );
        assert!(h.is_connected(id));
    }

    #[tokio::test]
    async fn log_disconnect_does_not_terminate_or_kill() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::WebM).await.expect("media push");
        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log push");
        h.ongoing(id).session_must_be_recorded = true;

        h.disconnect(id, RecordingFileType::SessionRecordingLog).await;
        h.manager.handle_remove(id);

        assert!(h.is_connected(id));
        assert!(h.manager.rx.active_recordings.contains(id));
        assert!(h.ongoing(id).session_must_be_recorded);
        h.expect_no_kill();

        h.disconnect(id, RecordingFileType::WebM).await;
        h.manager.handle_remove(id);

        assert!(h.is_terminated(id));
        h.expect_kill(id).await;
    }

    #[tokio::test]
    async fn log_connect_does_not_revive_disconnected_media() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::WebM).await.expect("media push");
        h.disconnect(id, RecordingFileType::WebM).await;
        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log push");

        assert!(!h.is_connected(id));
    }

    #[tokio::test]
    async fn media_expiry_with_log_connected_kills_once_and_waits_for_log() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::WebM).await.expect("media push");
        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log push");
        h.ongoing(id).session_must_be_recorded = true;

        h.disconnect(id, RecordingFileType::WebM).await;
        h.manager.handle_remove(id);

        h.expect_kill(id).await;
        assert!(!h.is_connected(id));
        assert!(h.manager.rx.active_recordings.contains(id));

        h.disconnect(id, RecordingFileType::SessionRecordingLog).await;
        h.manager.handle_remove(id);

        assert!(h.is_terminated(id));
        h.expect_no_kill();
    }

    #[tokio::test]
    async fn media_only_session_is_unchanged() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::WebM).await.expect("media push");
        assert!(h.connect(id, RecordingFileType::WebM).await.is_err());

        h.disconnect(id, RecordingFileType::WebM).await;
        assert!(!h.is_connected(id));

        h.connect(id, RecordingFileType::WebM).await.expect("media reconnect");
        assert!(h.is_connected(id));
        assert_eq!(
            h.manifest_file_names(id),
            (
                vec!["recording-0.webm".to_owned(), "recording-1.webm".to_owned()],
                vec![]
            )
        );

        h.disconnect(id, RecordingFileType::WebM).await;
        h.manager.handle_remove(id);

        assert!(h.is_terminated(id));
        assert!(h.manifest_json_on_disk(id).get("logs").is_none());
    }

    #[tokio::test]
    async fn log_only_session_is_unchanged() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log push");
        assert!(h.is_connected(id));
        assert!(h.manager.rx.active_recordings.contains(id));
        h.ongoing(id).session_must_be_recorded = true;

        h.disconnect(id, RecordingFileType::SessionRecordingLog).await;
        assert!(!h.is_connected(id));

        h.manager.handle_remove(id);

        assert!(h.is_terminated(id));
        h.expect_kill(id).await;

        let manifest = h.manifest_json_on_disk(id);
        assert_eq!(manifest["files"][0]["fileName"], "recording-0.slog");
        assert!(manifest.get("logs").is_none());
    }

    #[tokio::test]
    async fn file_names_are_unique_across_files_and_logs() {
        let mut h = harness();
        let id = Uuid::new_v4();

        h.connect(id, RecordingFileType::WebM).await.expect("media push");
        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log push");
        h.disconnect(id, RecordingFileType::WebM).await;
        h.connect(id, RecordingFileType::WebM).await.expect("media reconnect");
        h.disconnect(id, RecordingFileType::SessionRecordingLog).await;
        h.connect(id, RecordingFileType::SessionRecordingLog)
            .await
            .expect("log reconnect");
        h.disconnect(id, RecordingFileType::WebM).await;
        h.disconnect(id, RecordingFileType::SessionRecordingLog).await;

        assert_eq!(
            h.manifest_file_names(id),
            (
                vec!["recording-0.webm".to_owned(), "recording-2.webm".to_owned()],
                vec!["recording-1.slog".to_owned(), "recording-3.slog".to_owned()],
            )
        );
    }

    #[test]
    fn manifest_without_logs_is_read_and_written_unchanged() {
        let json = serde_json::json!({
            "sessionId": "11111111-1111-1111-1111-111111111111",
            "startTime": 1,
            "duration": 5,
            "files": [
                { "fileName": "recording-0.webm", "startTime": 1, "duration": 5 }
            ]
        });

        let manifest: JrecManifest = serde_json::from_value(json.clone()).expect("manifest without logs");
        assert!(manifest.logs.is_empty());
        assert_eq!(serde_json::to_value(&manifest).expect("serialize manifest"), json);
    }

    #[tokio::test]
    async fn log_push_size_limit_closes_only_the_log_push() {
        let recordings_dir = tempfile::tempdir().expect("temp dir");
        let recordings_path = Utf8PathBuf::from_path_buf(recordings_dir.path().to_path_buf()).expect("UTF-8 path");
        let (recordings, rx) = recording_message_channel();
        let (session_manager_handle, session_manager_rx) = session_manager_channel();
        let _kills = session_manager_rx.spawn_mock();
        let (job_queue_handle, _job_queue_rx) = JobQueueHandle::new();
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let manager = RecordingManagerTask::new(rx, recordings_path.clone(), session_manager_handle, job_queue_handle);
        tokio::spawn(recording_manager_task(manager, shutdown_signal.clone()));

        let id = Uuid::new_v4();
        let push = |client_stream, file_type| {
            let claims: JrecTokenClaims = serde_json::from_value(serde_json::json!({
                "jet_aid": id,
                "jet_rop": "push",
                "exp": 0,
                "jti": Uuid::new_v4(),
            }))
            .expect("push claims");

            tokio::spawn(
                ClientPush::builder()
                    .recordings(recordings.clone())
                    .claims(claims)
                    .client_stream(client_stream)
                    .file_type(file_type)
                    .session_id(id)
                    .shutdown_signal(shutdown_signal.clone())
                    .build()
                    .run(),
            )
        };

        let (mut media_client, media_server) = io::duplex(BUFFER_WRITER_SIZE);
        let media_push = push(media_server, RecordingFileType::WebM);
        media_client.write_all(b"media").await.expect("write media");

        wait_until_connected(&recordings, id).await;

        let (mut log_client, log_server) = io::duplex(BUFFER_WRITER_SIZE);
        let log_push = push(log_server, RecordingFileType::SessionRecordingLog);
        tokio::spawn(async move {
            let chunk = vec![b'x'; BUFFER_WRITER_SIZE];
            while log_client.write_all(&chunk).await.is_ok() {}
        });

        let log_outcome = log_push.await.expect("join log push").expect("log push");
        assert!(matches!(log_outcome, PushOutcome::SizeLimitReached));

        let log_file = recordings_path.join(id.to_string()).join("recording-1.slog");
        let log_size = std::fs::metadata(&log_file).expect("log file").len();
        assert_eq!(log_size, LOG_PUSH_SIZE_LIMIT);

        assert!(matches!(
            recordings.get_state(id).await.expect("state"),
            Some(OnGoingRecordingState::Connected)
        ));
        assert!(!media_push.is_finished());

        drop(media_client);
        let media_outcome = media_push.await.expect("join media push").expect("media push");
        assert!(matches!(media_outcome, PushOutcome::Done));
    }

    async fn wait_until_connected(recordings: &RecordingMessageSender, id: Uuid) {
        for _ in 0..500 {
            if let Ok(Some(OnGoingRecordingState::Connected)) = recordings.get_state(id).await {
                return;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        panic!("recording {id} never connected");
    }

    #[test]
    fn only_log_pushes_have_a_size_limit() {
        assert_eq!(
            push_size_limit(RecordingFileType::SessionRecordingLog),
            LOG_PUSH_SIZE_LIMIT
        );

        for file_type in [
            RecordingFileType::WebM,
            RecordingFileType::TRP,
            RecordingFileType::Asciicast,
        ] {
            assert_eq!(push_size_limit(file_type), u64::MAX);
        }
    }
}
