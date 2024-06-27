use crate::recording::RecordingMessageSender;
use crate::subscriber;
use crate::target_addr::TargetAddr;
use crate::token::{ApplicationProtocol, SessionTtl};
use anyhow::Context as _;
use async_trait::async_trait;
use core::fmt;
use devolutions_gateway_task::{ShutdownSignal, Task};
use std::cmp;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tap::prelude::*;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot, Notify};
use uuid::Uuid;

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "connection_mode")]
#[serde(rename_all = "lowercase")]
pub enum ConnectionModeDetails {
    Rdv,
    Fwd { destination_host: TargetAddr },
}

#[derive(Debug, Serialize, Clone)]
pub struct SessionInfo {
    pub association_id: Uuid,
    pub application_protocol: ApplicationProtocol,
    pub recording_policy: bool,
    pub filtering_policy: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub start_timestamp: OffsetDateTime,
    pub time_to_live: SessionTtl,
    #[serde(flatten)]
    pub mode_details: ConnectionModeDetails,
}

impl SessionInfo {
    pub fn new(association_id: Uuid, ap: ApplicationProtocol, mode_details: ConnectionModeDetails) -> Self {
        Self {
            association_id,
            application_protocol: ap,
            recording_policy: false,
            filtering_policy: false,
            start_timestamp: OffsetDateTime::now_utc(),
            time_to_live: SessionTtl::Unlimited,
            mode_details,
        }
    }

    pub fn with_recording_policy(mut self, value: bool) -> Self {
        self.recording_policy = value;
        self
    }

    pub fn with_filtering_policy(mut self, value: bool) -> Self {
        self.filtering_policy = value;
        self
    }

    pub fn with_ttl(mut self, value: SessionTtl) -> Self {
        self.time_to_live = value;
        self
    }

    pub fn id(&self) -> Uuid {
        self.association_id
    }
}

#[instrument]
pub async fn add_session_in_progress(
    sessions: &SessionMessageSender,
    subscriber_tx: &subscriber::SubscriberSender,
    info: SessionInfo,
    notify_kill: Arc<Notify>,
) -> anyhow::Result<()> {
    let association_id = info.association_id;
    let start_timestamp = info.start_timestamp;

    sessions
        .new_session(info, notify_kill)
        .await
        .context("couldn't register new session")?;

    let message = subscriber::Message::session_started(subscriber::SubscriberSessionInfo {
        association_id,
        start_timestamp,
    });

    if let Err(error) = subscriber_tx.try_send(message) {
        warn!(%error, "Failed to send subscriber message");
    }

    Ok(())
}

#[instrument]
pub async fn remove_session_in_progress(
    sessions: &SessionMessageSender,
    subscriber_tx: &subscriber::SubscriberSender,
    id: Uuid,
) -> anyhow::Result<()> {
    let removed_session = sessions
        .remove_session(id)
        .await
        .context("couldn't remove running session")?;

    if let Some(session) = removed_session {
        let message = subscriber::Message::session_ended(subscriber::SubscriberSessionInfo {
            association_id: id,
            start_timestamp: session.start_timestamp,
        });

        if let Err(error) = subscriber_tx.try_send(message) {
            warn!(%error, "Failed to send subscriber message");
        }
    }

    Ok(())
}

pub type RunningSessions = HashMap<Uuid, SessionInfo>;

#[must_use]
pub enum KillResult {
    Success,
    NotFound,
}

enum SessionManagerMessage {
    New {
        info: SessionInfo,
        notify_kill: Arc<Notify>,
    },
    GetInfo {
        id: Uuid,
        channel: oneshot::Sender<Option<SessionInfo>>,
    },
    Remove {
        id: Uuid,
        channel: oneshot::Sender<Option<SessionInfo>>,
    },
    Kill {
        id: Uuid,
        channel: oneshot::Sender<KillResult>,
    },
    GetRunning {
        channel: oneshot::Sender<RunningSessions>,
    },
    GetCount {
        channel: oneshot::Sender<usize>,
    },
}

impl fmt::Debug for SessionManagerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionManagerMessage::New { info, notify_kill: _ } => {
                f.debug_struct("New").field("info", info).finish_non_exhaustive()
            }
            SessionManagerMessage::GetInfo { id, channel: _ } => {
                f.debug_struct("GetInfo").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::Remove { id, channel: _ } => {
                f.debug_struct("Remove").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::Kill { id, channel: _ } => {
                f.debug_struct("Kill").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::GetRunning { channel: _ } => f.debug_struct("GetRunning").finish_non_exhaustive(),
            SessionManagerMessage::GetCount { channel: _ } => f.debug_struct("GetCount").finish_non_exhaustive(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionMessageSender(mpsc::Sender<SessionManagerMessage>);

impl SessionMessageSender {
    pub async fn new_session(&self, info: SessionInfo, notify_kill: Arc<Notify>) -> anyhow::Result<()> {
        self.0
            .send(SessionManagerMessage::New { info, notify_kill })
            .await
            .ok()
            .context("couldn't send New message")
    }

    pub async fn get_session_info(&self, id: Uuid) -> anyhow::Result<Option<SessionInfo>> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::GetInfo { id, channel: tx })
            .await
            .ok()
            .context("couldn't send Remove message")?;
        rx.await.context("couldn't receive info for session")
    }

    pub async fn remove_session(&self, id: Uuid) -> anyhow::Result<Option<SessionInfo>> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::Remove { id, channel: tx })
            .await
            .ok()
            .context("couldn't send Remove message")?;
        rx.await.context("couldn't receive info for removed session")
    }

    pub async fn kill_session(&self, id: Uuid) -> anyhow::Result<KillResult> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::Kill { id, channel: tx })
            .await
            .ok()
            .context("couldn't send Kill message")?;
        rx.await.context("couldn't receive kill result")
    }

    pub async fn get_running_sessions(&self) -> anyhow::Result<RunningSessions> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::GetRunning { channel: tx })
            .await
            .ok()
            .context("couldn't send GetRunning message")?;
        rx.await.context("couldn't receive running session list")
    }

    pub async fn get_running_session_count(&self) -> anyhow::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::GetCount { channel: tx })
            .await
            .ok()
            .context("couldn't send GetRunning message")?;
        rx.await.context("couldn't receive running session count")
    }
}

pub struct SessionMessageReceiver(mpsc::Receiver<SessionManagerMessage>);

pub fn session_manager_channel() -> (SessionMessageSender, SessionMessageReceiver) {
    mpsc::channel(64).pipe(|(tx, rx)| (SessionMessageSender(tx), SessionMessageReceiver(rx)))
}

struct WithTtlInfo {
    deadline: tokio::time::Instant,
    session_id: Uuid,
}

impl PartialEq for WithTtlInfo {
    fn eq(&self, other: &Self) -> bool {
        self.deadline.eq(&other.deadline) && self.session_id.eq(&other.session_id)
    }
}

impl Eq for WithTtlInfo {}

impl PartialOrd for WithTtlInfo {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WithTtlInfo {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.deadline.cmp(&other.deadline) {
            cmp::Ordering::Less => cmp::Ordering::Greater,
            cmp::Ordering::Equal => self.session_id.cmp(&other.session_id),
            cmp::Ordering::Greater => cmp::Ordering::Less,
        }
    }
}

pub struct SessionManagerTask {
    tx: SessionMessageSender,
    rx: SessionMessageReceiver,
    all_running: RunningSessions,
    all_notify_kill: HashMap<Uuid, Arc<Notify>>,
    recording_manager_handle: RecordingMessageSender,
}

impl SessionManagerTask {
    pub fn init(recording_manager_handle: RecordingMessageSender) -> Self {
        let (tx, rx) = session_manager_channel();

        Self::new(tx, rx, recording_manager_handle)
    }

    pub fn new(
        tx: SessionMessageSender,
        rx: SessionMessageReceiver,
        recording_manager_handle: RecordingMessageSender,
    ) -> Self {
        Self {
            tx,
            rx,
            all_running: HashMap::new(),
            all_notify_kill: HashMap::new(),
            recording_manager_handle,
        }
    }

    pub fn handle(&self) -> SessionMessageSender {
        self.tx.clone()
    }

    fn handle_new(&mut self, info: SessionInfo, notify_kill: Arc<Notify>) {
        let id = info.association_id;
        self.all_running.insert(id, info);
        self.all_notify_kill.insert(id, notify_kill);
    }

    fn handle_get_info(&mut self, id: Uuid) -> Option<SessionInfo> {
        self.all_running.get(&id).cloned()
    }

    fn handle_remove(&mut self, id: Uuid) -> Option<SessionInfo> {
        let removed_session = self.all_running.remove(&id);
        let _ = self.all_notify_kill.remove(&id);
        removed_session
    }

    fn handle_kill(&self, id: Uuid) -> KillResult {
        match self.all_notify_kill.get(&id) {
            Some(notify_kill) => {
                notify_kill.notify_waiters();
                KillResult::Success
            }
            None => KillResult::NotFound,
        }
    }
}

#[async_trait]
impl Task for SessionManagerTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "session manager";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        session_manager_task(self, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn session_manager_task(
    mut manager: SessionManagerTask,
    mut shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    debug!("Task started");

    let mut with_ttl = BinaryHeap::<WithTtlInfo>::new();
    let auto_kill_sleep = tokio::time::sleep_until(tokio::time::Instant::now());
    tokio::pin!(auto_kill_sleep);
    (&mut auto_kill_sleep).await; // Consume initial sleep.

    loop {
        tokio::select! {
            () = &mut auto_kill_sleep, if !with_ttl.is_empty() => {
                // Will never panic since we check for non-emptiness before entering this block.
                let to_kill = with_ttl.pop().unwrap();

                match manager.handle_kill(to_kill.session_id) {
                    KillResult::Success => {
                        info!(session.id = %to_kill.session_id, "Session killed because it reached its max duration");
                    }
                    KillResult::NotFound => {
                        debug!(session.id = %to_kill.session_id, "Session already ended");
                    }
                }

                // Re-arm the Sleep instance with the next deadline if required.
                if let Some(next) = with_ttl.peek() {
                    auto_kill_sleep.as_mut().reset(next.deadline)
                }
            }
            msg = manager.rx.0.recv() => {
                let Some(msg) = msg else {
                    warn!("All senders are dead");
                    break;
                };

                debug!(?msg, "Received message");

                match msg {
                    SessionManagerMessage::New { info, notify_kill } => {
                        if let SessionTtl::Limited { minutes } = info.time_to_live {
                            let now = tokio::time::Instant::now();
                            let duration = Duration::from_secs(minutes.get() * 60);
                            let deadline = now + duration;

                            with_ttl.push(WithTtlInfo {
                                deadline,
                                session_id: info.id(),
                            });

                            // Reset the Sleep instance if the new deadline is sooner or it is already elapsed.
                            if auto_kill_sleep.is_elapsed() || deadline < auto_kill_sleep.deadline() {
                                auto_kill_sleep.as_mut().reset(deadline);
                            }

                            debug!(session.id = %info.id(), minutes = minutes.get(), "Limited TTL session registered");
                        }

                        if info.recording_policy {
                            let task = EnsureRecordingPolicyTask {
                                session_id: info.id(),
                                session_manager_handle: manager.tx.clone(),
                                recording_manager_handle: manager.recording_manager_handle.clone(),
                            };

                            devolutions_gateway_task::spawn_task(task, shutdown_signal.clone()).detach();

                            debug!(session.id = %info.id(), "Session with recording policy registered");
                        }

                        manager.handle_new(info, notify_kill);
                    }
                    SessionManagerMessage::GetInfo { id, channel } => {
                        let session_info = manager.handle_get_info(id);
                        let _ = channel.send(session_info);
                    }
                    SessionManagerMessage::Remove { id, channel } => {
                        let removed_session = manager.handle_remove(id);
                        let _ = channel.send(removed_session);
                    }
                    SessionManagerMessage::Kill { id, channel } => {
                        let kill_result = manager.handle_kill(id);
                        let _ = channel.send(kill_result);
                    }
                    SessionManagerMessage::GetRunning { channel } => {
                        let _ = channel.send(manager.all_running.clone());
                    }
                    SessionManagerMessage::GetCount { channel } => {
                        let _ = channel.send(manager.all_running.len());
                    }
                }
            }
            _ = shutdown_signal.wait() => {
                break;
            }
        }
    }

    debug!("Task is stopping; kill all running sessions");

    for notify_kill in manager.all_notify_kill.values() {
        notify_kill.notify_waiters();
    }

    debug!("Task is stopping; wait for leftover messages");

    while let Some(msg) = manager.rx.0.recv().await {
        debug!(?msg, "Received message");
        match msg {
            SessionManagerMessage::Remove { id, channel } => {
                let removed_session = manager.handle_remove(id);
                let _ = channel.send(removed_session);
            }
            SessionManagerMessage::Kill { channel, .. } => {
                let _ = channel.send(KillResult::Success);
            }
            _ => {}
        }
    }

    debug!("Task terminated");

    Ok(())
}

struct EnsureRecordingPolicyTask {
    session_id: Uuid,
    session_manager_handle: SessionMessageSender,
    recording_manager_handle: RecordingMessageSender,
}

#[async_trait]
impl Task for EnsureRecordingPolicyTask {
    type Output = ();

    const NAME: &'static str = "ensure recording policy";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Self::Output {
        use futures::future::Either;
        use std::pin::pin;

        let sleep = tokio::time::sleep(Duration::from_secs(10));
        let shutdown_signal = shutdown_signal.wait();

        match futures::future::select(pin!(sleep), pin!(shutdown_signal)).await {
            Either::Left(_) => {}
            Either::Right(_) => return,
        }

        let is_not_recording = self
            .recording_manager_handle
            .get_state(self.session_id)
            .await
            .ok()
            .flatten()
            .is_none();

        if is_not_recording {
            match self.session_manager_handle.kill_session(self.session_id).await {
                Ok(KillResult::Success) => {
                    warn!(
                        session.id = %self.session_id,
                        reason = "recording policy violated",
                        "Session killed",
                    );
                }
                Ok(KillResult::NotFound) => {
                    trace!(session.id = %self.session_id, "Session already ended");
                }
                Err(error) => {
                    debug!(session.id = %self.session_id, error = format!("{error:#}"), "Couldn’t kill the session");
                }
            }
        }
    }
}
