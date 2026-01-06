use core::fmt;
use std::cmp;
use std::collections::{BinaryHeap, HashMap};
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use futures::future::Either;
use tap::prelude::*;
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc, oneshot};
use typed_builder::TypedBuilder;
use uuid::Uuid;

use crate::recording::RecordingMessageSender;
use crate::subscriber;
use crate::target_addr::TargetAddr;
use crate::token::{ApplicationProtocol, ReconnectionPolicy, RecordingPolicy, SessionTtl};

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "connection_mode")]
#[serde(rename_all = "lowercase")]
pub enum ConnectionModeDetails {
    Rdv,
    Fwd { destination_host: TargetAddr },
}

#[derive(Debug, Serialize, Clone, TypedBuilder)]
pub struct SessionInfo {
    #[serde(rename = "association_id")]
    pub id: Uuid,
    pub application_protocol: ApplicationProtocol,
    #[builder(setter(transform = |value: RecordingPolicy| value != RecordingPolicy::None))]
    pub recording_policy: bool,
    #[builder(default = false)] // Not enforced yet, so it’s okay to not set it at all for now.
    pub filtering_policy: bool,
    #[builder(setter(skip), default = OffsetDateTime::now_utc())]
    #[serde(with = "time::serde::rfc3339")]
    pub start_timestamp: OffsetDateTime,
    pub time_to_live: SessionTtl,
    #[serde(flatten)]
    pub details: ConnectionModeDetails,
}

#[instrument]
pub async fn add_session_in_progress(
    sessions: &SessionMessageSender,
    subscriber_tx: &subscriber::SubscriberSender,
    info: SessionInfo,
    notify_kill: Arc<Notify>,
    disconnect_interest: Option<DisconnectInterest>,
) -> anyhow::Result<()> {
    let association_id = info.id;
    let start_timestamp = info.start_timestamp;

    sessions
        .new_session(info, notify_kill, disconnect_interest)
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

#[derive(Debug, Clone, Copy)]
pub struct DisconnectInterest {
    pub window: Duration,
}

impl DisconnectInterest {
    pub fn from_reconnection_policy(policy: ReconnectionPolicy) -> Option<DisconnectInterest> {
        match policy {
            ReconnectionPolicy::Disallowed => None,
            ReconnectionPolicy::Allowed { window_in_seconds } => Some(DisconnectInterest {
                window: Duration::from_secs(u64::from(window_in_seconds.get())),
            }),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DisconnectedInfo {
    pub id: Uuid,
    pub was_killed: bool,
    pub date: OffsetDateTime,
    pub interest: DisconnectInterest,
    pub count: u8,
}

enum SessionManagerMessage {
    New {
        info: SessionInfo,
        notify_kill: Arc<Notify>,
        disconnect_interest: Option<DisconnectInterest>,
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
    GetDisconnectedInfo {
        id: Uuid,
        channel: oneshot::Sender<Option<DisconnectedInfo>>,
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
            SessionManagerMessage::New {
                info,
                notify_kill: _,
                disconnect_interest,
            } => f
                .debug_struct("New")
                .field("info", info)
                .field("disconnect_interest", disconnect_interest)
                .finish_non_exhaustive(),
            SessionManagerMessage::GetInfo { id, channel: _ } => {
                f.debug_struct("GetInfo").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::Remove { id, channel: _ } => {
                f.debug_struct("Remove").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::Kill { id, channel: _ } => {
                f.debug_struct("Kill").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::GetDisconnectedInfo { id, channel: _ } => f
                .debug_struct("GetDisconnectedInfo")
                .field("id", id)
                .finish_non_exhaustive(),
            SessionManagerMessage::GetRunning { channel: _ } => f.debug_struct("GetRunning").finish_non_exhaustive(),
            SessionManagerMessage::GetCount { channel: _ } => f.debug_struct("GetCount").finish_non_exhaustive(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionMessageSender(mpsc::Sender<SessionManagerMessage>);

impl SessionMessageSender {
    pub async fn new_session(
        &self,
        info: SessionInfo,
        notify_kill: Arc<Notify>,
        disconnect_interest: Option<DisconnectInterest>,
    ) -> anyhow::Result<()> {
        self.0
            .send(SessionManagerMessage::New {
                info,
                notify_kill,
                disconnect_interest,
            })
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
            .context("couldn't send GetInfo message")?;
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

    pub async fn get_disconnected_info(&self, id: Uuid) -> anyhow::Result<Option<DisconnectedInfo>> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::GetDisconnectedInfo { id, channel: tx })
            .await
            .ok()
            .context("couldn't send GetDisconnectedInfo message")?;
        rx.await.context("couldn't receive disconnected info for session")
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
    disconnect_interest: HashMap<Uuid, DisconnectInterest>,
    disconnected_info: HashMap<Uuid, DisconnectedInfo>,
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
            disconnect_interest: HashMap::new(),
            disconnected_info: HashMap::new(),
        }
    }

    pub fn handle(&self) -> SessionMessageSender {
        self.tx.clone()
    }

    fn handle_new(
        &mut self,
        info: SessionInfo,
        notify_kill: Arc<Notify>,
        disconnect_interest: Option<DisconnectInterest>,
    ) {
        let id = info.id;

        self.all_running.insert(id, info);
        self.all_notify_kill.insert(id, notify_kill);

        if let Some(interest) = disconnect_interest {
            self.disconnect_interest.insert(id, interest);
        }
    }

    fn handle_get_info(&mut self, id: Uuid) -> Option<SessionInfo> {
        self.all_running.get(&id).cloned()
    }

    fn handle_remove(&mut self, id: Uuid) -> Option<SessionInfo> {
        let removed_session = self.all_running.remove(&id);

        let _ = self.all_notify_kill.remove(&id);

        if let Some(interest) = self.disconnect_interest.remove(&id) {
            self.update_disconnected_info(id, interest, false);
        }

        removed_session
    }

    fn handle_kill(&mut self, id: Uuid) -> KillResult {
        if let Some(interest) = self.disconnect_interest.get(&id).copied() {
            self.update_disconnected_info(id, interest, true);
        }

        match self.all_notify_kill.get(&id) {
            Some(notify_kill) => {
                notify_kill.notify_waiters();
                KillResult::Success
            }
            None => KillResult::NotFound,
        }
    }

    fn handle_get_disconnected_info(&mut self, id: Uuid) -> Option<DisconnectedInfo> {
        self.disconnected_info.get(&id).copied()
    }

    /// Try to insert disconnected info. Nothing will happen in the info are already inserted.
    fn update_disconnected_info(&mut self, id: Uuid, interest: DisconnectInterest, was_killed: bool) {
        self.disconnected_info
            .entry(id)
            .and_modify(|info| {
                // Never unset the was_killed flag.
                info.was_killed |= was_killed;

                if !was_killed {
                    info.date = OffsetDateTime::now_utc();
                    info.interest = interest;
                    info.count += 1;
                }
            })
            .or_insert_with(|| DisconnectedInfo {
                id,
                was_killed,
                date: OffsetDateTime::now_utc(),
                interest,
                count: if was_killed { 0 } else { 1 },
            });
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
    const DISCONNECTED_INFO_CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 5); // 5 minutes

    debug!("Task started");

    let mut with_ttl = BinaryHeap::<WithTtlInfo>::new();
    let auto_kill_sleep = tokio::time::sleep_until(tokio::time::Instant::now());
    tokio::pin!(auto_kill_sleep);
    (&mut auto_kill_sleep).await; // Consume initial sleep.

    let mut cleanup_interval = tokio::time::interval(DISCONNECTED_INFO_CLEANUP_INTERVAL);

    loop {
        tokio::select! {
            () = &mut auto_kill_sleep, if !with_ttl.is_empty() => {
                let to_kill = with_ttl.pop().expect("we check for non-emptiness before entering this block");

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
                    SessionManagerMessage::New { info, notify_kill, disconnect_interest } => {
                        if let SessionTtl::Limited { minutes } = info.time_to_live {
                            let now = tokio::time::Instant::now();
                            let duration = Duration::from_secs(minutes.get() * 60);
                            let deadline = now + duration;

                            with_ttl.push(WithTtlInfo {
                                deadline,
                                session_id: info.id,
                            });

                            // Reset the Sleep instance if the new deadline is sooner or it is already elapsed.
                            if auto_kill_sleep.is_elapsed() || deadline < auto_kill_sleep.deadline() {
                                auto_kill_sleep.as_mut().reset(deadline);
                            }

                            debug!(session.id = %info.id, minutes = minutes.get(), "Limited TTL session registered");
                        }

                        if info.recording_policy {
                            let task = EnsureRecordingPolicyTask {
                                session_id: info.id,
                                session_manager_handle: manager.tx.clone(),
                                recording_manager_handle: manager.recording_manager_handle.clone(),
                            };

                            devolutions_gateway_task::spawn_task(task, shutdown_signal.clone()).detach();

                            debug!(session.id = %info.id, "Session with recording policy registered");
                        }

                        manager.handle_new(info, notify_kill, disconnect_interest);
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
                    SessionManagerMessage::GetDisconnectedInfo { id, channel } => {
                        let disconnected_info = manager.handle_get_disconnected_info(id);
                        let _ = channel.send(disconnected_info);
                    }
                    SessionManagerMessage::GetRunning { channel } => {
                        let _ = channel.send(manager.all_running.clone());
                    }
                    SessionManagerMessage::GetCount { channel } => {
                        let _ = channel.send(manager.all_running.len());
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                trace!(table_size = manager.disconnected_info.len(), "Cleanup disconnected info table");
                let now = OffsetDateTime::now_utc();
                manager.disconnected_info.retain(|_, info| now < info.date + info.interest.window);
                trace!(table_size = manager.disconnected_info.len(), "Disconnected info table cleanup complete");
            }
            () = shutdown_signal.wait() => {
                break;
            }
        }
    }

    debug!("Task is stopping; kill all running sessions");

    for notify_kill in manager.all_notify_kill.values() {
        notify_kill.notify_waiters();
    }

    debug!("Task is stopping; wait for leftover messages");

    loop {
        // Here, we await with a timeout because this task holds a handle to the
        // recording manager, but the recording manager itself also holds a handle to
        // the session manager. As long as the other end doesn’t drop the handle, the
        // recv future will never resolve. We simply assume there are no leftover messages
        // to process after one second of inactivity.
        let msg = match futures::future::select(
            pin!(manager.rx.0.recv()),
            pin!(tokio::time::sleep(Duration::from_secs(1))),
        )
        .await
        {
            Either::Left((Some(msg), _)) => msg,
            Either::Left((None, _)) => break,
            Either::Right(_) => break,
        };

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
        let sleep = tokio::time::sleep(Duration::from_secs(10));
        let shutdown_signal = shutdown_signal.wait();

        match futures::future::select(pin!(sleep), pin!(shutdown_signal)).await {
            Either::Left(_) => {}
            Either::Right(_) => return,
        }

        let is_recording = self
            .recording_manager_handle
            .get_state(self.session_id)
            .await
            .ok()
            .flatten()
            .is_some();

        if is_recording {
            let _ = self
                .recording_manager_handle
                .update_recording_policy(self.session_id, true)
                .await;
        } else {
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
