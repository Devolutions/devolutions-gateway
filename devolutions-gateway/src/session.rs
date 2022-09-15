use crate::{subscriber, token::ApplicationProtocol, utils::TargetAddr};
use anyhow::Context as _;
use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Arc};
use tap::prelude::*;
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
    pub start_timestamp: DateTime<Utc>,
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
            start_timestamp: Utc::now(),
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

    pub fn id(&self) -> Uuid {
        self.association_id
    }
}

#[instrument]
pub async fn add_session_in_progress(
    sessions: &SessionManagerHandle,
    subscriber_tx: &subscriber::SubscriberSender,
    info: SessionInfo,
    notify_kill: Arc<Notify>,
) -> anyhow::Result<()> {
    let association_id = info.association_id;
    let start_timestamp = info.start_timestamp;

    sessions
        .new_session(info, notify_kill)
        .await
        .context("Couldn't register new session")?;

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
    sessions: &SessionManagerHandle,
    subscriber_tx: &subscriber::SubscriberSender,
    id: Uuid,
) -> anyhow::Result<()> {
    let removed_session = sessions
        .remove_session(id)
        .await
        .context("Couldn't remove running session")?;

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

pub enum KillResult {
    Success,
    NotFound,
}

pub enum SessionManagerMessage {
    New {
        info: SessionInfo,
        notify_kill: Arc<Notify>,
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
}

#[derive(Clone, Debug)]
pub struct SessionManagerHandle(mpsc::Sender<SessionManagerMessage>);

impl SessionManagerHandle {
    pub async fn new_session(&self, info: SessionInfo, notify_kill: Arc<Notify>) -> anyhow::Result<()> {
        self.0
            .send(SessionManagerMessage::New { info, notify_kill })
            .await
            .ok()
            .context("Couldn't send New message")
    }

    pub async fn remove_session(&self, id: Uuid) -> anyhow::Result<Option<SessionInfo>> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::Remove { id, channel: tx })
            .await
            .ok()
            .context("Couldn't send Remove message")?;
        rx.await.context("Couldn't receive removed session info")
    }

    pub async fn kill_session(&self, id: Uuid) -> anyhow::Result<KillResult> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::Kill { id, channel: tx })
            .await
            .ok()
            .context("Couldn't send Kill message")?;
        rx.await.context("Couldn't receive kill result")
    }

    pub async fn get_running_sessions(&self) -> anyhow::Result<RunningSessions> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(SessionManagerMessage::GetRunning { channel: tx })
            .await
            .ok()
            .context("Couldn't send GetRunning message")?;
        rx.await.context("Couldn't receive running session list")
    }
}

pub struct SessionManagerReceiver(mpsc::Receiver<SessionManagerMessage>);

pub fn session_manager_channel() -> (SessionManagerHandle, SessionManagerReceiver) {
    mpsc::channel(64).pipe(|(tx, rx)| (SessionManagerHandle(tx), SessionManagerReceiver(rx)))
}

pub struct SessionManagerTask {
    rx: SessionManagerReceiver,
    all_running: HashMap<Uuid, SessionInfo>,
    all_notify_kill: HashMap<Uuid, Arc<Notify>>,
}

impl SessionManagerTask {
    pub fn new(rx: SessionManagerReceiver) -> Self {
        Self {
            rx,
            all_running: HashMap::new(),
            all_notify_kill: HashMap::new(),
        }
    }
}

pub async fn session_manager_task(task: SessionManagerTask) -> anyhow::Result<()> {
    debug!("Task started");

    let SessionManagerTask {
        mut rx,
        mut all_running,
        mut all_notify_kill,
    } = task;

    loop {
        match rx.0.recv().await.context("All senders are dead")? {
            SessionManagerMessage::New { info, notify_kill } => {
                let id = info.association_id;
                all_running.insert(id, info);
                all_notify_kill.insert(id, notify_kill);
            }
            SessionManagerMessage::Remove { id, channel } => {
                let removed_session = all_running.remove(&id);
                all_notify_kill.remove(&id);
                let _ = channel.send(removed_session);
            }
            SessionManagerMessage::Kill { id, channel } => match all_notify_kill.get(&id) {
                Some(notify_kill) => {
                    notify_kill.notify_waiters();
                    let _ = channel.send(KillResult::Success);
                }
                None => {
                    let _ = channel.send(KillResult::NotFound);
                }
            },
            SessionManagerMessage::GetRunning { channel } => {
                let _ = channel.send(all_running.clone());
            }
        }
    }
}
