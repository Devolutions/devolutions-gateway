//! Traffic audit manager implementing an actor pattern for managing traffic audit events.
//!
//! This module provides a shareable handle (`TrafficAuditHandle`) for pushing, claiming,
//! and acknowledging traffic audit events, with an underlying task that manages the
//! `LibSqlTrafficAuditRepo` object.

use anyhow::Context as _;
use async_trait::async_trait;
use core::fmt;
use devolutions_gateway_task::{ShutdownSignal, Task};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use traffic_audit::{ClaimedEvent, DynTrafficAuditRepo, TrafficAuditRepo, TrafficEvent};

const PURGE_INTERVAL: Duration = Duration::from_secs(60 * 60 * 3); // 3 hours.
const AUDIT_EVENT_LIFETIME_MS: i64 = 24 * 60 * 60 * 1000; // 24 hours

/// Messages sent to the traffic audit manager task
pub enum TrafficAuditMessage {
    Push {
        event: TrafficEvent,
        channel: oneshot::Sender<anyhow::Result<()>>,
    },
    Claim {
        consumer_id: String,
        lease_duration_ms: i64,
        max_events: usize,
        channel: oneshot::Sender<anyhow::Result<Vec<ClaimedEvent>>>,
    },
    Ack {
        ids: Vec<i64>,
        channel: oneshot::Sender<anyhow::Result<()>>,
    },
}

impl fmt::Debug for TrafficAuditMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrafficAuditMessage::Push { event, channel: _ } => {
                f.debug_struct("Push").field("event", event).finish_non_exhaustive()
            }
            TrafficAuditMessage::Claim {
                consumer_id,
                lease_duration_ms,
                max_events,
                channel: _,
            } => f
                .debug_struct("Claim")
                .field("consumer_id", consumer_id)
                .field("lease_duration_ms", lease_duration_ms)
                .field("max_events", max_events)
                .finish_non_exhaustive(),
            TrafficAuditMessage::Ack { ids, channel: _ } => {
                f.debug_struct("Ack").field("ids", ids).finish_non_exhaustive()
            }
        }
    }
}

/// Handle for sending messages to the traffic audit manager
#[derive(Clone, Debug)]
pub struct TrafficAuditHandle(mpsc::Sender<TrafficAuditMessage>);

pub type TrafficAuditReceiver = mpsc::Receiver<TrafficAuditMessage>;

impl TrafficAuditHandle {
    pub fn new() -> (Self, TrafficAuditReceiver) {
        let (tx, rx) = mpsc::channel(256);
        (Self(tx), rx)
    }

    /// Push a new traffic event to the audit system
    pub async fn push(&self, event: TrafficEvent) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();

        self.0
            .send(TrafficAuditMessage::Push { event, channel: tx })
            .await
            .context("traffic audit manager task is dead")?;

        rx.await
            .context("failed to receive response from traffic audit manager")?
    }

    /// Claim traffic events for processing
    pub async fn claim(
        &self,
        consumer_id: impl Into<String>,
        lease_duration_ms: i64,
        max_events: usize,
    ) -> anyhow::Result<Vec<ClaimedEvent>> {
        let (tx, rx) = oneshot::channel();

        self.0
            .send(TrafficAuditMessage::Claim {
                consumer_id: consumer_id.into(),
                lease_duration_ms,
                max_events,
                channel: tx,
            })
            .await
            .context("traffic audit manager task is dead")?;

        rx.await
            .context("failed to receive response from traffic audit manager")?
    }

    /// Acknowledge processing of claimed traffic events
    pub async fn ack(&self, ids: Vec<i64>) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();

        self.0
            .send(TrafficAuditMessage::Ack { ids, channel: tx })
            .await
            .context("traffic audit manager task is dead")?;

        rx.await
            .context("failed to receive response from traffic audit manager")?
    }
}

/// Traffic audit manager task that handles all repository operations
pub struct TrafficAuditManagerTask {
    handle: TrafficAuditHandle,
    rx: mpsc::Receiver<TrafficAuditMessage>,
    repo: DynTrafficAuditRepo,
}

impl TrafficAuditManagerTask {
    /// Initialize a new traffic audit manager with the given repository
    pub async fn init(path_or_url: &str) -> anyhow::Result<Self> {
        let repo = traffic_audit_libsql::LibSqlTrafficAuditRepo::open(path_or_url)
            .await
            .context("failed to open traffic audit repository")?;

        repo.setup().await.context("traffic audit repository setup")?;

        let (handle, rx) = TrafficAuditHandle::new();

        Ok(Self {
            handle,
            rx,
            repo: Arc::new(repo),
        })
    }

    /// Get a handle to this traffic audit manager
    pub fn handle(&self) -> TrafficAuditHandle {
        self.handle.clone()
    }
}

#[async_trait]
impl Task for TrafficAuditManagerTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "traffic audit manager";

    #[instrument(name = "traffic_audit", skip_all)]
    async fn run(mut self, mut shutdown_signal: ShutdownSignal) -> Self::Output {
        debug!("Task started");

        let mut purge_interval = tokio::time::interval(PURGE_INTERVAL);

        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    let Some(msg) = msg else {
                        warn!("All senders are dead");
                        break;
                    };

                    debug!(?msg, "Received message");

                    match msg {
                        TrafficAuditMessage::Push { event, channel } => {
                            let result = self.repo.push(event).await;
                            let _ = channel.send(result);
                        }
                        TrafficAuditMessage::Claim {
                            consumer_id,
                            lease_duration_ms,
                            max_events,
                            channel,
                        } => {
                            let result = self
                                .repo
                                .claim(&consumer_id, lease_duration_ms, max_events)
                                .await;
                            let _ = channel.send(result);
                        }
                        TrafficAuditMessage::Ack { ids, channel } => {
                            let result = self.repo.ack(&ids).await;
                            let _ = channel.send(result);
                        }
                    }
                }
                _ = purge_interval.tick() => {
                    let now = i64::try_from(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .expect("now after UNIX_EPOCH")
                            .as_millis(),
                    )
                    .expect("u128-to-i64");

                    if let Err(error) = self.repo.purge(now - AUDIT_EVENT_LIFETIME_MS).await {
                        warn!(%error, "Couldn't purge traffic audit events");
                    }
                }
                () = shutdown_signal.wait() => {
                    break;
                }
            }
        }

        debug!("Task terminated");

        Ok(())
    }
}
