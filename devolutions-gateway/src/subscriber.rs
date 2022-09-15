use crate::config::dto::Subscriber;
use crate::config::ConfHandle;
use crate::SESSIONS_IN_PROGRESS;
use anyhow::Context as _;
use chrono::{DateTime, Utc};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use uuid::Uuid;

pub type SubscriberSender = mpsc::Sender<Message>;
pub type SubscriberReceiver = mpsc::Receiver<Message>;

pub fn subscriber_channel() -> (SubscriberSender, SubscriberReceiver) {
    mpsc::channel(64)
}

#[derive(Debug, Serialize)]
pub struct SubscriberSessionInfo {
    pub association_id: Uuid,
    pub start_timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
#[allow(clippy::enum_variant_names)]
enum MessageInner {
    #[serde(rename = "session.started")]
    SessionStarted { session: SubscriberSessionInfo },
    #[serde(rename = "session.ended")]
    SessionEnded { session: SubscriberSessionInfo },
    #[serde(rename = "session.list")]
    SessionList { session_list: Vec<SubscriberSessionInfo> },
}

#[derive(Debug, Serialize)]
pub struct Message {
    timestamp: DateTime<Utc>,
    #[serde(flatten)]
    inner: MessageInner,
}

impl Message {
    pub fn session_started(session: SubscriberSessionInfo) -> Self {
        Self {
            timestamp: session.start_timestamp,
            inner: MessageInner::SessionStarted { session },
        }
    }

    pub fn session_ended(session: SubscriberSessionInfo) -> Self {
        Self {
            timestamp: Utc::now(),
            inner: MessageInner::SessionEnded { session },
        }
    }

    pub fn session_list(session_list: Vec<SubscriberSessionInfo>) -> Self {
        Self {
            timestamp: Utc::now(),
            inner: MessageInner::SessionList { session_list },
        }
    }
}

pub async fn send_message(subscriber: &Subscriber, message: &Message) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    client
        .post(subscriber.url.clone())
        .header("Authorization", format!("Bearer {}", subscriber.token))
        .json(message)
        .send()
        .await
        .context("Failed to post message at the subscriber URL")?
        .error_for_status()
        .context("Subscriber responded with an error code")?;

    Ok(())
}

#[instrument(skip(tx))]
pub async fn subscriber_polling_task(tx: SubscriberSender) -> anyhow::Result<()> {
    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 20); // once per 20 minutes

    debug!("Task started");

    loop {
        trace!("Send session list message");

        let session_list: Vec<_> = SESSIONS_IN_PROGRESS
            .read()
            .values()
            .map(|session| SubscriberSessionInfo {
                association_id: session.association_id,
                start_timestamp: session.start_timestamp,
            })
            .collect();

        let message = Message::session_list(session_list);

        tx.send(message)
            .await
            .map_err(|e| anyhow::anyhow!("Subscriber Task ended: {e}"))?;

        sleep(TASK_INTERVAL).await;
    }
}

#[instrument(skip(conf_handle, rx))]
pub async fn subscriber_task(conf_handle: ConfHandle, mut rx: SubscriberReceiver) -> anyhow::Result<()> {
    debug!("Task started");

    let mut conf = conf_handle.get_conf();

    loop {
        tokio::select! {
            _ = conf_handle.change_notified() => {
                conf = conf_handle.get_conf();
            }
            msg = rx.recv() => {
                let msg = msg.context("All senders are dead")?;
                if let Some(subscriber) = conf.subscriber.as_ref() {
                    debug!(?msg, %subscriber.url, "Send message");
                    if let Err(error) = send_message(subscriber, &msg).await {
                        warn!(error = format!("{error:#}"), "Couldn't send message to the subscriber");
                    }
                } else {
                    trace!(?msg, "Subscriber is not configured, ignore message");
                }
            }
        }
    }
}
