use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use axum::extract::ws;
use bytes::Bytes;
use serde::Serialize;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt as _, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use ulid::Ulid;
use uuid::Uuid;

use crate::token::RecordingFileType;
use crate::ws::MessageObserver;

const CAPTURE_DIR_ENV: &str = "DGATEWAY_JREC_CAPTURE_DIR";
const CAPTURE_FORMAT_VERSION: u32 = 1;

static CAPTURE_RUN: LazyLock<(Ulid, Instant)> = LazyLock::new(|| (Ulid::new(), Instant::now()));

pub(crate) enum CaptureOutcome {
    Done,
    StorageFull,
    Error,
}

impl CaptureOutcome {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::StorageFull => "storage_full",
            Self::Error => "error",
        }
    }
}

pub(crate) struct JrecCapture {
    connection_path: PathBuf,
    observer: MessageObserver,
    sender: mpsc::UnboundedSender<CaptureCommand>,
    started_at: Instant,
    writer_task: JoinHandle<anyhow::Result<()>>,
}

impl JrecCapture {
    pub(crate) async fn start(
        session_id: Uuid,
        file_type: RecordingFileType,
        source_addr: SocketAddr,
    ) -> anyhow::Result<Option<Self>> {
        let Some(root) = std::env::var_os(CAPTURE_DIR_ENV) else {
            return Ok(None);
        };

        let root = absolute_capture_root(root)?;
        let connection_path = root
            .join(format!("run-{}", CAPTURE_RUN.0))
            .join(session_id.to_string())
            .join(format!("connection-{}", Ulid::new()));
        tokio::fs::create_dir_all(&connection_path)
            .await
            .with_context(|| format!("create capture directory at {}", connection_path.display()))?;

        let opened_at_unix_us = duration_us(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before the Unix epoch")?,
        );
        let metadata = CaptureMetadata {
            format_version: CAPTURE_FORMAT_VERSION,
            session_id,
            file_type: file_type.extension(),
            source_addr,
            opened_at_unix_us,
            opened_at_run_us: duration_us(CAPTURE_RUN.1.elapsed()),
        };
        write_metadata(&connection_path, &metadata).await?;

        let (sender, receiver) = mpsc::unbounded_channel();
        let started_at = Instant::now();
        let observer_sender = sender.clone();
        let observer: MessageObserver = Arc::new(move |message: &ws::Message| {
            let command = CaptureCommand::Message {
                time_us: duration_us(started_at.elapsed()),
                message: CapturedMessage::from(message),
            };
            let _ = observer_sender.send(command);
        });
        let writer_path = connection_path.clone();
        let writer_task = tokio::spawn(async move { write_capture(&writer_path, receiver).await });

        Ok(Some(Self {
            connection_path,
            observer,
            sender,
            started_at,
            writer_task,
        }))
    }

    pub(crate) fn observer(&self) -> MessageObserver {
        Arc::clone(&self.observer)
    }

    pub(crate) async fn finish(self, outcome: CaptureOutcome) {
        let _ = self.sender.send(CaptureCommand::Finished {
            time_us: duration_us(self.started_at.elapsed()),
            outcome,
        });
        drop(self.sender);

        match self.writer_task.await {
            Ok(Ok(())) => info!(path = %self.connection_path.display(), "Recorded JREC push capture"),
            Ok(Err(error)) => {
                error!(path = %self.connection_path.display(), error = %error, "Failed to record JREC push capture")
            }
            Err(error) => {
                error!(path = %self.connection_path.display(), error = %error, "JREC push capture task failed")
            }
        }
    }
}

fn absolute_capture_root(root: OsString) -> anyhow::Result<PathBuf> {
    let root = PathBuf::from(root);
    anyhow::ensure!(root.is_absolute(), "capture directory must be absolute");
    Ok(root)
}

fn duration_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[derive(Serialize)]
struct CaptureMetadata<'a> {
    format_version: u32,
    session_id: Uuid,
    file_type: &'a str,
    source_addr: SocketAddr,
    opened_at_unix_us: u64,
    opened_at_run_us: u64,
}

async fn write_metadata(path: &Path, metadata: &CaptureMetadata<'_>) -> anyhow::Result<()> {
    let metadata_path = path.join("metadata.json");
    let mut contents = serde_json::to_vec_pretty(metadata).context("serialize capture metadata")?;
    contents.push(b'\n');
    tokio::fs::write(&metadata_path, contents)
        .await
        .with_context(|| format!("write capture metadata at {}", metadata_path.display()))
}

enum CaptureCommand {
    Message { time_us: u64, message: CapturedMessage },
    Finished { time_us: u64, outcome: CaptureOutcome },
}

enum CapturedMessage {
    Payload { message_type: &'static str, data: Bytes },
    Close { code: Option<u16>, reason: Option<String> },
}

impl From<&ws::Message> for CapturedMessage {
    fn from(message: &ws::Message) -> Self {
        match message {
            ws::Message::Text(data) => Self::Payload {
                message_type: "text",
                data: Bytes::copy_from_slice(data.as_bytes()),
            },
            ws::Message::Binary(data) => Self::Payload {
                message_type: "binary",
                data: data.clone(),
            },
            ws::Message::Ping(data) => Self::Payload {
                message_type: "ping",
                data: data.clone(),
            },
            ws::Message::Pong(data) => Self::Payload {
                message_type: "pong",
                data: data.clone(),
            },
            ws::Message::Close(frame) => Self::Close {
                code: frame.as_ref().map(|frame| frame.code),
                reason: frame.as_ref().map(|frame| frame.reason.to_string()),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum CaptureEvent<'a> {
    Message {
        time_us: u64,
        message_type: &'a str,
        offset: u64,
        length: u64,
    },
    Close {
        time_us: u64,
        code: Option<u16>,
        reason: Option<String>,
    },
    Finished {
        time_us: u64,
        outcome: &'a str,
    },
}

async fn write_capture(path: &Path, mut receiver: mpsc::UnboundedReceiver<CaptureCommand>) -> anyhow::Result<()> {
    let events_path = path.join("events.jsonl");
    let payload_path = path.join("payload.bin");
    let mut events = BufWriter::new(
        File::create(&events_path)
            .await
            .with_context(|| format!("create capture events at {}", events_path.display()))?,
    );
    let mut payload = BufWriter::new(
        File::create(&payload_path)
            .await
            .with_context(|| format!("create capture payload at {}", payload_path.display()))?,
    );
    let mut payload_offset = 0u64;

    while let Some(command) = receiver.recv().await {
        match command {
            CaptureCommand::Message {
                time_us,
                message: CapturedMessage::Payload { message_type, data },
            } => {
                let length = u64::try_from(data.len()).context("capture payload is too large")?;
                payload.write_all(&data).await.context("write capture payload")?;
                write_event(
                    &mut events,
                    &CaptureEvent::Message {
                        time_us,
                        message_type,
                        offset: payload_offset,
                        length,
                    },
                )
                .await?;
                payload_offset = payload_offset
                    .checked_add(length)
                    .context("capture payload offset overflow")?;
            }
            CaptureCommand::Message {
                time_us,
                message: CapturedMessage::Close { code, reason },
            } => {
                write_event(&mut events, &CaptureEvent::Close { time_us, code, reason }).await?;
            }
            CaptureCommand::Finished { time_us, outcome } => {
                write_event(
                    &mut events,
                    &CaptureEvent::Finished {
                        time_us,
                        outcome: outcome.as_str(),
                    },
                )
                .await?;
                break;
            }
        }
    }

    payload.flush().await.context("flush capture payload")?;
    events.flush().await.context("flush capture events")?;
    Ok(())
}

async fn write_event(events: &mut BufWriter<File>, event: &CaptureEvent<'_>) -> anyhow::Result<()> {
    let mut line = serde_json::to_vec(event).context("serialize capture event")?;
    line.push(b'\n');
    events.write_all(&line).await.context("write capture event")
}
