use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::body::Body;
use axum::extract::ws::{CloseFrame, Utf8Bytes, WebSocket};
use axum::response::Response;
use bytes::Bytes;
use devolutions_gateway_task::ShutdownSignal;
use futures::{SinkExt, Stream, stream};
use terminal_streamer::terminal_stream;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncReadExt;
use tokio::sync::{Notify, watch};
use uuid::Uuid;
use video_streamer::{RecordingEvent, SessionConfig, StartAt, stream_session};

use crate::recording::{RecordingMessageSender, RecordingStreamState};
use crate::token::RecordingFileType;

pub(crate) async fn stream_recording(
    ws: axum::extract::WebSocketUpgrade,
    shutdown_signal: ShutdownSignal,
    recordings: RecordingMessageSender,
    recording_id: Uuid,
) -> anyhow::Result<Response<Body>> {
    let stream_state = recordings.subscribe_to_stream(recording_id).await?;
    let path = stream_state
        .borrow()
        .clips
        .last()
        .context("recording has no clips")?
        .path
        .clone();
    let streaming_type = validate_streaming_file(&path).await?;
    let upgrade_result = match streaming_type {
        StreamingType::Terminal => {
            let shutdown_notify = recordings.subscribe_to_recording_finish(recording_id).await?;
            let when_new_chunk_appended = move || {
                let (tx, rx) = tokio::sync::oneshot::channel();
                recordings.add_new_chunk_listener(recording_id, tx);
                rx
            };
            let path = Arc::new(path);
            ws.on_upgrade(move |socket| async move {
                if let Err(e) = setup_terminal_streaming(&path, socket, shutdown_notify, when_new_chunk_appended).await
                {
                    error!(error = ?e, "Terminal streaming failed");
                }
            })
        }
        StreamingType::WebM => ws.on_upgrade(move |socket| async move {
            if let Err(e) = setup_webm_streaming(stream_state, socket, shutdown_signal).await {
                error!(error = ?e, "WebM streaming failed");
            }
        }),
    };

    Ok(upgrade_result)
}

struct TerminalStreamSocketImpl(WebSocket);

impl terminal_streamer::TerminalStreamSocket for TerminalStreamSocketImpl {
    async fn send(&mut self, value: String) -> Result<(), anyhow::Error> {
        self.0
            .send(axum::extract::ws::Message::Text(Utf8Bytes::from(value)))
            .await?;
        Ok(())
    }

    async fn close(&mut self) {
        let _ = self
            .0
            .send(axum::extract::ws::Message::Close(Some(CloseFrame {
                code: 1000,
                reason: Utf8Bytes::from_static("EOF"),
            })))
            .await;
        let _ = self.0.flush().await;
    }
}

enum StreamingType {
    Terminal,
    WebM,
}

async fn validate_streaming_file(path: &camino::Utf8Path) -> anyhow::Result<StreamingType> {
    let path_extension = path
        .extension()
        .context("no extension found in the recording file path")?;

    info!(?path, extension = ?path_extension, "Streaming file");
    if !(path_extension == RecordingFileType::WebM.extension()
        || path_extension == RecordingFileType::Asciicast.extension()
        || path_extension == RecordingFileType::TRP.extension())
    {
        anyhow::bail!("invalid file type");
    }

    if path_extension == RecordingFileType::Asciicast.extension()
        || path_extension == RecordingFileType::TRP.extension()
    {
        Ok(StreamingType::Terminal)
    } else {
        Ok(StreamingType::WebM)
    }
}

async fn setup_terminal_streaming(
    path: &camino::Utf8Path,
    socket: WebSocket,
    shutdown_notify: Arc<Notify>,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()> + Send + 'static,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    const FILE_SHARE_READ: u32 = 0x00000001;

    #[cfg(windows)]
    let streaming_file = OpenOptions::new()
        .read(true)
        .access_mode(FILE_SHARE_READ)
        .open(path)
        .await
        .with_context(|| format!("failed to open file: {path:?}"))?;

    #[cfg(not(windows))]
    let streaming_file = OpenOptions::new()
        .read(true)
        .open(path)
        .await
        .with_context(|| format!("failed to open file: {path:?}"))?;

    let path_extension = path
        .extension()
        .context("no extension found in the recording file path")?;
    let input_type = if path_extension == RecordingFileType::Asciicast.extension() {
        terminal_streamer::InputStreamType::Asciinema
    } else {
        terminal_streamer::InputStreamType::Trp
    };

    terminal_stream(
        TerminalStreamSocketImpl(socket),
        streaming_file,
        shutdown_notify,
        input_type,
        when_new_chunk_appended,
    )
    .await
    .inspect_err(|e| error!(error = format!("{e:#}"), "Streaming file failed"))?;

    Ok(())
}

async fn setup_webm_streaming(
    stream_state: watch::Receiver<RecordingStreamState>,
    socket: WebSocket,
    shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    let source = recording_event_stream(stream_state)?;
    let (websocket_stream, close_handle) = crate::ws::handle_messages(
        socket,
        crate::ws::KeepAliveShutdownSignal(shutdown_signal),
        Duration::from_secs(45),
    );
    let streaming_result = stream_session(source, websocket_stream, SessionConfig::default()).await;

    match streaming_result {
        Err(error) => {
            close_handle.server_error("webm streaming failure".to_owned()).await;
            error!(error = format!("{error:#}"), "Streaming file failed");
            Err(error)
        }
        Ok(()) => {
            close_handle.normal_close().await;
            Ok(())
        }
    }
}

struct CurrentRecordingClip {
    sequence: u64,
    file: File,
    caught_up: bool,
}

struct RecordingEventSource {
    stream_state: watch::Receiver<RecordingStreamState>,
    next_clip: usize,
    current_clip: Option<CurrentRecordingClip>,
    next_start_at: StartAt,
    ended: bool,
}

impl RecordingEventSource {
    fn new(mut stream_state: watch::Receiver<RecordingStreamState>) -> anyhow::Result<Self> {
        let state = stream_state.borrow_and_update().clone();
        let (next_clip, next_start_at) = match state.active {
            Some(active) => (
                usize::try_from(active.sequence).context("recording sequence does not fit in usize")?,
                if active.ready {
                    StartAt::LiveEdge
                } else {
                    StartAt::Beginning
                },
            ),
            None => (state.clips.len(), StartAt::Beginning),
        };

        Ok(Self {
            stream_state,
            next_clip,
            current_clip: None,
            next_start_at,
            ended: false,
        })
    }

    async fn next_event(&mut self) -> anyhow::Result<Option<RecordingEvent>> {
        const READ_BUFFER_SIZE: usize = 64 * 1024;

        if self.ended {
            return Ok(None);
        }

        loop {
            let state = self.stream_state.borrow_and_update().clone();

            if let Some(current_clip) = self.current_clip.as_mut() {
                let mut bytes = vec![0; READ_BUFFER_SIZE];
                let read = current_clip.file.read(&mut bytes).await?;
                if read > 0 {
                    bytes.truncate(read);
                    return Ok(Some(RecordingEvent::Bytes(Bytes::from(bytes))));
                }

                if !current_clip.caught_up {
                    current_clip.caught_up = true;
                    return Ok(Some(RecordingEvent::CaughtUp));
                }

                if state
                    .active
                    .is_some_and(|active| active.sequence == current_clip.sequence)
                {
                    self.stream_state
                        .changed()
                        .await
                        .context("recording stream state closed")?;
                    continue;
                }

                self.current_clip = None;
                self.next_clip = self.next_clip.checked_add(1).context("recording clip index overflow")?;
                return Ok(Some(RecordingEvent::ClipEnded));
            }

            if let Some(clip) = state.clips.get(self.next_clip) {
                let expected_sequence =
                    u64::try_from(self.next_clip).context("recording clip index does not fit in u64")?;
                if clip.sequence != expected_sequence {
                    anyhow::bail!("recording clip sequence is not contiguous");
                }

                if state
                    .active
                    .is_some_and(|active| active.sequence == clip.sequence && !active.ready)
                {
                    self.stream_state
                        .changed()
                        .await
                        .context("recording stream state closed")?;
                    continue;
                }

                if clip.path.extension() != Some(RecordingFileType::WebM.extension()) {
                    anyhow::bail!("recording clip is not WebM");
                }

                let file = File::open(&clip.path)
                    .await
                    .with_context(|| format!("failed to open recording clip: {}", clip.path))?;
                let start_at = std::mem::replace(&mut self.next_start_at, StartAt::Beginning);
                self.current_clip = Some(CurrentRecordingClip {
                    sequence: clip.sequence,
                    file,
                    caught_up: false,
                });
                return Ok(Some(RecordingEvent::ClipStarted {
                    sequence: clip.sequence,
                    start_at,
                }));
            }

            if state.ended {
                self.ended = true;
                return Ok(Some(RecordingEvent::SessionEnded));
            }

            self.stream_state
                .changed()
                .await
                .context("recording stream state closed")?;
        }
    }
}

fn recording_event_stream(
    stream_state: watch::Receiver<RecordingStreamState>,
) -> anyhow::Result<impl Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static> {
    let source = RecordingEventSource::new(stream_state)?;
    Ok(stream::unfold(Some(source), |source| async move {
        let mut source = source?;
        match source.next_event().await {
            Ok(Some(event)) => Some((Ok(event), Some(source))),
            Ok(None) => None,
            Err(error) => Some((Err(error), None)),
        }
    }))
}
