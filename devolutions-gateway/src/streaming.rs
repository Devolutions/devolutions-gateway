use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::body::Body;
use axum::extract::ws::{CloseFrame, Utf8Bytes, WebSocket};
use axum::response::Response;
use devolutions_gateway_task::ShutdownSignal;
use futures::{SinkExt, Stream, stream};
use terminal_streamer::terminal_stream;
use tokio::fs::{File, OpenOptions};
use tokio::sync::{Notify, watch};
use uuid::Uuid;
use video_streamer::{RecordingClip, RecordingEvent, RecordingSource, SessionConfig, StartAt, stream_session};

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
        StreamingType::Terminal(input_type) => {
            let shutdown_notify = recordings.subscribe_to_recording_finish(recording_id).await?;
            let when_new_chunk_appended = move || {
                let (tx, rx) = tokio::sync::oneshot::channel();
                recordings.add_new_chunk_listener(recording_id, tx);
                rx
            };
            let path = Arc::new(path);
            ws.on_upgrade(move |socket| async move {
                if let Err(e) =
                    setup_terminal_streaming(&path, input_type, socket, shutdown_notify, when_new_chunk_appended).await
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
    Terminal(terminal_streamer::InputStreamType),
    WebM,
}

/// Determines streamability from recording type, which is stricter than pull MIME handling.
/// A file may be downloadable but still rejected here when there is no streaming backend.
async fn validate_streaming_file(path: &camino::Utf8Path) -> anyhow::Result<StreamingType> {
    let path_extension = path
        .extension()
        .context("no extension found in the recording file path")?;

    info!(?path, extension = ?path_extension, "Streaming file");
    let file_type =
        RecordingFileType::from_extension(path_extension).ok_or_else(|| anyhow::anyhow!("invalid file type"))?;
    streaming_type_for_file_type(file_type)
}

fn streaming_type_for_file_type(file_type: RecordingFileType) -> anyhow::Result<StreamingType> {
    match file_type {
        RecordingFileType::Asciicast => Ok(StreamingType::Terminal(terminal_streamer::InputStreamType::Asciinema)),
        RecordingFileType::TRP => Ok(StreamingType::Terminal(terminal_streamer::InputStreamType::Trp)),
        RecordingFileType::WebM => Ok(StreamingType::WebM),
        RecordingFileType::SessionRecordingLog => anyhow::bail!("invalid file type"),
    }
}

async fn setup_terminal_streaming(
    path: &camino::Utf8Path,
    input_type: terminal_streamer::InputStreamType,
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
    let source = WebmRecordingSource { stream_state };
    let (websocket_stream, close_handle) = crate::ws::handle_messages(
        socket,
        crate::ws::KeepAliveShutdownSignal(shutdown_signal),
        Duration::from_secs(45),
    );
    let streaming_result = stream_session(source, websocket_stream, SessionConfig::default()).await;

    match streaming_result {
        Err(error) => {
            close_handle.server_error("webm streaming failure".to_owned()).await;
            error!(error = format!("{error:#}"), "WebM streaming failed");
            Err(error)
        }
        Ok(()) => {
            close_handle.normal_close().await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod file_type_tests {
    use super::*;

    #[tokio::test]
    async fn validates_streaming_behavior_from_file_extension() {
        let webm_type = validate_streaming_file(camino::Utf8Path::new("recording-0.webm"))
            .await
            .expect("webm should be accepted");
        assert!(matches!(webm_type, StreamingType::WebM));

        let cast_type = validate_streaming_file(camino::Utf8Path::new("recording-0.cast"))
            .await
            .expect("cast should be accepted");
        assert!(matches!(
            cast_type,
            StreamingType::Terminal(terminal_streamer::InputStreamType::Asciinema)
        ));

        let trp_type = validate_streaming_file(camino::Utf8Path::new("recording-0.trp"))
            .await
            .expect("trp should be accepted");
        assert!(matches!(
            trp_type,
            StreamingType::Terminal(terminal_streamer::InputStreamType::Trp)
        ));

        assert!(
            validate_streaming_file(camino::Utf8Path::new("recording-0.slog"))
                .await
                .is_err(),
            "slog should be rejected for streaming"
        );
        assert!(
            validate_streaming_file(camino::Utf8Path::new("recording-0.bin"))
                .await
                .is_err(),
            "unknown extension should be rejected"
        );
        assert!(
            validate_streaming_file(camino::Utf8Path::new("recording-0"))
                .await
                .is_err(),
            "missing extension should be rejected"
        );
    }

    #[test]
    fn maps_recording_file_type_to_streaming_type() {
        let asciicast_type =
            streaming_type_for_file_type(RecordingFileType::Asciicast).expect("asciicast should stream in terminal");
        assert!(matches!(
            asciicast_type,
            StreamingType::Terminal(terminal_streamer::InputStreamType::Asciinema)
        ));

        let trp_type = streaming_type_for_file_type(RecordingFileType::TRP).expect("trp should stream in terminal");
        assert!(matches!(
            trp_type,
            StreamingType::Terminal(terminal_streamer::InputStreamType::Trp)
        ));

        let webm_type = streaming_type_for_file_type(RecordingFileType::WebM).expect("webm should stream as video");
        assert!(matches!(webm_type, StreamingType::WebM));
        assert!(streaming_type_for_file_type(RecordingFileType::SessionRecordingLog).is_err());
    }
}

struct WebmRecordingSource {
    stream_state: watch::Receiver<RecordingStreamState>,
}

impl RecordingSource for WebmRecordingSource {
    type Stream = Pin<Box<dyn Stream<Item = anyhow::Result<RecordingEvent>> + Send>>;
    type Start = Pin<Box<dyn Future<Output = anyhow::Result<Self::Stream>> + Send>>;

    fn start(self) -> Self::Start {
        Box::pin(async move { recording_event_stream(self.stream_state) })
    }
}

struct CurrentRecordingClip {
    sequence: u64,
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
        if self.ended {
            return Ok(None);
        }

        loop {
            let state = self.stream_state.borrow().clone();

            if let Some(current_clip) = self.current_clip.as_mut() {
                if !current_clip.caught_up {
                    current_clip.caught_up = true;
                    return Ok(Some(RecordingEvent::CaughtUp));
                }

                if state
                    .active
                    .is_some_and(|active| active.sequence == current_clip.sequence)
                {
                    if self.stream_state.has_changed()? {
                        let latest = self.stream_state.borrow_and_update().clone();
                        if latest
                            .active
                            .is_some_and(|active| active.sequence == current_clip.sequence)
                        {
                            return Ok(Some(RecordingEvent::DataAvailable));
                        }
                        continue;
                    }
                    self.stream_state
                        .changed()
                        .await
                        .context("recording stream state closed")?;
                    if self
                        .stream_state
                        .borrow()
                        .active
                        .is_some_and(|active| active.sequence == current_clip.sequence)
                    {
                        return Ok(Some(RecordingEvent::DataAvailable));
                    }
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
                let file = file.into_std().await;
                let start_at = std::mem::replace(&mut self.next_start_at, StartAt::Beginning);
                self.current_clip = Some(CurrentRecordingClip {
                    sequence: clip.sequence,
                    caught_up: false,
                });
                return Ok(Some(RecordingEvent::ClipStarted {
                    sequence: clip.sequence,
                    start_at,
                    clip: RecordingClip::new(file),
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
) -> anyhow::Result<Pin<Box<dyn Stream<Item = anyhow::Result<RecordingEvent>> + Send>>> {
    let source = RecordingEventSource::new(stream_state)?;
    Ok(Box::pin(stream::unfold(Some(source), |source| async move {
        let mut source = source?;
        match source.next_event().await {
            Ok(Some(event)) => Some((Ok(event), Some(source))),
            Ok(None) => None,
            Err(error) => Some((Err(error), None)),
        }
    })))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::recording::{ActiveRecordingStreamClip, RecordingStreamClip};

    struct ScratchDirectory(camino::Utf8PathBuf);

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn reconnect_waits_for_the_next_clip_before_ending_the_session() {
        let scratch = camino::Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("streaming-tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&scratch).expect("create test directory");
        let _cleanup = ScratchDirectory(scratch.clone());

        let first_path = scratch.join("recording-0.webm");
        let second_path = scratch.join("recording-1.webm");
        fs::write(&first_path, b"first").expect("write first clip");
        fs::write(&second_path, b"second").expect("write second clip");

        let first_clip = RecordingStreamClip {
            sequence: 0,
            path: first_path,
        };
        let state = RecordingStreamState::for_test(
            vec![first_clip],
            Some(ActiveRecordingStreamClip {
                sequence: 0,
                ready: true,
            }),
            false,
        );
        let (sender, receiver) = watch::channel(state);
        let mut source = RecordingEventSource::new(receiver).expect("create recording event source");

        match source.next_event().await.expect("read first start") {
            Some(RecordingEvent::ClipStarted {
                sequence,
                start_at,
                clip,
            }) => {
                assert_eq!(sequence, 0);
                assert_eq!(start_at, StartAt::LiveEdge);
                drop(clip);
            }
            event => panic!("unexpected first start event: {event:?}"),
        }
        assert!(matches!(
            source.next_event().await.expect("catch up first clip"),
            Some(RecordingEvent::CaughtUp)
        ));
        sender.send_modify(|_| {});
        assert!(matches!(
            source.next_event().await.expect("read availability marker"),
            Some(RecordingEvent::DataAvailable)
        ));

        sender.send_modify(RecordingStreamState::mark_disconnected);
        assert!(matches!(
            source.next_event().await.expect("end first clip"),
            Some(RecordingEvent::ClipEnded)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), source.next_event())
                .await
                .is_err(),
            "a reconnectable disconnect must not emit SessionEnded"
        );

        sender.send_modify(|state| {
            Arc::make_mut(&mut state.clips).push(RecordingStreamClip {
                sequence: 1,
                path: second_path,
            });
            state.active = Some(ActiveRecordingStreamClip {
                sequence: 1,
                ready: true,
            });
            state.ended = false;
        });
        match source.next_event().await.expect("read second start") {
            Some(RecordingEvent::ClipStarted {
                sequence,
                start_at,
                clip,
            }) => {
                assert_eq!(sequence, 1);
                assert_eq!(start_at, StartAt::Beginning);
                drop(clip);
            }
            event => panic!("unexpected second start event: {event:?}"),
        }
        assert!(matches!(
            source.next_event().await.expect("catch up second clip"),
            Some(RecordingEvent::CaughtUp)
        ));

        sender.send_modify(RecordingStreamState::mark_disconnected);
        assert!(matches!(
            source.next_event().await.expect("end second clip"),
            Some(RecordingEvent::ClipEnded)
        ));
        sender.send_modify(RecordingStreamState::mark_ended);
        assert!(matches!(
            source.next_event().await.expect("end session"),
            Some(RecordingEvent::SessionEnded)
        ));
        assert!(source.next_event().await.expect("finish source").is_none());
    }

    #[tokio::test]
    async fn catch_up_precedes_coalesced_append_markers() {
        let scratch = camino::Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("streaming-tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&scratch).expect("create test directory");
        let _cleanup = ScratchDirectory(scratch.clone());

        let path = scratch.join("recording-0.webm");
        fs::write(&path, b"recording").expect("write clip");
        let state = RecordingStreamState::for_test(
            vec![RecordingStreamClip { sequence: 0, path }],
            Some(ActiveRecordingStreamClip {
                sequence: 0,
                ready: true,
            }),
            false,
        );
        let (sender, receiver) = watch::channel(state);
        let mut source = RecordingEventSource::new(receiver).expect("create recording event source");

        assert!(matches!(
            source.next_event().await.expect("read clip start"),
            Some(RecordingEvent::ClipStarted { .. })
        ));
        sender.send_modify(|_| {});
        sender.send_modify(|_| {});

        assert!(matches!(
            source.next_event().await.expect("read catch-up marker"),
            Some(RecordingEvent::CaughtUp)
        ));
        assert!(matches!(
            source.next_event().await.expect("read coalesced availability marker"),
            Some(RecordingEvent::DataAvailable)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), source.next_event())
                .await
                .is_err(),
            "coalesced append markers must produce one availability event"
        );
    }
}
