use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::ws::{CloseFrame, Utf8Bytes, WebSocket};
use axum::response::Response;
use devolutions_gateway_task::{ChildTask, ShutdownSignal};
use futures::{SinkExt, Stream, stream};
use terminal_streamer::terminal_stream;
use tokio::fs::{File, OpenOptions};
use tokio::sync::{Notify, watch};
use uuid::Uuid;
use video_streamer::{
    RecordingClip, RecordingEvent, SHADOW_PROTOCOL_V2, SessionConfig, ShadowProtocolVersion, StartAt, stream_session,
};

use crate::recording::{RecordingStreamState, StreamLifecycle};
use crate::token::RecordingFileType;

/// WebSocket close codes of the `/shadow` endpoint.
///
/// Codes from 4000 to 4999 are reserved for private use: <https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code>.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ShadowCloseCode {
    /// The recording is not running, or it ended.
    StreamingEnded = 4001,
    InternalError = 4002,
    Forbidden = 4003,
}

/// Accepts the upgrade only to close it with `code`, so that the client sees why it was rejected.
pub(crate) fn reject_shadow(ws: axum::extract::WebSocketUpgrade, code: ShadowCloseCode) -> Response {
    // Echo an offered shadow protocol so that browsers open the socket and see the close code.
    let (ws, _) = negotiate_shadow_protocol(ws);
    ws.on_upgrade(move |mut socket| async move {
        let _ = socket
            .send(axum::extract::ws::Message::Close(Some(CloseFrame {
                code: code as u16,
                reason: Utf8Bytes::from_static(""),
            })))
            .await;
    })
}

/// Streams the recording that `stream_state` describes, or closes the upgrade with the reason it can’t.
pub(crate) async fn stream_recording(
    ws: axum::extract::WebSocketUpgrade,
    shutdown_signal: ShutdownSignal,
    stream_state: watch::Receiver<RecordingStreamState>,
    recording_id: Uuid,
) -> Response {
    // One read decides everything below, so a concurrent reconnection can’t mix two states.
    let (path, index, lifecycle, active) = {
        let state = stream_state.borrow();
        let index = state.clips.len().saturating_sub(1);
        (
            state.clips.last().cloned(),
            index,
            state.lifecycle,
            state.is_active(index),
        )
    };

    if lifecycle == StreamLifecycle::Ended {
        return reject_shadow(ws, ShadowCloseCode::StreamingEnded);
    }

    let Some(path) = path else {
        warn!(%recording_id, "Shadow recording rejected: no recording files found");
        return reject_shadow(ws, ShadowCloseCode::InternalError);
    };

    let streaming_type = match validate_streaming_file(&path).await {
        Ok(streaming_type) => streaming_type,
        Err(error) => {
            warn!(%recording_id, error = format!("{error:#}"), "Shadow recording rejected: the recording can’t be streamed");
            return reject_shadow(ws, ShadowCloseCode::InternalError);
        }
    };

    match streaming_type {
        StreamingType::Terminal(input_type) => {
            // A terminal viewer follows one clip only, so a disconnected recording has nothing live to show.
            if !active {
                return reject_shadow(ws, ShadowCloseCode::StreamingEnded);
            }

            ws.on_upgrade(move |socket| async move {
                let shutdown_notify = Arc::new(Notify::new());
                let notify = Arc::clone(&shutdown_notify);
                let data_appended = stream_state.clone();
                let _shutdown_bridge = ChildTask::spawn(async move {
                    wait_for_terminal_stream_end(stream_state, index, shutdown_signal).await;
                    notify.notify_one();
                });
                if let Err(error) =
                    setup_terminal_streaming(&path, input_type, socket, shutdown_notify, data_appended).await
                {
                    error!(error = format!("{error:#}"), "Terminal streaming failed");
                }
            })
        }
        StreamingType::WebM => {
            let (ws, version) = negotiate_shadow_protocol(ws);
            debug!(%recording_id, ?version, "Negotiated shadow protocol");
            ws.on_upgrade(move |socket| async move {
                if let Err(error) = setup_webm_streaming(stream_state, socket, shutdown_signal, version).await {
                    error!(error = format!("{error:#}"), "WebM streaming failed");
                }
            })
        }
    }
}

/// Selects shadow protocol V2 when the client offers its WebSocket subprotocol, and V1 otherwise.
///
/// The upgrade response echoes the subprotocol only for V2, so V2 clients can tell which version they got.
pub(crate) fn negotiate_shadow_protocol(
    ws: axum::extract::WebSocketUpgrade,
) -> (axum::extract::WebSocketUpgrade, ShadowProtocolVersion) {
    let ws = ws.protocols([SHADOW_PROTOCOL_V2]);
    let version = if ws.selected_protocol().is_some() {
        ShadowProtocolVersion::V2
    } else {
        ShadowProtocolVersion::V1
    };
    (ws, version)
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
    data_appended: watch::Receiver<RecordingStreamState>,
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
        data_appended,
    )
    .await
    .inspect_err(|e| error!(error = format!("{e:#}"), "Streaming file failed"))?;

    Ok(())
}

/// Returns once the clip at `index` can no longer receive data.
async fn wait_for_recording_clip_end(mut stream_state: watch::Receiver<RecordingStreamState>, index: usize) {
    let _ = stream_state.wait_for(|state| !state.is_active(index)).await;
}

async fn wait_for_terminal_stream_end(
    stream_state: watch::Receiver<RecordingStreamState>,
    index: usize,
    mut shutdown_signal: ShutdownSignal,
) {
    tokio::select! {
        () = wait_for_recording_clip_end(stream_state, index) => {}
        () = shutdown_signal.wait() => {}
    }
}

async fn setup_webm_streaming(
    stream_state: watch::Receiver<RecordingStreamState>,
    socket: WebSocket,
    shutdown_signal: ShutdownSignal,
    version: ShadowProtocolVersion,
) -> anyhow::Result<()> {
    let mut session_shutdown = shutdown_signal.clone();
    let (websocket_stream, close_handle) = crate::ws::handle_messages(
        socket,
        crate::ws::KeepAliveShutdownSignal(shutdown_signal),
        Duration::from_secs(45),
    );
    let start_source = move || async move { Ok(recording_event_stream(stream_state)) };
    let streaming_result = tokio::select! {
        result = stream_session(start_source, websocket_stream, SessionConfig::default(), version) => result,
        () = session_shutdown.wait() => return Ok(()),
    };

    match streaming_result {
        Err(error) => {
            close_handle.server_error("webm streaming failure".to_owned()).await;
            Err(error)
        }
        Ok(()) => {
            close_handle.normal_close().await;
            Ok(())
        }
    }
}

struct CurrentRecordingClip {
    index: usize,
    caught_up: bool,
}

/// Turns the recording manager’s view of one recording session into the events `video_streamer` consumes.
struct RecordingEventSource {
    stream_state: watch::Receiver<RecordingStreamState>,
    next_clip: usize,
    current_clip: Option<CurrentRecordingClip>,
    next_start_at: StartAt,
    ended: bool,
}

impl RecordingEventSource {
    fn new(mut stream_state: watch::Receiver<RecordingStreamState>) -> Self {
        let (next_clip, next_start_at) = {
            let state = stream_state.borrow_and_update();
            let last = state.clips.len().saturating_sub(1);
            match state.lifecycle {
                StreamLifecycle::Recording => (last, StartAt::LiveEdge),
                StreamLifecycle::Opening => (last, StartAt::Beginning),
                // The next clip, if any, starts with a reconnection.
                StreamLifecycle::Disconnected | StreamLifecycle::Ended => (state.clips.len(), StartAt::Beginning),
            }
        };

        Self {
            stream_state,
            next_clip,
            current_clip: None,
            next_start_at,
            ended: false,
        }
    }

    async fn wait_for_change(&mut self) -> anyhow::Result<()> {
        self.stream_state
            .changed()
            .await
            .context("recording stream state closed")
    }

    async fn next_event(&mut self) -> anyhow::Result<Option<RecordingEvent>> {
        if self.ended {
            return Ok(None);
        }

        loop {
            if let Some(current_clip) = self.current_clip.as_mut() {
                if !current_clip.caught_up {
                    current_clip.caught_up = true;
                    return Ok(Some(RecordingEvent::CaughtUp));
                }

                let index = current_clip.index;

                // Any change either appended data to this clip or ended it.
                self.wait_for_change().await?;
                if self.stream_state.borrow_and_update().is_active(index) {
                    return Ok(Some(RecordingEvent::DataAvailable));
                }

                self.current_clip = None;
                self.next_clip = index.checked_add(1).context("recording clip index overflow")?;
                return Ok(Some(RecordingEvent::ClipEnded));
            }

            let (next_path, opening, lifecycle) = {
                let state = self.stream_state.borrow_and_update();
                (
                    state.clips.get(self.next_clip).cloned(),
                    state.is_opening(self.next_clip),
                    state.lifecycle,
                )
            };

            if let Some(path) = next_path {
                if opening {
                    // Wait until the producer opened the clip file, so that it exists and was truncated.
                    self.wait_for_change().await?;
                    continue;
                }

                if path.extension() != Some(RecordingFileType::WebM.extension()) {
                    // A reconnection may switch to another format; the WebM stream ends there instead of failing.
                    debug!(%path, "Recording switched to a non-WebM clip; ending the WebM stream");
                    self.ended = true;
                    return Ok(Some(RecordingEvent::SessionEnded));
                }

                let file = File::open(&path)
                    .await
                    .with_context(|| format!("failed to open recording clip: {path}"))?;
                let file = file.into_std().await;
                let start_at = std::mem::replace(&mut self.next_start_at, StartAt::Beginning);
                let sequence = u64::try_from(self.next_clip).context("recording clip index does not fit in u64")?;
                self.current_clip = Some(CurrentRecordingClip {
                    index: self.next_clip,
                    caught_up: false,
                });
                return Ok(Some(RecordingEvent::ClipStarted {
                    sequence,
                    start_at,
                    clip: RecordingClip::new(file),
                }));
            }

            if lifecycle == StreamLifecycle::Ended {
                self.ended = true;
                return Ok(Some(RecordingEvent::SessionEnded));
            }

            self.wait_for_change().await?;
        }
    }
}

fn recording_event_stream(
    stream_state: watch::Receiver<RecordingStreamState>,
) -> impl Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static {
    stream::try_unfold(RecordingEventSource::new(stream_state), |mut source| async move {
        Ok(source.next_event().await?.map(|event| (event, source)))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    struct ScratchDirectory(camino::Utf8PathBuf);

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch_directory() -> ScratchDirectory {
        let scratch = camino::Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("streaming-tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&scratch).expect("create test directory");
        ScratchDirectory(scratch)
    }

    /// What the `/shadow` handshake route under test does.
    #[derive(Clone, Copy)]
    enum ShadowRoute {
        /// Negotiates, then sends the selected version as a text message.
        Negotiate,
        /// Rejects with `ShadowCloseCode::Forbidden`.
        Reject,
    }

    struct ShadowHandshake {
        /// The `Sec-WebSocket-Protocol` response header.
        echoed: Option<String>,
        /// The first frame’s opcode.
        opcode: u8,
        payload: Vec<u8>,
    }

    /// Performs a raw WebSocket handshake against `route` and reads the first frame.
    ///
    /// The handshake is written by hand because tungstenite rejects a response without a subprotocol when one was offered,
    /// although RFC 6455 and .NET accept it.
    async fn shadow_handshake(offered_protocols: Option<&str>, route: ShadowRoute) -> ShadowHandshake {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tower::Service as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let (io, _) = listener.accept().await.expect("accept");
            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                axum::Router::new()
                    .route(
                        "/shadow",
                        axum::routing::get(move |ws: axum::extract::WebSocketUpgrade| async move {
                            match route {
                                ShadowRoute::Negotiate => {
                                    let (ws, version) = negotiate_shadow_protocol(ws);
                                    let version = match version {
                                        ShadowProtocolVersion::V1 => "v1",
                                        ShadowProtocolVersion::V2 => "v2",
                                    };
                                    ws.on_upgrade(move |mut socket| async move {
                                        let _ = socket
                                            .send(axum::extract::ws::Message::Text(Utf8Bytes::from_static(version)))
                                            .await;
                                    })
                                }
                                ShadowRoute::Reject => reject_shadow(ws, ShadowCloseCode::Forbidden),
                            }
                        }),
                    )
                    .call(request)
            });
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(io), service)
                .await;
        });

        let mut client = tokio::net::TcpStream::connect(address).await.expect("connect");
        let protocol_header = offered_protocols
            .map(|protocols| format!("Sec-WebSocket-Protocol: {protocols}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET /shadow HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{protocol_header}\r\n"
        );
        client.write_all(request.as_bytes()).await.expect("write handshake");

        let mut received = Vec::new();
        let header_end = loop {
            let mut buffer = [0; 1024];
            let read = client.read(&mut buffer).await.expect("read handshake");
            assert!(0 < read, "server closed during the handshake");
            received.extend_from_slice(&buffer[..read]);
            if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = std::str::from_utf8(&received[..header_end]).expect("ASCII response head");
        assert!(head.starts_with("HTTP/1.1 101"), "unexpected response: {head}");
        let echoed = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sec-websocket-protocol")
                .then(|| value.trim().to_owned())
        });

        // The server sends one short, unmasked frame: FIN + opcode, payload length, payload.
        let mut frame = received[header_end..].to_vec();
        while frame.len() < 2 || frame.len() < 2 + usize::from(frame[1]) {
            let mut buffer = [0; 64];
            let read = client.read(&mut buffer).await.expect("read frame");
            assert!(0 < read, "server closed before sending a frame");
            frame.extend_from_slice(&buffer[..read]);
        }

        drop(client);
        let _ = server.await;
        ShadowHandshake {
            echoed,
            opcode: frame[0] & 0x0F,
            payload: frame[2..2 + usize::from(frame[1])].to_vec(),
        }
    }

    async fn negotiated_version(offered_protocols: Option<&str>) -> (Option<String>, String) {
        let handshake = shadow_handshake(offered_protocols, ShadowRoute::Negotiate).await;
        assert_eq!(handshake.opcode, 0x1, "expected a text frame");
        let selected = String::from_utf8(handshake.payload).expect("UTF-8 version");
        (handshake.echoed, selected)
    }

    #[rstest::rstest]
    #[case::offers_v2(Some("jrec-shadow.v2"), Some("jrec-shadow.v2"), "v2")]
    #[case::offers_v2_among_others(Some("jrec-shadow.v3, jrec-shadow.v2"), Some("jrec-shadow.v2"), "v2")]
    #[case::offers_nothing(None, None, "v1")]
    #[case::offers_an_unknown_protocol(Some("jrec-shadow.v3"), None, "v1")]
    #[tokio::test]
    async fn client_gets_the_shadow_protocol_it_offers(
        #[case] offered: Option<&str>,
        #[case] expected_echo: Option<&str>,
        #[case] expected_version: &str,
    ) {
        let (echoed, selected) = negotiated_version(offered).await;
        assert_eq!(echoed.as_deref(), expected_echo);
        assert_eq!(selected, expected_version);
    }

    #[tokio::test]
    async fn rejection_echoes_the_offer_so_browsers_see_the_close_code() {
        let handshake = shadow_handshake(Some("jrec-shadow.v2"), ShadowRoute::Reject).await;

        assert_eq!(handshake.echoed.as_deref(), Some("jrec-shadow.v2"));
        assert_eq!(handshake.opcode, 0x8, "expected a close frame");
        assert_eq!(handshake.payload[..2], 4003u16.to_be_bytes());
    }

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

    #[tokio::test]
    async fn terminal_clip_end_is_retained_before_waiting() {
        let state = RecordingStreamState::for_test(vec!["recording-0.cast".into()], StreamLifecycle::Recording);
        let (sender, receiver) = watch::channel(state);
        sender.send_modify(RecordingStreamState::mark_disconnected);

        tokio::time::timeout(Duration::from_millis(25), wait_for_recording_clip_end(receiver, 0))
            .await
            .expect("clip end should already be visible");
    }

    /// Simulates the recording manager’s reconnection: the clip list grows and the new clip opens.
    fn reconnect(sender: &watch::Sender<RecordingStreamState>, path: camino::Utf8PathBuf) {
        sender.send_modify(|state| {
            let mut clips = state.clips.as_ref().clone();
            clips.push(path);
            *state = RecordingStreamState::for_test(clips, StreamLifecycle::Opening);
        });
    }

    fn clip_started(event: Option<RecordingEvent>) -> (u64, StartAt) {
        match event {
            Some(RecordingEvent::ClipStarted { sequence, start_at, .. }) => (sequence, start_at),
            event => panic!("expected a clip start, got {event:?}"),
        }
    }

    #[tokio::test]
    async fn reconnect_waits_for_the_next_clip_before_ending_the_session() {
        let scratch = scratch_directory();
        let first_path = scratch.0.join("recording-0.webm");
        let second_path = scratch.0.join("recording-1.webm");
        fs::write(&first_path, b"first").expect("write first clip");
        fs::write(&second_path, b"second").expect("write second clip");

        let state = RecordingStreamState::for_test(vec![first_path], StreamLifecycle::Recording);
        let (sender, receiver) = watch::channel(state);
        let mut source = RecordingEventSource::new(receiver);

        let first = source.next_event().await.expect("read first start");
        assert_eq!(clip_started(first), (0, StartAt::LiveEdge));
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

        reconnect(&sender, second_path);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), source.next_event())
                .await
                .is_err(),
            "a clip whose file is not open must not start"
        );
        sender.send_modify(|state| state.lifecycle = StreamLifecycle::Recording);
        let second = source.next_event().await.expect("read second start");
        assert_eq!(clip_started(second), (1, StartAt::Beginning));
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
    async fn reconnect_to_another_format_ends_the_webm_stream_normally() {
        let scratch = scratch_directory();
        let webm_path = scratch.0.join("recording-0.webm");
        fs::write(&webm_path, b"webm").expect("write WebM clip");

        let state = RecordingStreamState::for_test(vec![webm_path], StreamLifecycle::Recording);
        let (sender, receiver) = watch::channel(state);
        let mut source = RecordingEventSource::new(receiver);

        assert_eq!(
            clip_started(source.next_event().await.expect("read clip start")),
            (0, StartAt::LiveEdge)
        );
        assert!(matches!(
            source.next_event().await.expect("catch up"),
            Some(RecordingEvent::CaughtUp)
        ));
        sender.send_modify(RecordingStreamState::mark_disconnected);
        assert!(matches!(
            source.next_event().await.expect("end WebM clip"),
            Some(RecordingEvent::ClipEnded)
        ));

        reconnect(&sender, scratch.0.join("recording-1.slog"));
        sender.send_modify(|state| state.lifecycle = StreamLifecycle::Recording);
        assert!(matches!(
            source.next_event().await.expect("end the WebM stream"),
            Some(RecordingEvent::SessionEnded)
        ));
        assert!(source.next_event().await.expect("finish source").is_none());
    }

    #[tokio::test]
    async fn catch_up_precedes_coalesced_append_markers() {
        let scratch = scratch_directory();
        let path = scratch.0.join("recording-0.webm");
        fs::write(&path, b"recording").expect("write clip");
        let state = RecordingStreamState::for_test(vec![path], StreamLifecycle::Recording);
        let (sender, receiver) = watch::channel(state);
        let mut source = RecordingEventSource::new(receiver);

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
