use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use cadeau::xmf::recorder::Recorder;
use futures::{Sink, Stream};
use tokio::sync::mpsc;
use video_streamer::{RecordingClip, RecordingEvent, SessionConfig, ShadowProtocolVersion, StartAt, stream_session};

mod support;
use support::*;

const WIDTH: usize = 320;
const HEIGHT: usize = 240;
const SECONDS: u64 = 10;

struct ChannelTransport {
    incoming: mpsc::UnboundedReceiver<Result<Bytes, io::Error>>,
    outgoing: mpsc::UnboundedSender<Bytes>,
}

impl Stream for ChannelTransport {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().incoming.poll_recv(cx)
    }
}

impl Sink<Bytes> for ChannelTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.outgoing
            .send(item)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Records one distinct picture per second, like a 1 fps recorder.
fn record_clip() -> Vec<u8> {
    let dir = unique_temp_dir("video-streamer-live-edge-join");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("clip.webm");
    let mut recorder = Recorder::builder(WIDTH, HEIGHT)
        .frame_rate(1)
        .current_time(0)
        .init(&path)
        .expect("init recorder");
    for second in 0..SECONDS {
        recorder.set_current_time(second * 1000);
        let value = u8::try_from(20 + second * 20).expect("small value");
        let picture = vec![value; WIDTH * HEIGHT * 4];
        recorder
            .update_frame(&picture, 0, 0, WIDTH, HEIGHT, WIDTH * 4)
            .expect("update frame");
        recorder.timeout();
    }
    drop(recorder);
    let bytes = std::fs::read(&path).expect("read clip");
    let _ = std::fs::remove_dir_all(dir);
    bytes
}

/// Streams a complete clip to a viewer that joins at `start_at`, and returns the WebM bytes of the first segment.
async fn stream_clip(clip: Vec<u8>, start_at: StartAt) -> Vec<u8> {
    let start_source = move || async move {
        Ok(futures::stream::iter([
            Ok(RecordingEvent::ClipStarted {
                sequence: 0,
                start_at,
                clip: RecordingClip::new(io::Cursor::new(clip)),
            }),
            Ok(RecordingEvent::DataAvailable),
            Ok(RecordingEvent::CaughtUp),
            Ok(RecordingEvent::ClipEnded),
            Ok(RecordingEvent::SessionEnded),
        ]))
    };

    let (client_sender, client_receiver) = mpsc::unbounded_channel();
    let (server_sender, mut server_receiver) = mpsc::unbounded_channel();
    let transport = ChannelTransport {
        incoming: client_receiver,
        outgoing: server_sender,
    };
    client_sender.send(Ok(Bytes::from_static(&[0]))).expect("send Start");
    client_sender.send(Ok(Bytes::from_static(&[1]))).expect("send Pull");

    let config = SessionConfig {
        encoder_threads: 1,
        adaptive_frame_skip: false,
    };
    let server = tokio::spawn(stream_session(
        start_source,
        transport,
        config,
        ShadowProtocolVersion::V2,
    ));

    let mut segment = Vec::new();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(30), server_receiver.recv())
            .await
            .expect("server message in time")
            .expect("server message");
        let (kind, payload) = parse_server_message(&message);
        match kind {
            0x00 => segment.extend_from_slice(payload),
            0x01 => {}
            0x03 => break,
            other => panic!("unexpected server message {other}"),
        }
        client_sender.send(Ok(Bytes::from_static(&[1]))).expect("send Pull");
    }
    drop(client_sender);
    server.await.expect("join server").expect("stream session");
    segment
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_edge_viewer_starts_at_the_live_picture() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }
    let clip = record_clip();
    let source_timestamps = extract_block_absolute_timestamps_ms(&clip).expect("source timestamps");
    assert_eq!(source_timestamps.len(), usize::try_from(SECONDS).expect("small"));

    let segment = stream_clip(clip, StartAt::LiveEdge).await;

    // The joining viewer gets only the live picture, at time 0, not the group of pictures behind it.
    let output_timestamps = extract_block_absolute_timestamps_ms(&segment).expect("output timestamps");
    assert_eq!(output_timestamps, vec![0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn beginning_viewer_gets_every_frame() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }
    let clip = record_clip();
    let source_timestamps = extract_block_absolute_timestamps_ms(&clip).expect("source timestamps");

    let segment = stream_clip(clip, StartAt::Beginning).await;

    let output_timestamps = extract_block_absolute_timestamps_ms(&segment).expect("output timestamps");
    assert_eq!(output_timestamps.len(), source_timestamps.len());
}
