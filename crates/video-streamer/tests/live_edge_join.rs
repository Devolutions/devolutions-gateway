use std::io::{self, Read, Seek, SeekFrom};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use cadeau::xmf::recorder::Recorder;
use cadeau::xmf::vpx::{VpxCodec, VpxDecoder};
use ebml_iterable::TagDecoder;
use futures::{Sink, Stream};
use tokio::sync::mpsc;
use video_streamer::{RecordingClip, RecordingEvent, SessionConfig, ShadowProtocolVersion, StartAt, stream_session};
use webm_iterable::WebmIterator;
use webm_iterable::matroska_spec::{MatroskaSpec, SimpleBlock};

mod support;
use support::*;

const WIDTH: usize = 320;
const HEIGHT: usize = 240;
const SECONDS: u64 = 10;
/// Frames already recorded when the viewer joins; the rest arrive live.
const FRAMES_BEFORE_JOIN: usize = 6;

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

/// A recording file that the producer is still appending to: only the first `visible` bytes are readable.
struct GrowingClip {
    data: Arc<Vec<u8>>,
    visible: Arc<AtomicUsize>,
    position: usize,
}

impl Read for GrowingClip {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let end = self.visible.load(Ordering::Acquire).min(self.data.len());
        let read = end.saturating_sub(self.position).min(buffer.len());
        buffer[..read].copy_from_slice(&self.data[self.position..self.position + read]);
        self.position += read;
        Ok(read)
    }
}

impl Seek for GrowingClip {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let SeekFrom::Start(offset) = position else {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "only absolute seeks"));
        };
        self.position = usize::try_from(offset).map_err(io::Error::other)?;
        Ok(offset)
    }
}

/// Records one distinct picture per second, like a 1 fps recorder.
fn record_clip(test: &str) -> Vec<u8> {
    // Tests run in parallel: a per-test directory keeps their recorders off the same file.
    let dir = unique_temp_dir(&format!("video-streamer-{test}"));
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

/// Byte offset where the `index`-th video block (0-based) starts.
fn block_offset(clip: &[u8], index: usize) -> usize {
    let mut decoder = TagDecoder::<MatroskaSpec>::new(&[]);
    let mut input = BytesMut::from(clip);
    let mut blocks = 0;
    while let Some(positioned) = decoder.decode(&mut input).expect("decode clip") {
        if matches!(positioned.tag, MatroskaSpec::SimpleBlock(_)) {
            if blocks == index {
                return positioned.offset;
            }
            blocks += 1;
        }
    }
    panic!("clip has only {blocks} blocks");
}

struct OutputFrame {
    timestamp: i64,
    key_frame: bool,
    data: Vec<u8>,
}

fn output_frames(segment: &[u8]) -> Vec<OutputFrame> {
    let mut cluster_timestamp = 0i64;
    let mut frames = Vec::new();
    for tag in WebmIterator::new(io::Cursor::new(segment), &[]) {
        match tag {
            Ok(MatroskaSpec::Timestamp(timestamp)) => {
                cluster_timestamp = i64::try_from(timestamp).expect("small timestamp");
            }
            Ok(tag @ MatroskaSpec::SimpleBlock(_)) => {
                let block = SimpleBlock::try_from(&tag).expect("simple block");
                let mut data = block.read_frame_data().expect("frame data");
                assert_eq!(data.len(), 1, "laced block");
                frames.push(OutputFrame {
                    timestamp: cluster_timestamp + i64::from(block.timestamp),
                    key_frame: block.keyframe,
                    data: data.remove(0).data.to_vec(),
                });
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    frames
}

/// Streams a recording to one viewer and returns the WebM bytes of the first output segment.
///
/// The viewer joins when `visible_at_join` bytes are recorded. The rest of the clip is appended after the viewer got
/// its first frame.
async fn stream_clip(clip: Vec<u8>, visible_at_join: usize, start_at: StartAt) -> Vec<u8> {
    let data = Arc::new(clip);
    let visible = Arc::new(AtomicUsize::new(visible_at_join));
    let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
    for event in [
        RecordingEvent::ClipStarted {
            sequence: 0,
            start_at,
            clip: RecordingClip::new(GrowingClip {
                data: Arc::clone(&data),
                visible: Arc::clone(&visible),
                position: 0,
            }),
        },
        RecordingEvent::DataAvailable,
        RecordingEvent::CaughtUp,
    ] {
        event_sender.send(Ok(event)).expect("queue event");
    }
    let start_source = move || async move { Ok(futures::stream::poll_fn(move |cx| event_receiver.poll_recv(cx))) };

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
    let mut appended = false;
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
        if !appended && !output_frames(&segment).is_empty() {
            appended = true;
            visible.store(data.len(), Ordering::Release);
            for event in [
                RecordingEvent::DataAvailable,
                RecordingEvent::ClipEnded,
                RecordingEvent::SessionEnded,
            ] {
                event_sender.send(Ok(event)).expect("queue event");
            }
        }
        client_sender.send(Ok(Bytes::from_static(&[1]))).expect("send Pull");
    }
    drop(client_sender);
    server.await.expect("join server").expect("stream session");
    segment
}

/// Every output frame must decode in order from a fresh decoder, starting with the first key frame.
fn assert_decodes_from_scratch(frames: &[OutputFrame]) {
    let mut decoder = VpxDecoder::builder()
        .threads(1)
        .width(0)
        .height(0)
        .codec(VpxCodec::VP8)
        .build()
        .expect("build decoder");
    for (index, frame) in frames.iter().enumerate() {
        decoder
            .decode(&frame.data)
            .unwrap_or_else(|error| panic!("output frame {index} does not decode: {error}"));
        let picture = decoder
            .next_frame()
            .unwrap_or_else(|error| panic!("output frame {index} has no picture: {error}"));
        assert_eq!(
            (picture.width(), picture.height()),
            (
                u32::try_from(WIDTH).expect("small"),
                u32::try_from(HEIGHT).expect("small")
            )
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_edge_viewer_starts_at_the_live_picture() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }
    let clip = record_clip("live-edge-join");
    let source_timestamps = extract_block_absolute_timestamps_ms(&clip).expect("source timestamps");
    assert_eq!(source_timestamps.len(), usize::try_from(SECONDS).expect("small"));
    let join_offset = block_offset(&clip, FRAMES_BEFORE_JOIN);

    let segment = stream_clip(clip, join_offset, StartAt::LiveEdge).await;

    // The viewer starts at the last frame recorded before it joined, not at the group of pictures behind it.
    let frames = output_frames(&segment);
    let timestamps: Vec<i64> = frames.iter().map(|frame| frame.timestamp).collect();
    let live_picture = source_timestamps[FRAMES_BEFORE_JOIN - 1];
    let expected: Vec<i64> = source_timestamps[FRAMES_BEFORE_JOIN - 1..]
        .iter()
        .map(|timestamp| timestamp - live_picture)
        .collect();
    assert_eq!(timestamps, expected);
    assert!(frames[0].key_frame, "the first output frame must be a key frame");
    assert!(
        frames[1..].iter().all(|frame| !frame.key_frame),
        "later frames reference the new key frame"
    );
    assert_decodes_from_scratch(&frames);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn beginning_viewer_gets_every_frame() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }
    let clip = record_clip("beginning-join");
    let source_timestamps = extract_block_absolute_timestamps_ms(&clip).expect("source timestamps");
    let join_offset = block_offset(&clip, FRAMES_BEFORE_JOIN);

    let segment = stream_clip(clip, join_offset, StartAt::Beginning).await;

    let frames = output_frames(&segment);
    assert_eq!(frames.len(), source_timestamps.len());
    assert!(frames[0].key_frame);
    assert_decodes_from_scratch(&frames);
}
