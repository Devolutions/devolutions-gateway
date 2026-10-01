//! Measures the pipeline Gateway ships: one recording through `stream_session`, pulled to the end like a viewer would.

use std::io::{self, Write as _};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use futures::channel::mpsc;
use futures::{Sink, SinkExt as _, Stream, StreamExt as _, stream};
use video_streamer::{RecordingClip, RecordingEvent, SessionConfig, ShadowProtocolVersion, StartAt, stream_session};

const START: &[u8] = &[0];
const PULL: &[u8] = &[1];
const ERROR: u8 = 2;
const STREAM_ENDED: u8 = 3;

/// The server side of an in-memory WebSocket: client requests in, server responses out.
struct ServerTransport {
    requests: mpsc::UnboundedReceiver<Bytes>,
    responses: mpsc::UnboundedSender<Bytes>,
}

impl Stream for ServerTransport {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.requests.poll_next_unpin(cx).map(|request| request.map(Ok))
    }
}

impl Sink<Bytes> for ServerTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, response: Bytes) -> Result<(), Self::Error> {
        self.responses
            .unbounded_send(response)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client is gone"))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Streams `recording` as one finished input clip and returns the WebM bytes the viewer received.
async fn stream_recording(recording: &'static [u8]) -> u64 {
    let (mut request_sender, requests) = mpsc::unbounded();
    let (responses, mut response_receiver) = mpsc::unbounded();
    let transport = ServerTransport { requests, responses };

    let start_source = move || async move {
        let events = [
            RecordingEvent::ClipStarted {
                sequence: 0,
                start_at: StartAt::Beginning,
                clip: RecordingClip::new(io::Cursor::new(recording)),
            },
            RecordingEvent::CaughtUp,
            RecordingEvent::ClipEnded,
            RecordingEvent::SessionEnded,
        ];
        Ok(stream::iter(events.map(Ok)))
    };
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

    request_sender
        .send(Bytes::from_static(START))
        .await
        .expect("send Start");
    let mut received = 0u64;
    while let Some(response) = response_receiver.next().await {
        match response.first() {
            Some(&STREAM_ENDED) => break,
            Some(&ERROR) => panic!("stream failed: {:?}", String::from_utf8_lossy(&response[1..])),
            _ => received += u64::try_from(response.len()).expect("response length fits in u64"),
        }
        request_sender.send(Bytes::from_static(PULL)).await.expect("send Pull");
    }

    server.await.expect("server task").expect("stream session");
    received
}

fn bench_stream_session(c: &mut Criterion) {
    let Ok(path) = std::env::var("DGATEWAY_LIB_XMF_PATH") else {
        let _ = writeln!(io::stdout(), "DGATEWAY_LIB_XMF_PATH not set; skipping benchmarks");
        return;
    };
    // SAFETY: This is how the project loads XMF elsewhere.
    if let Err(error) = unsafe { cadeau::xmf::init(&path) } {
        let _ = writeln!(io::stdout(), "failed to initialize XMF from {path}: {error:#}");
        return;
    }

    // The asset is supplied locally, like the other video-streamer benchmarks and ignored tests.
    let asset = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testing-assets")
        .join("uncued-recording.webm");
    let recording: &'static [u8] = match std::fs::read(&asset) {
        Ok(recording) => recording.leak(),
        Err(error) => {
            let _ = writeln!(
                io::stdout(),
                "{} not readable ({error}); skipping benchmarks",
                asset.display()
            );
            return;
        }
    };
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("stream_session");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));
    group.bench_function("uncued_recording_to_stream_end", |b| {
        b.iter_custom(|iterations| {
            let start = Instant::now();
            for _ in 0..iterations {
                let received = runtime.block_on(stream_recording(recording));
                assert!(0 < received, "the viewer received no media");
            }
            start.elapsed()
        });
    });
    group.finish();
}

criterion_group!(benches, bench_stream_session);
criterion_main!(benches);
