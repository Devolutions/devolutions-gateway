use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Sink, Stream, StreamExt as _, stream};
use tokio::sync::{mpsc, oneshot};

use super::message::{ClientMessage, ServerMessage, decode_client_message, encode_server_message};
use super::segments::SessionSegments;
use super::transport::CodecTransport;
use super::*;
use crate::normalizer::{SegmentEvent, SegmentInfo};
use crate::session::{RecordingEvent, RecordingSource};

struct ChannelTransport {
    incoming: mpsc::UnboundedReceiver<Result<Bytes, std::io::Error>>,
    outgoing: mpsc::UnboundedSender<Bytes>,
}

struct ClientSender(mpsc::UnboundedSender<Result<Bytes, std::io::Error>>);

impl ClientSender {
    fn send(&self, message: Bytes) -> Result<(), mpsc::error::SendError<Result<Bytes, std::io::Error>>> {
        self.0.send(Ok(message))
    }

    fn send_error(&self, error: std::io::Error) -> Result<(), mpsc::error::SendError<Result<Bytes, std::io::Error>>> {
        self.0.send(Err(error))
    }
}

impl Stream for ChannelTransport {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}

impl Sink<Bytes> for ChannelTransport {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, message: Bytes) -> Result<(), Self::Error> {
        self.outgoing
            .send(message)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "test receiver closed"))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn channel_transport() -> (ChannelTransport, ClientSender, mpsc::UnboundedReceiver<Bytes>) {
    let (client_sender, incoming) = mpsc::unbounded_channel();
    let (outgoing, client_receiver) = mpsc::unbounded_channel();
    (
        ChannelTransport { incoming, outgoing },
        ClientSender(client_sender),
        client_receiver,
    )
}

async fn receive_response(receiver: &mut mpsc::UnboundedReceiver<Bytes>) -> Bytes {
    tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await
        .expect("timed out waiting for server response")
        .expect("server response channel closed")
}

struct TestRecordingSource<F>(F);

fn recording_source<F>(start: F) -> TestRecordingSource<F> {
    TestRecordingSource(start)
}

impl<F, Fut, S> RecordingSource for TestRecordingSource<F>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<S>> + Send + 'static,
    S: Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static,
{
    type Stream = S;
    type Start = Fut;

    fn start(self) -> Self::Start {
        self.0()
    }
}

fn segment_source(events: impl IntoIterator<Item = anyhow::Result<SegmentEvent>>) -> Vec<anyhow::Result<SegmentEvent>> {
    events.into_iter().collect()
}

async fn stream_segment_source<T, E, S>(transport: T, source: S) -> anyhow::Result<()>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
    S: Stream<Item = anyhow::Result<SegmentEvent>> + Send + 'static,
{
    let mut transport = SessionTransport::new(CodecTransport::new(transport));
    let mut segments = SessionSegments::new(crate::normalizer::test_session(source));
    receive_expected_request(&mut transport, ClientMessage::Start)
        .await?
        .ok_or_else(|| anyhow::anyhow!("test transport closed before Start"))?;

    let stream_result = run_started_session(&mut transport, &mut segments).await;
    let shutdown_result = segments.into_inner().shutdown().await;

    match (stream_result, shutdown_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[tokio::test]
async fn invalid_initial_request_does_not_start_or_poll_source() {
    let start_calls = Arc::new(AtomicUsize::new(0));
    let poll_calls = Arc::new(AtomicUsize::new(0));
    let source = {
        let start_calls = Arc::clone(&start_calls);
        let poll_calls = Arc::clone(&poll_calls);
        recording_source(move || {
            start_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok::<_, anyhow::Error>(stream::poll_fn(move |_cx| {
                    poll_calls.fetch_add(1, Ordering::SeqCst);
                    Poll::Pending
                }))
            }
        })
    };
    let (transport, client_sender, mut client_receiver) = channel_transport();
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send invalid initial Pull");
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    assert_eq!(receive_response(&mut client_receiver).await[0], 2);
    assert!(task.await.expect("stream task panicked").is_err());
    assert_eq!(start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(poll_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn undecodable_request_while_idle_sends_one_error() {
    let source =
        recording_source(|| async { Ok::<_, anyhow::Error>(stream::empty::<anyhow::Result<RecordingEvent>>()) });
    let (transport, client_sender, mut client_receiver) = channel_transport();
    client_sender
        .send(Bytes::from_static(b"\x00\x01"))
        .expect("send undecodable request");
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    assert_eq!(receive_response(&mut client_receiver).await[0], 2);
    assert!(task.await.expect("stream task panicked").is_err());
    assert!(client_receiver.try_recv().is_err());
}

#[tokio::test]
async fn transport_error_while_idle_returns_without_response() {
    let source =
        recording_source(|| async { Ok::<_, anyhow::Error>(stream::empty::<anyhow::Result<RecordingEvent>>()) });
    let (transport, client_sender, mut client_receiver) = channel_transport();
    client_sender
        .send_error(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "transport failed",
        ))
        .expect("send transport error");
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    assert!(task.await.expect("stream task panicked").is_err());
    assert!(client_receiver.try_recv().is_err());
}

#[tokio::test]
async fn valid_start_launches_source_before_polling_the_underlying_source() {
    let start_calls = Arc::new(AtomicUsize::new(0));
    let (polled_sender, polled_receiver) = oneshot::channel();
    let (release_sender, mut release_receiver) = oneshot::channel();
    let (dropped_sender, dropped_receiver) = oneshot::channel();
    let source = {
        let start_calls = Arc::clone(&start_calls);
        recording_source(move || {
            start_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                let drop_signal = DropSignal(Some(dropped_sender));
                let mut polled_sender = Some(polled_sender);
                let mut emitted = false;
                Ok::<_, anyhow::Error>(stream::poll_fn(move |cx| {
                    let _ = &drop_signal;
                    if let Some(sender) = polled_sender.take() {
                        let _ = sender.send(());
                    }
                    if emitted {
                        return Poll::Ready(None);
                    }
                    match Pin::new(&mut release_receiver).poll(cx) {
                        Poll::Ready(_) => {
                            emitted = true;
                            Poll::Ready(Some(Ok(RecordingEvent::SessionEnded)))
                        }
                        Poll::Pending => Poll::Pending,
                    }
                }))
            }
        })
    };
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    assert_eq!(start_calls.load(Ordering::SeqCst), 0);
    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    polled_receiver.await.expect("underlying source was polled");
    assert_eq!(start_calls.load(Ordering::SeqCst), 1);

    client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    release_sender.send(()).expect("release source");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
    dropped_receiver.await.expect("running source was dropped");
}

#[tokio::test]
async fn aborting_running_session_drops_source() {
    let (polled_sender, polled_receiver) = oneshot::channel();
    let (dropped_sender, dropped_receiver) = oneshot::channel();
    let source = recording_source(move || async move {
        let drop_signal = DropSignal(Some(dropped_sender));
        let mut polled_sender = Some(polled_sender);
        Ok::<_, anyhow::Error>(stream::poll_fn(move |_cx| {
            let _ = &drop_signal;
            if let Some(sender) = polled_sender.take() {
                let _ = sender.send(());
            }
            Poll::Pending
        }))
    });
    let (transport, client_sender, _client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    polled_receiver.await.expect("underlying source was polled");
    task.abort();
    assert!(task.await.expect_err("aborted stream must not finish").is_cancelled());
    dropped_receiver.await.expect("running source was dropped");
}

#[tokio::test]
async fn undecodable_request_waits_for_current_media_and_rejects_only_that_request() {
    let (media_waiting_sender, media_waiting_receiver) = oneshot::channel();
    let (media_release_sender, media_release_receiver) = oneshot::channel();
    let source = stream::iter([Ok(SegmentEvent::Begin(SegmentInfo {
        sequence: 0,
        width: 640,
        height: 480,
    }))])
    .chain(stream::once(async move {
        media_waiting_sender.send(()).expect("signal pending media");
        media_release_receiver.await.expect("release media");
        Ok(SegmentEvent::Data(Bytes::from_static(b"chunk")))
    }))
    .chain(stream::pending());
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segment_source(transport, source));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    media_waiting_receiver.await.expect("media was polled");
    client_sender
        .send(Bytes::from_static(b"\xFF"))
        .expect("send undecodable request");
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send unread Pull");
    assert!(client_receiver.try_recv().is_err());
    media_release_sender.send(()).expect("release media");

    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00chunk")
    );
    assert_eq!(receive_response(&mut client_receiver).await[0], 2);
    assert!(task.await.expect("stream task panicked").is_err());
    assert_eq!(client_receiver.recv().await, None);
}

#[tokio::test]
async fn transport_error_waits_for_current_media_response() {
    let (media_waiting_sender, media_waiting_receiver) = oneshot::channel();
    let (media_release_sender, media_release_receiver) = oneshot::channel();
    let source = stream::iter([Ok(SegmentEvent::Begin(SegmentInfo {
        sequence: 0,
        width: 640,
        height: 480,
    }))])
    .chain(stream::once(async move {
        media_waiting_sender.send(()).expect("signal pending media");
        media_release_receiver.await.expect("release media");
        Ok(SegmentEvent::Data(Bytes::from_static(b"chunk")))
    }))
    .chain(stream::pending());
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segment_source(transport, source));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    media_waiting_receiver.await.expect("media was polled");
    client_sender
        .send_error(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "transport failed",
        ))
        .expect("send transport error");
    assert!(client_receiver.try_recv().is_err());
    media_release_sender.send(()).expect("release media");

    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00chunk")
    );
    assert!(task.await.expect("stream task panicked").is_err());
    assert_eq!(client_receiver.recv().await, None);
}

#[tokio::test]
async fn disconnect_before_start_does_not_start_source() {
    let start_calls = Arc::new(AtomicUsize::new(0));
    let source = {
        let start_calls = Arc::clone(&start_calls);
        recording_source(move || {
            start_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, anyhow::Error>(stream::empty::<anyhow::Result<RecordingEvent>>()) }
        })
    };
    let (transport, client_sender, _client_receiver) = channel_transport();
    drop(client_sender);
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    task.await
        .expect("stream task panicked")
        .expect("disconnect should end the stream cleanly");
    assert_eq!(start_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn source_starts_once_after_valid_start() {
    let start_calls = Arc::new(AtomicUsize::new(0));
    let source = {
        let start_calls = Arc::clone(&start_calls);
        recording_source(move || {
            start_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, anyhow::Error>(stream::iter([Ok(RecordingEvent::SessionEnded)])) }
        })
    };
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
    assert_eq!(start_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn pull_sent_during_launch_is_unread_after_stream_end() {
    let (started_sender, started_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = oneshot::channel();
    let source = recording_source(move || async move {
        started_sender.send(()).expect("signal startup");
        release_receiver.await.expect("release startup");
        Ok::<_, anyhow::Error>(stream::iter([Ok(RecordingEvent::SessionEnded)]))
    });
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send unread Pull");
    started_receiver.await.expect("startup was polled");
    assert!(
        client_receiver.try_recv().is_err(),
        "launch must not respond before the source is ready"
    );
    release_sender.send(()).expect("release startup");

    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
    assert_eq!(client_receiver.recv().await, None);
}

#[tokio::test]
async fn startup_failure_rejects_the_accepted_start_only() {
    let (started_sender, started_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = oneshot::channel();
    let source = recording_source(move || async move {
        started_sender.send(()).expect("signal startup");
        release_receiver.await.expect("release startup");
        Err::<stream::Empty<anyhow::Result<RecordingEvent>>, _>(anyhow::anyhow!("startup failed"))
    });
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send unread Pull");
    started_receiver.await.expect("startup was polled");
    release_sender.send(()).expect("release startup");

    assert_eq!(receive_response(&mut client_receiver).await[0], 2);
    assert!(
        client_receiver.try_recv().is_err(),
        "unread Pull must not receive a startup error"
    );
    assert!(task.await.expect("stream task panicked").is_err());
    assert_eq!(client_receiver.recv().await, None);
}

#[tokio::test]
async fn disconnect_waits_for_current_media_response() {
    let (media_waiting_sender, media_waiting_receiver) = oneshot::channel();
    let (media_release_sender, media_release_receiver) = oneshot::channel();
    let source = stream::iter([Ok(SegmentEvent::Begin(SegmentInfo {
        sequence: 0,
        width: 640,
        height: 480,
    }))])
    .chain(stream::once(async move {
        media_waiting_sender.send(()).expect("signal pending media");
        media_release_receiver.await.expect("release media");
        Ok(SegmentEvent::Data(Bytes::from_static(b"chunk")))
    }))
    .chain(stream::pending());
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segment_source(transport, source));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    media_waiting_receiver.await.expect("media was polled");
    drop(client_sender);
    assert!(client_receiver.try_recv().is_err());
    media_release_sender.send(()).expect("release media");

    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00chunk")
    );
    task.await
        .expect("stream task panicked")
        .expect("disconnect should end the stream cleanly");
    assert_eq!(client_receiver.recv().await, None);
}

#[tokio::test]
async fn abort_during_startup_drops_pending_source() {
    let (dropped_sender, dropped_receiver) = oneshot::channel();
    let (started_sender, started_receiver) = oneshot::channel();
    let source = recording_source(move || async move {
        let _drop_signal = DropSignal(Some(dropped_sender));
        started_sender.send(()).expect("signal startup");
        futures_util::future::pending::<()>().await;
        Ok::<_, anyhow::Error>(stream::empty::<anyhow::Result<RecordingEvent>>())
    });
    let (transport, client_sender, _client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segments(transport, source, SessionConfig::default()));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    started_receiver.await.expect("startup was polled");
    task.abort();
    assert!(task.await.expect_err("aborted stream must not finish").is_cancelled());
    dropped_receiver.await.expect("pending source was dropped");
}

#[test]
fn protocol_codes_are_stable() {
    assert_eq!(
        encode_server_message(ServerMessage::Metadata),
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    assert_eq!(
        encode_server_message(ServerMessage::SegmentStarted),
        Bytes::from_static(b"\x04{\"codec\":\"vp8\"}")
    );
    assert_eq!(
        encode_server_message(ServerMessage::Chunk(Bytes::from_static(b"webm"))),
        Bytes::from_static(b"\x00webm")
    );
    assert_eq!(
        encode_server_message(ServerMessage::StreamEnded),
        Bytes::from_static(b"\x03")
    );
}

#[test]
fn client_messages_require_one_complete_transport_message() {
    assert_eq!(
        decode_client_message(b"\x00").expect("decode start"),
        ClientMessage::Start
    );
    assert_eq!(
        decode_client_message(b"\x01").expect("decode pull"),
        ClientMessage::Pull
    );
    assert!(decode_client_message(b"\x02").is_err());
    assert!(decode_client_message(b"\x00\x01").is_err());
    assert!(decode_client_message(b"").is_err());
}

#[tokio::test]
async fn transport_adapts_typed_messages_at_the_wire_boundary() {
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let mut transport = SessionTransport::new(CodecTransport::new(transport));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        transport
            .recv()
            .await
            .expect("transport message")
            .expect("decoded client message"),
        ClientMessage::Start
    );

    transport
        .send(ServerMessage::StreamEnded)
        .await
        .expect("send typed server message");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
}

#[tokio::test]
async fn segment_end_is_implicit_on_the_wire() {
    let events = [
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 0,
            width: 640,
            height: 480,
        })),
        Ok(SegmentEvent::Data(Bytes::from_static(b"first"))),
        Ok(SegmentEvent::End),
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 1,
            width: 800,
            height: 600,
        })),
        Ok(SegmentEvent::Data(Bytes::from_static(b"second"))),
        Ok(SegmentEvent::End),
    ];
    let mut segments = SessionSegments::new(stream::iter(events));

    assert_eq!(
        segments.next().await.expect("first data"),
        ServerMessage::Chunk(Bytes::from_static(b"first"))
    );
    assert_eq!(
        segments.next().await.expect("second begin"),
        ServerMessage::SegmentStarted
    );
    assert_eq!(
        segments.next().await.expect("second data"),
        ServerMessage::Chunk(Bytes::from_static(b"second"))
    );
    assert_eq!(segments.next().await.expect("stream end"), ServerMessage::StreamEnded);
}

#[tokio::test]
async fn multi_segment_protocol_transcript_is_stable() {
    let source = segment_source([
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 0,
            width: 640,
            height: 480,
        })),
        Ok(SegmentEvent::Data(Bytes::from_static(b"first"))),
        Ok(SegmentEvent::End),
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 1,
            width: 800,
            height: 600,
        })),
        Ok(SegmentEvent::Data(Bytes::from_static(b"second"))),
        Ok(SegmentEvent::End),
    ]);
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segment_source(transport, stream::iter(source)));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );

    for expected in [
        Bytes::from_static(b"\x00first"),
        Bytes::from_static(b"\x04{\"codec\":\"vp8\"}"),
        Bytes::from_static(b"\x00second"),
        Bytes::from_static(b"\x03"),
    ] {
        client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
        assert_eq!(receive_response(&mut client_receiver).await, expected);
    }

    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
}

#[tokio::test]
async fn buffered_pulls_are_served_in_order() {
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let source = segment_source([
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 0,
            width: 640,
            height: 480,
        })),
        Ok(SegmentEvent::Data(Bytes::from_static(b"first"))),
        Ok(SegmentEvent::Data(Bytes::from_static(b"second"))),
        Ok(SegmentEvent::End),
    ]);
    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    for _ in 0..3 {
        client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    }
    let task = tokio::spawn(stream_segment_source(transport, stream::iter(source)));

    assert_eq!(receive_response(&mut client_receiver).await[0], 1);
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00first")
    );
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00second")
    );
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
}

#[tokio::test]
async fn buffered_pull_is_read_after_the_current_media_response() {
    let (media_waiting_sender, media_waiting_receiver) = oneshot::channel();
    let (media_release_sender, media_release_receiver) = oneshot::channel();
    let source = stream::iter([Ok(SegmentEvent::Begin(SegmentInfo {
        sequence: 0,
        width: 640,
        height: 480,
    }))])
    .chain(stream::once(async move {
        media_waiting_sender.send(()).expect("signal pending media");
        media_release_receiver.await.expect("release media");
        Ok(SegmentEvent::Data(Bytes::from_static(b"chunk")))
    }))
    .chain(stream::iter([Ok(SegmentEvent::End)]));
    let (transport, client_sender, mut client_receiver) = channel_transport();
    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    let task = tokio::spawn(stream_segment_source(transport, source));

    assert_eq!(receive_response(&mut client_receiver).await[0], 1);
    client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    media_waiting_receiver.await.expect("media was polled");
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send buffered Pull");
    assert!(client_receiver.try_recv().is_err());
    media_release_sender.send(()).expect("release media");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00chunk")
    );
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
}

#[tokio::test]
async fn wrong_state_request_waits_for_current_media_and_sends_one_error() {
    let (media_waiting_sender, media_waiting_receiver) = oneshot::channel();
    let (media_release_sender, media_release_receiver) = oneshot::channel();
    let source = stream::iter([Ok(SegmentEvent::Begin(SegmentInfo {
        sequence: 0,
        width: 640,
        height: 480,
    }))])
    .chain(stream::once(async move {
        media_waiting_sender.send(()).expect("signal pending media");
        media_release_receiver.await.expect("release media");
        Ok(SegmentEvent::Data(Bytes::from_static(b"chunk")))
    }))
    .chain(stream::pending());
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let task = tokio::spawn(stream_segment_source(transport, source));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    client_sender.send(Bytes::from_static(b"\x01")).expect("send Pull");
    media_waiting_receiver.await.expect("media was polled");
    client_sender
        .send(Bytes::from_static(b"\x00"))
        .expect("send Start in running state");
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send unread Pull");
    assert!(client_receiver.try_recv().is_err());
    media_release_sender.send(()).expect("release media");

    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00chunk")
    );
    assert_eq!(receive_response(&mut client_receiver).await[0], 2);
    assert!(task.await.expect("stream task panicked").is_err());
    assert_eq!(client_receiver.recv().await, None);
}

#[tokio::test]
async fn first_segment_sequence_must_be_zero() {
    let mut segments = SessionSegments::new(stream::iter([Ok(SegmentEvent::Begin(SegmentInfo {
        sequence: 1,
        width: 640,
        height: 480,
    }))]));

    let error = segments.next().await.expect_err("nonzero first sequence must fail");

    assert!(
        format!("{error:#}").contains("segment sequence is not contiguous"),
        "{error:#}"
    );
}

#[tokio::test]
async fn segment_sequence_gap_is_rejected() {
    let mut segments = SessionSegments::new(stream::iter([
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 0,
            width: 640,
            height: 480,
        })),
        Ok(SegmentEvent::End),
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 2,
            width: 800,
            height: 600,
        })),
    ]));

    let error = segments.next().await.expect_err("segment sequence gap must fail");

    assert!(
        format!("{error:#}").contains("segment sequence is not contiguous"),
        "{error:#}"
    );
}

#[tokio::test]
async fn stream_end_answers_current_request_only() {
    let (transport, client_sender, mut client_receiver) = channel_transport();
    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send unread Pull");
    let source = stream::empty::<anyhow::Result<SegmentEvent>>();
    let task = tokio::spawn(stream_segment_source(transport, source));

    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
    assert_eq!(client_receiver.recv().await, None);
}

#[tokio::test]
async fn each_request_receives_exactly_one_response() {
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let source = segment_source([
        Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 0,
            width: 640,
            height: 480,
        })),
        Ok(SegmentEvent::Data(Bytes::from_static(b"chunk"))),
        Ok(SegmentEvent::End),
    ]);
    let task = tokio::spawn(stream_segment_source(transport, stream::iter(source)));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    assert_eq!(receive_response(&mut client_receiver).await[0], 1);
    assert!(
        client_receiver.try_recv().is_err(),
        "server sent a response without another request"
    );

    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send first Pull");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x00chunk")
    );
    assert!(
        client_receiver.try_recv().is_err(),
        "server sent a response without another request"
    );

    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send final Pull");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x03")
    );
    task.await
        .expect("stream task panicked")
        .expect("stream session failed");
}

#[tokio::test]
async fn segment_failure_sends_one_error_for_the_current_request() {
    let (transport, client_sender, mut client_receiver) = channel_transport();
    let source = segment_source([Err(anyhow::anyhow!("test segment failure"))]);
    let task = tokio::spawn(stream_segment_source(transport, stream::iter(source)));

    client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
    client_sender
        .send(Bytes::from_static(b"\x01"))
        .expect("send unread Pull");
    assert_eq!(
        receive_response(&mut client_receiver).await,
        Bytes::from_static(b"\x01{\"codec\":\"vp8\"}")
    );
    let response = receive_response(&mut client_receiver).await;
    assert_eq!(response[0], 2);
    assert!(task.await.expect("stream task panicked").is_err());
    assert_eq!(
        client_receiver.recv().await,
        None,
        "error must not be followed by StreamEnded"
    );
}
