use std::collections::VecDeque;
use std::error::Error;
use std::pin::Pin;

use anyhow::Context as _;
use bytes::{BufMut as _, Bytes, BytesMut};
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};

use crate::normalizer::{SegmentEvent, SegmentInfo};

const MAX_QUEUED_PULLS: usize = 1;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ServerMessage {
    Chunk(Bytes),
    SegmentStarted(SegmentInfo),
    Error(UserFriendlyError),
    StreamEnded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientMessage {
    Start,
    Pull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UserFriendlyError {
    UnexpectedError,
}

impl UserFriendlyError {
    fn as_str(&self) -> &'static str {
        match self {
            Self::UnexpectedError => "UnexpectedError",
        }
    }
}

pub(crate) async fn stream_segments<T, S, E>(mut transport: T, segments: S) -> anyhow::Result<()>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    S: Stream<Item = anyhow::Result<SegmentEvent>>,
    E: Error + Send + Sync + 'static,
{
    tokio::pin!(segments);
    let mut expected = ClientMessage::Start;
    let mut segment_state = SegmentState::AwaitingBegin { next_sequence: 0 };
    let mut queued_pulls = VecDeque::new();

    loop {
        let message = if let Some(message) = queued_pulls.pop_front() {
            Ok(message)
        } else {
            let Some(message) = transport.next().await else {
                return Ok(());
            };
            let message = message
                .map_err(anyhow::Error::new)
                .context("read client stream message")?;
            decode_client_message(&message)
        };
        let message = match message {
            Ok(message) if message == expected => message,
            Ok(message) => {
                debug!(
                    expected = ?expected,
                    got = ?message,
                    "Rejected client request in wrong state"
                );
                let _ =
                    send_server_message(&mut transport, ServerMessage::Error(UserFriendlyError::UnexpectedError)).await;
                anyhow::bail!("invalid client stream state");
            }
            Err(error) => {
                debug!(error = %error, "Rejected undecodable client request");
                let _ =
                    send_server_message(&mut transport, ServerMessage::Error(UserFriendlyError::UnexpectedError)).await;
                anyhow::bail!("invalid client stream state");
            }
        };
        debug!(
            request = ?message,
            segment_state = ?segment_state,
            queued_pulls = queued_pulls.len(),
            "Serving client request"
        );

        let response = match wait_for_response(&mut transport, segments.as_mut(), &mut segment_state, &mut queued_pulls)
            .await
        {
            Ok(Some(response)) => {
                debug!(
                    response = ?response_kind(&response),
                    queued_pulls = queued_pulls.len(),
                    "Sending server response"
                );
                response
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                debug!(error = format!("{error:#}"), "Request failed while waiting");
                let pending_requests = 1 + queued_pulls.len();
                for _ in 0..pending_requests {
                    let _ =
                        send_server_message(&mut transport, ServerMessage::Error(UserFriendlyError::UnexpectedError))
                            .await;
                }
                return Err(error);
            }
        };

        let ended = response == ServerMessage::StreamEnded;
        send_server_message(&mut transport, response).await?;
        if ended {
            while queued_pulls.pop_front().is_some() {
                send_server_message(&mut transport, ServerMessage::StreamEnded).await?;
            }
            return Ok(());
        }

        expected = match message {
            ClientMessage::Start | ClientMessage::Pull => ClientMessage::Pull,
        };
    }
}

async fn send_server_message<T, E>(transport: &mut T, message: ServerMessage) -> anyhow::Result<()>
where
    T: Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    transport
        .send(encode_server_message(message))
        .await
        .map_err(anyhow::Error::new)
        .context("write server stream message")
}

fn decode_client_message(message: &[u8]) -> anyhow::Result<ClientMessage> {
    match message {
        [0] => Ok(ClientMessage::Start),
        [1] => Ok(ClientMessage::Pull),
        _ => anyhow::bail!("invalid client message"),
    }
}

fn response_kind(message: &ServerMessage) -> &'static str {
    match message {
        ServerMessage::Chunk(_) => "chunk",
        ServerMessage::SegmentStarted(_) => "segment-started",
        ServerMessage::Error(_) => "error",
        ServerMessage::StreamEnded => "stream-ended",
    }
}

fn encode_server_message(message: ServerMessage) -> Bytes {
    let mut encoded = BytesMut::new();
    match message {
        ServerMessage::Chunk(chunk) => {
            encoded.reserve(1 + chunk.len());
            encoded.put_u8(0);
            encoded.put(chunk);
        }
        ServerMessage::SegmentStarted(info) => {
            encoded.put_u8(1);
            let json = format!(
                "{{\"codec\":\"vp8\",\"sequence\":{},\"width\":{},\"height\":{}}}",
                info.sequence, info.width, info.height
            );
            encoded.put(json.as_bytes());
        }
        ServerMessage::Error(error) => {
            encoded.put_u8(2);
            let json = format!("{{\"error\":\"{}\"}}", error.as_str());
            encoded.put(json.as_bytes());
        }
        ServerMessage::StreamEnded => encoded.put_u8(3),
    }
    encoded.freeze()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SegmentState {
    AwaitingBegin { next_sequence: u64 },
    Streaming { next_sequence: u64 },
}

async fn wait_for_response<T, S, E>(
    transport: &mut T,
    mut segments: Pin<&mut S>,
    state: &mut SegmentState,
    queued_pulls: &mut VecDeque<ClientMessage>,
) -> anyhow::Result<Option<ServerMessage>>
where
    T: Stream<Item = Result<Bytes, E>> + Unpin,
    S: Stream<Item = anyhow::Result<SegmentEvent>>,
    E: Error + Send + Sync + 'static,
{
    loop {
        tokio::select! {
            biased;
            message = transport.next() => match message {
                None => return Ok(None),
                Some(Ok(message)) => {
                    let message = decode_client_message(&message).context("decode pipelined client request")?;
                    if message == ClientMessage::Pull {
                        anyhow::ensure!(
                            queued_pulls.len() < MAX_QUEUED_PULLS,
                            "too many pipelined Pull requests"
                        );
                        debug!(
                            queued_pulls = queued_pulls.len() + 1,
                            "Queued pipelined Pull while waiting for response"
                        );
                        queued_pulls.push_back(message);
                    } else {
                        debug!(
                            incoming = ?message,
                            "Overlapping non-Pull request while waiting for response"
                        );
                        anyhow::bail!("client sent another request before receiving a response");
                    }
                }
                Some(Err(error)) => {
                    return Err(anyhow::Error::new(error).context("read client stream message"));
                }
            },
            response = next_segment_message(segments.as_mut(), state) => {
                return response;
            }
        }
    }
}

async fn next_segment_message<S>(
    mut segments: Pin<&mut S>,
    state: &mut SegmentState,
) -> anyhow::Result<Option<ServerMessage>>
where
    S: Stream<Item = anyhow::Result<SegmentEvent>>,
{
    loop {
        let Some(event) = segments.as_mut().next().await else {
            anyhow::ensure!(
                matches!(*state, SegmentState::AwaitingBegin { .. }),
                "segment stream ended inside a segment"
            );
            return Ok(Some(ServerMessage::StreamEnded));
        };

        match event? {
            SegmentEvent::Begin(info) => {
                let SegmentState::AwaitingBegin { next_sequence } = *state else {
                    anyhow::bail!("segment began before the previous segment ended");
                };
                anyhow::ensure!(
                    info.sequence == next_sequence,
                    "segment sequence is not contiguous: expected {next_sequence}, got {}",
                    info.sequence
                );
                *state = SegmentState::Streaming {
                    next_sequence: next_sequence.checked_add(1).context("segment sequence overflow")?,
                };
                debug!(
                    sequence = info.sequence,
                    width = info.width,
                    height = info.height,
                    "Segment begin"
                );
                return Ok(Some(ServerMessage::SegmentStarted(info)));
            }
            SegmentEvent::Data(data) => {
                anyhow::ensure!(
                    matches!(*state, SegmentState::Streaming { .. }),
                    "segment data arrived outside a segment"
                );
                debug!(bytes = data.len(), "Segment data");
                return Ok(Some(ServerMessage::Chunk(data)));
            }
            SegmentEvent::End => {
                let SegmentState::Streaming { next_sequence } = *state else {
                    anyhow::bail!("segment ended outside a segment");
                };
                *state = SegmentState::AwaitingBegin { next_sequence };
                debug!("Segment end");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use futures_util::{Sink, StreamExt as _, stream};
    use tokio::sync::mpsc;

    use super::*;

    fn pending_after(
        messages: impl IntoIterator<Item = Result<Bytes, std::io::Error>>,
    ) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Unpin {
        stream::iter(messages).chain(stream::pending())
    }

    struct ChannelTransport {
        incoming: mpsc::UnboundedReceiver<Bytes>,
        outgoing: mpsc::UnboundedSender<Bytes>,
    }

    impl Stream for ChannelTransport {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.incoming.poll_recv(cx).map(|message| message.map(Ok))
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

    fn channel_transport() -> (
        ChannelTransport,
        mpsc::UnboundedSender<Bytes>,
        mpsc::UnboundedReceiver<Bytes>,
    ) {
        let (client_sender, incoming) = mpsc::unbounded_channel();
        let (outgoing, client_receiver) = mpsc::unbounded_channel();
        (ChannelTransport { incoming, outgoing }, client_sender, client_receiver)
    }

    async fn receive_response(receiver: &mut mpsc::UnboundedReceiver<Bytes>) -> Bytes {
        tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("timed out waiting for server response")
            .expect("server response channel closed")
    }

    #[test]
    fn protocol_codes_are_stable() {
        assert_eq!(
            encode_server_message(ServerMessage::SegmentStarted(SegmentInfo {
                sequence: 7,
                width: 1920,
                height: 1080,
            })),
            Bytes::from_static(b"\x01{\"codec\":\"vp8\",\"sequence\":7,\"width\":1920,\"height\":1080}")
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
        assert!(decode_client_message(b"\x00\x01").is_err());
        assert!(decode_client_message(b"").is_err());
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
        let segments = stream::iter(events);
        tokio::pin!(segments);
        let mut state = SegmentState::AwaitingBegin { next_sequence: 0 };

        assert!(matches!(
            next_segment_message(segments.as_mut(), &mut state)
                .await
                .expect("first begin"),
            Some(ServerMessage::SegmentStarted(SegmentInfo { sequence: 0, .. }))
        ));
        assert_eq!(
            next_segment_message(segments.as_mut(), &mut state)
                .await
                .expect("first data"),
            Some(ServerMessage::Chunk(Bytes::from_static(b"first")))
        );
        assert!(matches!(
            next_segment_message(segments.as_mut(), &mut state)
                .await
                .expect("second begin"),
            Some(ServerMessage::SegmentStarted(SegmentInfo { sequence: 1, .. }))
        ));
        assert_eq!(
            next_segment_message(segments.as_mut(), &mut state)
                .await
                .expect("second data"),
            Some(ServerMessage::Chunk(Bytes::from_static(b"second")))
        );
        assert_eq!(
            next_segment_message(segments.as_mut(), &mut state)
                .await
                .expect("stream end"),
            Some(ServerMessage::StreamEnded)
        );
    }

    #[tokio::test]
    async fn start_response_buffers_one_pipelined_pull() {
        let mut transport = pending_after([Ok::<_, std::io::Error>(Bytes::from_static(b"\x01"))]);
        let segments = stream::once(async {
            tokio::task::yield_now().await;
            Ok(SegmentEvent::Begin(SegmentInfo {
                sequence: 0,
                width: 640,
                height: 480,
            }))
        });
        tokio::pin!(segments);
        let mut state = SegmentState::AwaitingBegin { next_sequence: 0 };
        let mut queued_pulls = VecDeque::new();

        let response = wait_for_response(&mut transport, segments.as_mut(), &mut state, &mut queued_pulls)
            .await
            .expect("wait for start response")
            .expect("segment response");

        assert!(matches!(
            response,
            ServerMessage::SegmentStarted(SegmentInfo { sequence: 0, .. })
        ));
        assert_eq!(queued_pulls, VecDeque::from([ClientMessage::Pull]));
    }

    #[tokio::test]
    async fn extra_pull_while_waiting_for_chunk_is_queued() {
        let mut transport = pending_after([Ok::<_, std::io::Error>(Bytes::from_static(b"\x01"))]);
        let segments = stream::once(async {
            tokio::task::yield_now().await;
            Ok(SegmentEvent::Data(Bytes::from_static(b"chunk")))
        });
        tokio::pin!(segments);
        let mut state = SegmentState::Streaming { next_sequence: 1 };
        let mut queued_pulls = VecDeque::new();

        let response = wait_for_response(&mut transport, segments.as_mut(), &mut state, &mut queued_pulls)
            .await
            .expect("wait for chunk")
            .expect("chunk response");

        assert_eq!(response, ServerMessage::Chunk(Bytes::from_static(b"chunk")));
        assert_eq!(queued_pulls, VecDeque::from([ClientMessage::Pull]));
    }

    #[tokio::test]
    async fn extra_start_while_waiting_is_still_rejected() {
        let mut transport = pending_after([Ok::<_, std::io::Error>(Bytes::from_static(b"\x00"))]);
        let segments = stream::once(async {
            tokio::task::yield_now().await;
            Ok(SegmentEvent::Data(Bytes::from_static(b"chunk")))
        });
        tokio::pin!(segments);
        let mut state = SegmentState::Streaming { next_sequence: 1 };
        let mut queued_pulls = VecDeque::new();

        let error = wait_for_response(&mut transport, segments.as_mut(), &mut state, &mut queued_pulls)
            .await
            .expect_err("overlapping Start must fail");

        assert!(
            format!("{error:#}").contains("client sent another request before receiving a response"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn first_segment_sequence_must_be_zero() {
        let segments = stream::iter([Ok(SegmentEvent::Begin(SegmentInfo {
            sequence: 1,
            width: 640,
            height: 480,
        }))]);
        tokio::pin!(segments);
        let mut state = SegmentState::AwaitingBegin { next_sequence: 0 };

        let error = next_segment_message(segments.as_mut(), &mut state)
            .await
            .expect_err("nonzero first sequence must fail");

        assert!(
            format!("{error:#}").contains("segment sequence is not contiguous"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn segment_sequence_gap_is_rejected() {
        let segments = stream::iter([
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
        ]);
        tokio::pin!(segments);
        let mut state = SegmentState::AwaitingBegin { next_sequence: 0 };

        assert!(matches!(
            next_segment_message(segments.as_mut(), &mut state)
                .await
                .expect("first segment"),
            Some(ServerMessage::SegmentStarted(SegmentInfo { sequence: 0, .. }))
        ));
        let error = next_segment_message(segments.as_mut(), &mut state)
            .await
            .expect_err("segment sequence gap must fail");

        assert!(
            format!("{error:#}").contains("segment sequence is not contiguous"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn pipelined_pull_queue_is_bounded() {
        let mut transport = pending_after([
            Ok::<_, std::io::Error>(Bytes::from_static(b"\x01")),
            Ok::<_, std::io::Error>(Bytes::from_static(b"\x01")),
        ]);
        let segments = stream::pending::<anyhow::Result<SegmentEvent>>();
        tokio::pin!(segments);
        let mut state = SegmentState::AwaitingBegin { next_sequence: 0 };
        let mut queued_pulls = VecDeque::new();

        let error = tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_response(&mut transport, segments.as_mut(), &mut state, &mut queued_pulls),
        )
        .await
        .expect("a second queued Pull must be rejected")
        .expect_err("a second queued Pull must fail");

        assert!(
            format!("{error:#}").contains("too many pipelined Pull requests"),
            "{error:#}"
        );
        assert_eq!(queued_pulls, VecDeque::from([ClientMessage::Pull]));
    }

    #[tokio::test]
    async fn ready_output_does_not_bypass_the_pipelined_pull_limit() {
        let (transport, client_sender, mut client_receiver) = channel_transport();
        client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
        client_sender
            .send(Bytes::from_static(b"\x01"))
            .expect("send first pipelined Pull");
        client_sender
            .send(Bytes::from_static(b"\x01"))
            .expect("send second pipelined Pull");
        let segments = stream::iter([
            Ok(SegmentEvent::Begin(SegmentInfo {
                sequence: 0,
                width: 640,
                height: 480,
            })),
            Ok(SegmentEvent::End),
        ]);
        let task = tokio::spawn(stream_segments(transport, segments));

        assert_eq!(receive_response(&mut client_receiver).await[0], 2);
        assert_eq!(receive_response(&mut client_receiver).await[0], 2);
        assert!(task.await.expect("stream task panicked").is_err());
        assert_eq!(client_receiver.recv().await, None);
    }

    #[tokio::test]
    async fn queued_pull_receives_stream_end() {
        let (transport, client_sender, mut client_receiver) = channel_transport();
        client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
        client_sender
            .send(Bytes::from_static(b"\x01"))
            .expect("send queued Pull");
        let task = tokio::spawn(stream_segments(transport, stream::empty()));

        assert_eq!(
            receive_response(&mut client_receiver).await,
            Bytes::from_static(b"\x03")
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
        let segments = stream::iter([
            Ok(SegmentEvent::Begin(SegmentInfo {
                sequence: 0,
                width: 640,
                height: 480,
            })),
            Ok(SegmentEvent::Data(Bytes::from_static(b"chunk"))),
            Ok(SegmentEvent::End),
        ]);
        let task = tokio::spawn(stream_segments(transport, segments));

        client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
        assert_eq!(receive_response(&mut client_receiver).await[0], 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client_receiver.recv())
                .await
                .is_err(),
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
            tokio::time::timeout(Duration::from_millis(10), client_receiver.recv())
                .await
                .is_err(),
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
    async fn segment_failure_sends_error_without_stream_end() {
        let (transport, client_sender, mut client_receiver) = channel_transport();
        let segments = stream::iter([Err(anyhow::anyhow!("test segment failure"))]);
        let task = tokio::spawn(stream_segments(transport, segments));

        client_sender.send(Bytes::from_static(b"\x00")).expect("send Start");
        let response = receive_response(&mut client_receiver).await;
        assert_eq!(response[0], 2);
        assert!(task.await.expect("stream task panicked").is_err());
        assert_eq!(
            client_receiver.recv().await,
            None,
            "error must not be followed by StreamEnded"
        );
    }
}
