use std::collections::VecDeque;
use std::error::Error;
use std::pin::Pin;

use anyhow::Context as _;
use bytes::{BufMut as _, Bytes, BytesMut};
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};

use crate::normalizer::{SegmentEvent, SegmentInfo};

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
    let mut segment_state = SegmentState::AwaitingBegin;
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
                let _ =
                    send_server_message(&mut transport, ServerMessage::Error(UserFriendlyError::UnexpectedError)).await;
                return Err(error);
            }
        };

        let ended = response == ServerMessage::StreamEnded;
        send_server_message(&mut transport, response).await?;
        if ended {
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
    AwaitingBegin,
    Streaming,
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
            response = next_segment_message(segments.as_mut(), state) => {
                return response;
            }
            message = transport.next() => match message {
                None => return Ok(None),
                Some(Ok(message)) => {
                    let message = decode_client_message(&message).context("decode pipelined client request")?;
                    if message == ClientMessage::Pull {
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
                *state == SegmentState::AwaitingBegin,
                "segment stream ended inside a segment"
            );
            return Ok(Some(ServerMessage::StreamEnded));
        };

        match event? {
            SegmentEvent::Begin(info) => {
                anyhow::ensure!(
                    *state == SegmentState::AwaitingBegin,
                    "segment began before the previous segment ended"
                );
                *state = SegmentState::Streaming;
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
                    *state == SegmentState::Streaming,
                    "segment data arrived outside a segment"
                );
                debug!(bytes = data.len(), "Segment data");
                return Ok(Some(ServerMessage::Chunk(data)));
            }
            SegmentEvent::End => {
                anyhow::ensure!(*state == SegmentState::Streaming, "segment ended outside a segment");
                *state = SegmentState::AwaitingBegin;
                debug!("Segment end");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use futures_util::{StreamExt as _, stream};

    use super::*;

    fn pending_after(
        messages: impl IntoIterator<Item = Result<Bytes, std::io::Error>>,
    ) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Unpin {
        stream::iter(messages).chain(stream::pending())
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
        let mut state = SegmentState::AwaitingBegin;

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
        let mut state = SegmentState::AwaitingBegin;
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
        let mut state = SegmentState::Streaming;
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
        let mut state = SegmentState::Streaming;
        let mut queued_pulls = VecDeque::new();

        let error = wait_for_response(&mut transport, segments.as_mut(), &mut state, &mut queued_pulls)
            .await
            .expect_err("overlapping Start must fail");

        assert!(
            format!("{error:#}").contains("client sent another request before receiving a response"),
            "{error:#}"
        );
    }
}
