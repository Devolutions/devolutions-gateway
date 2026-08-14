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

    loop {
        let Some(message) = transport.next().await else {
            return Ok(());
        };
        let message = message
            .map_err(anyhow::Error::new)
            .context("read client stream message")?;
        let message = match decode_client_message(&message) {
            Ok(message) if message == expected => message,
            Ok(_) | Err(_) => {
                let _ =
                    send_server_message(&mut transport, ServerMessage::Error(UserFriendlyError::UnexpectedError)).await;
                anyhow::bail!("invalid client stream state");
            }
        };

        let response = match wait_for_response(&mut transport, segments.as_mut(), &mut segment_state).await {
            Ok(Some(response)) => response,
            Ok(None) => return Ok(()),
            Err(error) => {
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
    segments: Pin<&mut S>,
    state: &mut SegmentState,
) -> anyhow::Result<Option<ServerMessage>>
where
    T: Stream<Item = Result<Bytes, E>> + Unpin,
    S: Stream<Item = anyhow::Result<SegmentEvent>>,
    E: Error + Send + Sync + 'static,
{
    tokio::select! {
        response = next_segment_message(segments, state) => response,
        message = transport.next() => match message {
            None => Ok(None),
            Some(Ok(_)) => anyhow::bail!("client sent another request before receiving a response"),
            Some(Err(error)) => Err(anyhow::Error::new(error).context("read client stream message")),
        },
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
                return Ok(Some(ServerMessage::SegmentStarted(info)));
            }
            SegmentEvent::Data(data) => {
                anyhow::ensure!(
                    *state == SegmentState::Streaming,
                    "segment data arrived outside a segment"
                );
                return Ok(Some(ServerMessage::Chunk(data)));
            }
            SegmentEvent::End => {
                anyhow::ensure!(*state == SegmentState::Streaming, "segment ended outside a segment");
                *state = SegmentState::AwaitingBegin;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::stream;

    use super::*;

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
}
