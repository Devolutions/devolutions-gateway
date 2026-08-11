use std::pin::Pin;

use anyhow::Context as _;
use bytes::Bytes;
use futures_util::{SinkExt as _, Stream, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio_util::bytes::{self, Buf, BufMut};
use tokio_util::codec::{self, Framed};

use crate::normalizer::{SegmentEvent, SegmentInfo};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ServerMessage {
    Chunk(Bytes),
    SegmentStarted(SegmentInfo),
    Error(UserFriendlyError),
    StreamEnded,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ClientMessage {
    Start,
    Pull,
}

pub(crate) struct ProtocolCodec;

impl codec::Decoder for ProtocolCodec {
    type Item = ClientMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let type_code = src.get_u8();
        let message = match type_code {
            0 => ClientMessage::Start,
            1 => ClientMessage::Pull,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid message type",
                ));
            }
        };

        Ok(Some(message))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UserFriendlyError {
    UnexpectedError,
}

impl UserFriendlyError {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::UnexpectedError => "UnexpectedError",
        }
    }
}

impl codec::Encoder<ServerMessage> for ProtocolCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: ServerMessage, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let type_code = match item {
            ServerMessage::Chunk(_) => 0,
            ServerMessage::SegmentStarted(_) => 1,
            ServerMessage::Error(_) => 2,
            ServerMessage::StreamEnded => 3,
        };

        dst.put_u8(type_code);

        match item {
            ServerMessage::Chunk(chunk) => dst.put(chunk),
            ServerMessage::SegmentStarted(info) => {
                let json = format!(
                    "{{\"codec\":\"vp8\",\"sequence\":{},\"width\":{},\"height\":{}}}",
                    info.sequence, info.width, info.height
                );
                dst.put(json.as_bytes());
            }
            ServerMessage::Error(error) => {
                let json = format!("{{\"error\":\"{}\"}}", error.as_str());
                dst.put(json.as_bytes());
            }
            ServerMessage::StreamEnded => {}
        }

        Ok(())
    }
}

pub(crate) async fn stream_segments<W, S>(output_stream: W, segments: S) -> anyhow::Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
    S: Stream<Item = anyhow::Result<SegmentEvent>>,
{
    let mut framed = Framed::new(output_stream, ProtocolCodec);
    tokio::pin!(segments);
    let mut client_started = false;
    let mut segment_state = SegmentState::AwaitingBegin;

    while let Some(message) = framed.next().await {
        let message = message.context("read client stream message")?;
        let valid = match message {
            ClientMessage::Start if !client_started => {
                client_started = true;
                true
            }
            ClientMessage::Pull if client_started => true,
            ClientMessage::Start | ClientMessage::Pull => false,
        };

        if !valid {
            framed
                .send(ServerMessage::Error(UserFriendlyError::UnexpectedError))
                .await?;
            framed.get_mut().shutdown().await?;
            anyhow::bail!("invalid client stream state");
        }

        let response = match next_segment_message(segments.as_mut(), &mut segment_state).await {
            Ok(Some(response)) => response,
            Ok(None) => {
                framed.send(ServerMessage::StreamEnded).await?;
                framed.get_mut().shutdown().await?;
                return Ok(());
            }
            Err(error) => {
                let _ = framed
                    .send(ServerMessage::Error(UserFriendlyError::UnexpectedError))
                    .await;
                let _ = framed.get_mut().shutdown().await;
                return Err(error);
            }
        };

        framed.send(response).await.context("write server stream message")?;
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SegmentState {
    AwaitingBegin,
    Streaming,
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
            return Ok(None);
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
    use tokio_util::codec::{Decoder as _, Encoder as _};

    use super::*;

    #[test]
    fn protocol_codes_are_stable() {
        let mut codec = ProtocolCodec;
        let mut buffer = bytes::BytesMut::new();

        codec
            .encode(
                ServerMessage::SegmentStarted(SegmentInfo {
                    sequence: 7,
                    width: 1920,
                    height: 1080,
                }),
                &mut buffer,
            )
            .expect("encode segment start");
        assert_eq!(
            &buffer[..],
            b"\x01{\"codec\":\"vp8\",\"sequence\":7,\"width\":1920,\"height\":1080}"
        );

        buffer.clear();
        codec
            .encode(ServerMessage::Chunk(Bytes::from_static(b"webm")), &mut buffer)
            .expect("encode chunk");
        assert_eq!(&buffer[..], b"\x00webm");

        buffer.clear();
        codec
            .encode(ServerMessage::StreamEnded, &mut buffer)
            .expect("encode end");
        assert_eq!(&buffer[..], b"\x03");
    }

    #[test]
    fn client_codes_are_stable() {
        let mut codec = ProtocolCodec;
        let mut buffer = bytes::BytesMut::from(&b"\x00\x01"[..]);

        assert_eq!(
            codec.decode(&mut buffer).expect("decode start"),
            Some(ClientMessage::Start)
        );
        assert_eq!(
            codec.decode(&mut buffer).expect("decode pull"),
            Some(ClientMessage::Pull)
        );
        assert_eq!(codec.decode(&mut buffer).expect("wait for input"), None);
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
            None
        );
    }
}
