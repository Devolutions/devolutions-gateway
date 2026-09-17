use bytes::{BufMut as _, Bytes, BytesMut};

const VP8_METADATA_PAYLOAD: &[u8] = b"{\"codec\":\"vp8\"}";

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ServerMessage {
    Chunk(Bytes),
    Metadata,
    SegmentStarted,
    Error(UserFriendlyError),
    StreamEnded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientMessage {
    Start,
    Pull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UserFriendlyError {
    UnexpectedError,
}

impl UserFriendlyError {
    fn as_str(&self) -> &'static str {
        match self {
            Self::UnexpectedError => "UnexpectedError",
        }
    }
}

pub(super) fn decode_client_message(message: &[u8]) -> anyhow::Result<ClientMessage> {
    match message {
        [0] => Ok(ClientMessage::Start),
        [1] => Ok(ClientMessage::Pull),
        _ => anyhow::bail!("invalid client message"),
    }
}

pub(super) fn response_kind(message: &ServerMessage) -> &'static str {
    match message {
        ServerMessage::Chunk(_) => "chunk",
        ServerMessage::Metadata => "metadata",
        ServerMessage::SegmentStarted => "segment-started",
        ServerMessage::Error(_) => "error",
        ServerMessage::StreamEnded => "stream-ended",
    }
}

pub(super) fn encode_server_message(message: ServerMessage) -> Bytes {
    let mut encoded = BytesMut::new();
    match message {
        ServerMessage::Chunk(chunk) => {
            encoded.reserve(1 + chunk.len());
            encoded.put_u8(0);
            encoded.put(chunk);
        }
        ServerMessage::Metadata => {
            encoded.put_u8(1);
            encoded.put(VP8_METADATA_PAYLOAD);
        }
        ServerMessage::Error(error) => {
            encoded.put_u8(2);
            let json = format!("{{\"error\":\"{}\"}}", error.as_str());
            encoded.put(json.as_bytes());
        }
        ServerMessage::StreamEnded => encoded.put_u8(3),
        ServerMessage::SegmentStarted => {
            encoded.put_u8(4);
            encoded.put(VP8_METADATA_PAYLOAD);
        }
    }
    encoded.freeze()
}
