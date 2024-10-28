use tokio_util::{
    bytes::{self, Buf, BufMut},
    codec,
};

#[derive(Debug)]
pub enum Codec {
    Vp8,
    Vp9,
}

impl TryFrom<&str> for Codec {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "vp8" => Ok(Codec::Vp8),
            "vp9" => Ok(Codec::Vp9),
            "V_VP8" => Ok(Codec::Vp8),
            "V_VP9" => Ok(Codec::Vp9),
            _ => Err(format!("unknown codec: {}", value)),
        }
    }
}

impl std::fmt::Display for Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Codec::Vp8 => write!(f, "vp8"),
            Codec::Vp9 => write!(f, "vp9"),
        }
    }
}

#[derive(Debug)]
pub enum ServerMessage<'a> {
    Chunk(&'a [u8]),
    // leave for future extension (e.g. audio metadata, size, etc.)
    MetaData { codec: Codec },
}

#[derive(Debug)]
pub enum ClientMessage {
    // leave for future extension (e.g. audio metadata, size, etc.)
    Start,
    Pull,
}

pub struct ProtocolCodeC;

impl codec::Decoder for ProtocolCodeC {
    type Item = ClientMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None); // Wait for more data
        }

        if src.is_empty() {
            return Ok(None); // Not enough data yet to decode a type code
        }

        let type_code = src.get_u8();
        let message = match type_code {
            0 => ClientMessage::Start,
            1 => ClientMessage::Pull,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid message type",
                ))
            }
        };

        Ok(Some(message))
    }
}

impl codec::Encoder<ServerMessage<'_>> for ProtocolCodeC {
    type Error = std::io::Error;

    fn encode(&mut self, item: ServerMessage<'_>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let type_code = match item {
            ServerMessage::Chunk(_) => 0,
            ServerMessage::MetaData { .. } => 1,
        };

        dst.put_u8(type_code);

        match item {
            ServerMessage::Chunk(chunk) => {
                dst.put(chunk);
            }
            ServerMessage::MetaData { codec } => {
                let json = format!("{{\"codec\":\"{}\"}}", codec);
                dst.put(json.as_bytes());
            }
        }

        Ok(())
    }
}
