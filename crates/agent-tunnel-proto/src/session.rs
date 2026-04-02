use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use uuid::Uuid;

use crate::error::ProtoError;
use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded session message size (64 KiB).
pub const MAX_SESSION_MESSAGE_SIZE: u32 = 64 * 1024;

/// Length-prefixed bincode encode and write to an async writer.
async fn encode_framed<T: Serialize, W: AsyncWrite + Unpin>(msg: &T, writer: &mut W) -> Result<(), ProtoError> {
    let payload = bincode::serialize(msg)?;
    let len = u32::try_from(payload.len()).map_err(|_| ProtoError::MessageTooLarge {
        size: u32::MAX,
        max: MAX_SESSION_MESSAGE_SIZE,
    })?;
    if MAX_SESSION_MESSAGE_SIZE < len {
        return Err(ProtoError::MessageTooLarge {
            size: len,
            max: MAX_SESSION_MESSAGE_SIZE,
        });
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and decode a length-prefixed bincode message from an async reader.
async fn decode_framed<T: DeserializeOwned, R: AsyncRead + Unpin>(reader: &mut R) -> Result<T, ProtoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if MAX_SESSION_MESSAGE_SIZE < len {
        return Err(ProtoError::MessageTooLarge {
            size: len,
            max: MAX_SESSION_MESSAGE_SIZE,
        });
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    let msg: T = bincode::deserialize(&payload)?;
    Ok(msg)
}

/// Request from Gateway to Agent to open a TCP connection to a target.
///
/// Sent as the first message on a newly opened QUIC bidirectional stream.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConnectMessage {
    pub protocol_version: u16,
    /// Association/session ID from the Gateway.
    pub session_id: Uuid,
    /// Target address in `host:port` form (e.g., `"192.168.1.100:3389"`).
    pub target: String,
}

/// Agent's response to a ConnectMessage.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum ConnectResponse {
    Success { protocol_version: u16 },
    Error { protocol_version: u16, reason: String },
}

impl ConnectMessage {
    pub fn new(session_id: Uuid, target: String) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            session_id,
            target,
        }
    }

    /// Length-prefixed bincode encode and write to an async writer.
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), ProtoError> {
        encode_framed(self, writer).await
    }

    /// Read and decode a length-prefixed bincode message from an async reader.
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtoError> {
        decode_framed(reader).await
    }
}

impl ConnectResponse {
    pub fn success() -> Self {
        Self::Success {
            protocol_version: CURRENT_PROTOCOL_VERSION,
        }
    }

    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            reason: reason.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Length-prefixed bincode encode and write to an async writer.
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), ProtoError> {
        encode_framed(self, writer).await
    }

    /// Read and decode a length-prefixed bincode message from an async reader.
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtoError> {
        decode_framed(reader).await
    }

    /// Extract the protocol version from any variant.
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Success { protocol_version } | Self::Error { protocol_version, .. } => *protocol_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_connect_message() {
        let msg = ConnectMessage::new(Uuid::new_v4(), "192.168.1.100:3389".to_owned());

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ConnectMessage::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn roundtrip_connect_response_success() {
        let msg = ConnectResponse::success();

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ConnectResponse::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn roundtrip_connect_response_error() {
        let msg = ConnectResponse::error("connection refused");

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ConnectResponse::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    fn arb_connect_message() -> impl Strategy<Value = ConnectMessage> {
        ("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}")
            .prop_map(|target| ConnectMessage::new(Uuid::new_v4(), target))
    }

    fn arb_connect_response() -> impl Strategy<Value = ConnectResponse> {
        prop_oneof![Just(ConnectResponse::success()), ".*".prop_map(ConnectResponse::error),]
    }

    proptest! {
        #[test]
        fn connect_message_roundtrip(msg in arb_connect_message()) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(async {
                let mut buf = Vec::new();
                msg.encode(&mut buf).await.expect("encode should succeed");
                let decoded = ConnectMessage::decode(&mut buf.as_slice()).await.expect("decode should succeed");
                // Compare fields individually because UUID is generated fresh
                prop_assert_eq!(&msg.target, &decoded.target);
                prop_assert_eq!(msg.protocol_version, decoded.protocol_version);
                prop_assert_eq!(msg.session_id, decoded.session_id);
                Ok(())
            })?;
        }

        #[test]
        fn connect_response_roundtrip(msg in arb_connect_response()) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(async {
                let mut buf = Vec::new();
                msg.encode(&mut buf).await.expect("encode should succeed");
                let decoded = ConnectResponse::decode(&mut buf.as_slice()).await.expect("decode should succeed");
                prop_assert_eq!(msg, decoded);
                Ok(())
            })?;
        }
    }
}
