use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use uuid::Uuid;

use crate::codec::{self, Decode, Encode};
use crate::error::ProtoError;
use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded session message size (64 KiB).
pub const MAX_SESSION_MESSAGE_SIZE: u32 = 64 * 1024;

// ConnectResponse sub-tags.
const TAG_RESPONSE_SUCCESS: u8 = 0x00;
const TAG_RESPONSE_ERROR: u8 = 0x01;

/// Request from Gateway to Agent to open a TCP connection to a target.
///
/// Sent as the first message on a newly opened QUIC bidirectional stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub protocol_version: u16,
    /// Association/session ID from the Gateway.
    pub session_id: Uuid,
    /// Target address in `host:port` form (e.g., `"192.168.1.100:3389"`).
    pub target: String,
}

/// Agent's response to a ConnectRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectResponse {
    Success { protocol_version: u16 },
    Error { protocol_version: u16, reason: String },
}

impl ConnectRequest {
    pub fn new(session_id: Uuid, target: String) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            session_id,
            target,
        }
    }

    /// Encode this request into a binary payload.
    ///
    /// Wire layout: `[2B version][16B uuid][4B target_len][target bytes]`
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.protocol_version);
        buf.put_slice(self.session_id.as_bytes());
        codec::put_string(buf, &self.target);
    }

    /// Decode a binary payload into a `ConnectRequest`.
    pub fn decode(mut buf: Bytes) -> Result<Self, ProtoError> {
        codec::ensure_remaining(buf.remaining(), 2 + 16, "ConnectRequest header")?;
        let protocol_version = buf.get_u16();
        let mut uuid_bytes = [0u8; 16];
        buf.copy_to_slice(&mut uuid_bytes);
        let session_id = Uuid::from_bytes(uuid_bytes);
        let target = codec::get_string(&mut buf)?;
        Ok(Self {
            protocol_version,
            session_id,
            target,
        })
    }
}

impl Encode for ConnectRequest {
    fn encode(&self, buf: &mut BytesMut) {
        self.encode(buf);
    }
}

impl Decode for ConnectRequest {
    fn decode(buf: Bytes) -> Result<Self, ProtoError> {
        Self::decode(buf)
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

    /// Extract the protocol version from any variant.
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Success { protocol_version } | Self::Error { protocol_version, .. } => *protocol_version,
        }
    }

    /// Encode this response into a binary payload.
    ///
    /// Wire layout:
    /// - Success: `[1B tag=0x00][2B version]`
    /// - Error:   `[1B tag=0x01][2B version][4B reason_len][reason bytes]`
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::Success { protocol_version } => {
                buf.put_u8(TAG_RESPONSE_SUCCESS);
                buf.put_u16(*protocol_version);
            }
            Self::Error {
                protocol_version,
                reason,
            } => {
                buf.put_u8(TAG_RESPONSE_ERROR);
                buf.put_u16(*protocol_version);
                codec::put_string(buf, reason);
            }
        }
    }

    /// Decode a binary payload into a `ConnectResponse`.
    pub fn decode(mut buf: Bytes) -> Result<Self, ProtoError> {
        codec::ensure_remaining(buf.remaining(), 1 + 2, "ConnectResponse header")?;
        let tag = buf.get_u8();
        let protocol_version = buf.get_u16();

        match tag {
            TAG_RESPONSE_SUCCESS => Ok(Self::Success { protocol_version }),
            TAG_RESPONSE_ERROR => {
                let reason = codec::get_string(&mut buf)?;
                Ok(Self::Error {
                    protocol_version,
                    reason,
                })
            }
            _ => Err(ProtoError::UnknownTag { tag }),
        }
    }
}

impl Encode for ConnectResponse {
    fn encode(&self, buf: &mut BytesMut) {
        self.encode(buf);
    }
}

impl Decode for ConnectResponse {
    fn decode(buf: Bytes) -> Result<Self, ProtoError> {
        Self::decode(buf)
    }
}
