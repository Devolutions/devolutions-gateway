//! Wire-format encoding and decoding for [`ConnectRequest`] and [`ConnectResponse`].

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use uuid::Uuid;

use crate::codec::{self, Decode, Encode};
use crate::error::ProtoError;
use crate::session::{ConnectRequest, ConnectResponse};

// ConnectResponse sub-tags.
const TAG_RESPONSE_SUCCESS: u8 = 0x00;
const TAG_RESPONSE_ERROR: u8 = 0x01;

impl Encode for ConnectRequest {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.protocol_version);
        buf.put_slice(self.session_id.as_bytes());
        codec::put_string(buf, &self.target);
    }
}

impl Decode for ConnectRequest {
    fn decode(mut buf: Bytes) -> Result<Self, ProtoError> {
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

impl Encode for ConnectResponse {
    fn encode(&self, buf: &mut BytesMut) {
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
}

impl Decode for ConnectResponse {
    fn decode(mut buf: Bytes) -> Result<Self, ProtoError> {
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
