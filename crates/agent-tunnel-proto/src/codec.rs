//! Shared encode/decode helpers for length-prefixed strings and size checks.

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use crate::error::ProtoError;

/// Trait for types that can encode themselves into a binary payload.
pub trait Encode {
    fn encode(&self, buf: &mut BytesMut);
}

/// Trait for types that can decode themselves from a binary payload.
pub trait Decode: Sized {
    fn decode(buf: Bytes) -> Result<Self, ProtoError>;
}

/// Write a length-prefixed UTF-8 string (u32 big-endian length + bytes).
#[expect(clippy::cast_possible_truncation, reason = "string length bounded by frame size limit")]
pub(crate) fn put_string(buf: &mut BytesMut, s: &str) {
    buf.put_u32(s.len() as u32);
    buf.put_slice(s.as_bytes());
}

/// Read a length-prefixed UTF-8 string (u32 big-endian length + bytes).
pub(crate) fn get_string(buf: &mut Bytes) -> Result<String, ProtoError> {
    ensure_remaining(buf.remaining(), 4, "string length")?;
    let len = buf.get_u32() as usize;
    ensure_remaining(buf.remaining(), len, "string data")?;
    let bytes = buf.split_to(len);
    String::from_utf8(bytes.to_vec()).map_err(|_| ProtoError::InvalidField {
        field: "string",
        reason: "not valid UTF-8",
    })
}

/// Check that the buffer has at least `expected` bytes remaining.
pub(crate) fn ensure_remaining(
    remaining: usize,
    expected: usize,
    context: &'static str,
) -> Result<(), ProtoError> {
    if remaining < expected {
        Err(ProtoError::Truncated { expected: context })
    } else {
        Ok(())
    }
}
