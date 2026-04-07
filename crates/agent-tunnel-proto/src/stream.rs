//! Typed stream wrappers for control and session QUIC streams.
//!
//! These provide a fluent API where the stream is the actor:
//! ```ignore
//! ctrl.send(&msg).await?;
//! let msg = ctrl.recv().await?;
//! ```

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::control::{ControlMessage, MAX_CONTROL_MESSAGE_SIZE};
use crate::error::ProtoError;
use crate::session::{ConnectRequest, ConnectResponse, MAX_SESSION_MESSAGE_SIZE};

// ---------------------------------------------------------------------------
// Control stream — bidirectional, send-only, recv-only
// ---------------------------------------------------------------------------

/// Bidirectional control stream (QUIC stream 0).
pub struct ControlStream<S, R> {
    pub send: S,
    pub recv: R,
}

/// Send-only half of a control stream.
pub struct ControlSendStream<S>(pub S);

/// Recv-only half of a control stream.
pub struct ControlRecvStream<R>(pub R);

impl<S, R> From<(S, R)> for ControlStream<S, R> {
    fn from((send, recv): (S, R)) -> Self {
        Self { send, recv }
    }
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> ControlStream<S, R> {
    pub fn new(send: S, recv: R) -> Self {
        Self { send, recv }
    }

    pub async fn send(&mut self, msg: &ControlMessage) -> Result<(), ProtoError> {
        let payload = bincode::serialize(msg)?;
        write_framed(&mut self.send, &payload, MAX_CONTROL_MESSAGE_SIZE).await
    }

    pub async fn recv(&mut self) -> Result<ControlMessage, ProtoError> {
        let payload = read_framed(&mut self.recv, MAX_CONTROL_MESSAGE_SIZE).await?;
        let msg: ControlMessage = bincode::deserialize(&payload)?;
        Ok(msg)
    }

    /// Split into typed send-only and recv-only halves.
    pub fn into_split(self) -> (ControlSendStream<S>, ControlRecvStream<R>) {
        (ControlSendStream(self.send), ControlRecvStream(self.recv))
    }
}

impl<S: AsyncWrite + Unpin> ControlSendStream<S> {
    pub async fn send(&mut self, msg: &ControlMessage) -> Result<(), ProtoError> {
        let payload = bincode::serialize(msg)?;
        write_framed(&mut self.0, &payload, MAX_CONTROL_MESSAGE_SIZE).await
    }
}

impl<R: AsyncRead + Unpin> ControlRecvStream<R> {
    pub async fn recv(&mut self) -> Result<ControlMessage, ProtoError> {
        let payload = read_framed(&mut self.0, MAX_CONTROL_MESSAGE_SIZE).await?;
        let msg: ControlMessage = bincode::deserialize(&payload)?;
        Ok(msg)
    }
}

// ---------------------------------------------------------------------------
// Session stream — handshake then raw bytes
// ---------------------------------------------------------------------------

/// Typed wrapper for a session stream (QUIC streams 1, 5, 9, ...).
///
/// Used for the connect handshake. After the handshake, call [`into_inner`]
/// to get the raw streams back for bidirectional byte proxying.
pub struct SessionStream<S, R> {
    pub send: S,
    pub recv: R,
}

impl<S, R> From<(S, R)> for SessionStream<S, R> {
    fn from((send, recv): (S, R)) -> Self {
        Self { send, recv }
    }
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> SessionStream<S, R> {
    pub fn new(send: S, recv: R) -> Self {
        Self { send, recv }
    }

    pub async fn send_request(&mut self, msg: &ConnectRequest) -> Result<(), ProtoError> {
        let payload = bincode::serialize(msg)?;
        write_framed(&mut self.send, &payload, MAX_SESSION_MESSAGE_SIZE).await
    }

    pub async fn recv_request(&mut self) -> Result<ConnectRequest, ProtoError> {
        let payload = read_framed(&mut self.recv, MAX_SESSION_MESSAGE_SIZE).await?;
        let msg: ConnectRequest = bincode::deserialize(&payload)?;
        Ok(msg)
    }

    pub async fn send_response(&mut self, msg: &ConnectResponse) -> Result<(), ProtoError> {
        let payload = bincode::serialize(msg)?;
        write_framed(&mut self.send, &payload, MAX_SESSION_MESSAGE_SIZE).await
    }

    pub async fn recv_response(&mut self) -> Result<ConnectResponse, ProtoError> {
        let payload = read_framed(&mut self.recv, MAX_SESSION_MESSAGE_SIZE).await?;
        let msg: ConnectResponse = bincode::deserialize(&payload)?;
        Ok(msg)
    }

    /// Consume the wrapper and return the raw streams for byte proxying.
    pub fn into_inner(self) -> (S, R) {
        (self.send, self.recv)
    }
}

// ---------------------------------------------------------------------------
// Framing helpers (length-prefixed bincode)
// ---------------------------------------------------------------------------

/// Encode a message as length-prefixed bincode and write to a stream.
async fn write_framed<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8], max_size: u32) -> Result<(), ProtoError> {
    let len = u32::try_from(payload.len()).map_err(|_| ProtoError::MessageTooLarge {
        size: u32::MAX,
        max: max_size,
    })?;
    if len > max_size {
        return Err(ProtoError::MessageTooLarge {
            size: len,
            max: max_size,
        });
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed bincode message from a stream.
async fn read_framed<R: AsyncRead + Unpin>(reader: &mut R, max_size: u32) -> Result<Vec<u8>, ProtoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if len > max_size {
        return Err(ProtoError::MessageTooLarge {
            size: len,
            max: max_size,
        });
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}
