//! Typed stream wrappers for control and session QUIC streams.
//!
//! Framing is handled by [`FramedSend`] and [`FramedRecv`], which encode/decode
//! messages with a 4-byte big-endian length prefix. The control and session
//! stream types compose these with the appropriate max frame size.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::codec::{Decode, Encode};
use crate::control::{ControlMessage, MAX_CONTROL_MESSAGE_SIZE};
use crate::error::ProtoError;
use crate::session::{ConnectRequest, ConnectResponse, MAX_SESSION_MESSAGE_SIZE};

// ---------------------------------------------------------------------------
// Length-prefixed framed I/O
// ---------------------------------------------------------------------------

/// A length-prefixed framed writer. Encodes messages and writes them with a 4-byte BE length header.
pub struct FramedSend<S> {
    inner: S,
    max_size: u32,
}

/// A length-prefixed framed reader. Reads a 4-byte BE length header, then decodes the payload.
pub struct FramedRecv<R> {
    inner: R,
    max_size: u32,
}

impl<S: AsyncWrite + Unpin> FramedSend<S> {
    /// Encode `msg` and write it as a length-prefixed frame.
    pub async fn send(&mut self, msg: &impl Encode) -> Result<(), ProtoError> {
        let mut payload = BytesMut::new();
        msg.encode(&mut payload);

        let len = u32::try_from(payload.len()).map_err(|_| ProtoError::MessageTooLarge {
            size: u32::MAX,
            max: self.max_size,
        })?;
        if len > self.max_size {
            return Err(ProtoError::MessageTooLarge {
                size: len,
                max: self.max_size,
            });
        }

        self.inner.write_all(&len.to_be_bytes()).await?;
        self.inner.write_all(&payload).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> FramedRecv<R> {
    /// Read a length-prefixed frame and decode it.
    pub async fn recv<T: Decode>(&mut self) -> Result<T, ProtoError> {
        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);

        if len > self.max_size {
            return Err(ProtoError::MessageTooLarge {
                size: len,
                max: self.max_size,
            });
        }

        let mut payload = vec![0u8; len as usize];
        self.inner.read_exact(&mut payload).await?;
        T::decode(Bytes::from(payload))
    }
}

// ---------------------------------------------------------------------------
// Control stream (QUIC stream 0)
// ---------------------------------------------------------------------------

/// Bidirectional control stream.
pub struct ControlStream<S, R> {
    pub send: FramedSend<S>,
    pub recv: FramedRecv<R>,
}

impl<S, R> From<(S, R)> for ControlStream<S, R> {
    fn from((send, recv): (S, R)) -> Self {
        Self {
            send: FramedSend { inner: send, max_size: MAX_CONTROL_MESSAGE_SIZE },
            recv: FramedRecv { inner: recv, max_size: MAX_CONTROL_MESSAGE_SIZE },
        }
    }
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> ControlStream<S, R> {
    pub fn new(send: S, recv: R) -> Self {
        Self::from((send, recv))
    }

    pub async fn send(&mut self, msg: &ControlMessage) -> Result<(), ProtoError> {
        self.send.send(msg).await
    }

    pub async fn recv(&mut self) -> Result<ControlMessage, ProtoError> {
        self.recv.recv().await
    }

    /// Split into send-only and recv-only halves.
    pub fn into_split(self) -> (FramedSend<S>, FramedRecv<R>) {
        (self.send, self.recv)
    }
}

// ---------------------------------------------------------------------------
// Session stream (QUIC streams 1, 5, 9, ...)
// ---------------------------------------------------------------------------

/// Typed wrapper for a session stream.
///
/// Used for the connect handshake. After the handshake, call [`into_inner`]
/// to get the raw streams back for bidirectional byte proxying.
pub struct SessionStream<S, R> {
    send: FramedSend<S>,
    recv: FramedRecv<R>,
}

impl<S, R> From<(S, R)> for SessionStream<S, R> {
    fn from((send, recv): (S, R)) -> Self {
        Self {
            send: FramedSend { inner: send, max_size: MAX_SESSION_MESSAGE_SIZE },
            recv: FramedRecv { inner: recv, max_size: MAX_SESSION_MESSAGE_SIZE },
        }
    }
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> SessionStream<S, R> {
    pub fn new(send: S, recv: R) -> Self {
        Self::from((send, recv))
    }

    pub async fn send_request(&mut self, msg: &ConnectRequest) -> Result<(), ProtoError> {
        self.send.send(msg).await
    }

    pub async fn recv_request(&mut self) -> Result<ConnectRequest, ProtoError> {
        self.recv.recv().await
    }

    pub async fn send_response(&mut self, msg: &ConnectResponse) -> Result<(), ProtoError> {
        self.send.send(msg).await
    }

    pub async fn recv_response(&mut self) -> Result<ConnectResponse, ProtoError> {
        self.recv.recv().await
    }

    /// Consume the wrapper and return the raw streams for byte proxying.
    pub fn into_inner(self) -> (S, R) {
        (self.send.inner, self.recv.inner)
    }
}
