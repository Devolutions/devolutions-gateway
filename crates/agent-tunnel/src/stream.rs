//! Wrapper around Quinn's `SendStream` + `RecvStream` providing a single
//! `AsyncRead + AsyncWrite` type for use with the gateway's proxy infrastructure.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional QUIC stream backed by Quinn's `SendStream` and `RecvStream`.
///
/// Implements `AsyncRead` (delegating to `recv`) and `AsyncWrite` (delegating
/// to `send`), so callers can treat it as a single bidirectional transport.
pub struct TunnelStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl AsyncRead for TunnelStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
