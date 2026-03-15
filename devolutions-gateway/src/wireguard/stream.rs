use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tunnel_proto::RelayMessage;

use super::peer::AgentPeer;

/// Virtual TCP stream over WireGuard tunnel.
///
/// Implements `AsyncRead` / `AsyncWrite` to behave like a regular TCP stream,
/// but data is transported through the WireGuard tunnel using the relay protocol.
pub struct VirtualTcpStream {
    peer: Arc<AgentPeer>,
    stream_id: u32,
    rx: mpsc::Receiver<Bytes>,
    close_tx: mpsc::Sender<RelayMessage>,
    outbound_tx: PollSender<RelayMessage>,
    read_buffer: Option<Bytes>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    closed: bool,
}

impl VirtualTcpStream {
    /// Create a new virtual TCP stream.
    pub fn new(
        peer: Arc<AgentPeer>,
        stream_id: u32,
        rx: mpsc::Receiver<Bytes>,
        outbound_tx: mpsc::Sender<RelayMessage>,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        let close_tx = outbound_tx.clone();
        Self {
            peer,
            stream_id,
            rx,
            close_tx,
            outbound_tx: PollSender::new(outbound_tx),
            read_buffer: None,
            peer_addr,
            local_addr,
            closed: false,
        }
    }

    /// Get the stream ID.
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Get the peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if let Some(cached) = this.read_buffer.take() {
            let to_copy = buf.remaining().min(cached.len());
            buf.put_slice(&cached[..to_copy]);

            if to_copy < cached.len() {
                this.read_buffer = Some(cached.slice(to_copy..));
            }

            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut this.rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = buf.remaining().min(data.len());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    this.read_buffer = Some(data.slice(to_copy..));
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let msg = RelayMessage::data(this.stream_id, Bytes::copy_from_slice(buf)).map_err(io::Error::other)?;

        match Pin::new(&mut this.outbound_tx).poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                this.outbound_tx
                    .send_item(msg)
                    .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }

        let msg = RelayMessage::close(this.stream_id).map_err(io::Error::other)?;
        match Pin::new(&mut this.outbound_tx).poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                this.outbound_tx
                    .send_item(msg)
                    .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
                this.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for VirtualTcpStream {
    fn drop(&mut self) {
        if !self.closed {
            if let Ok(msg) = RelayMessage::close(self.stream_id) {
                let _ = self.close_tx.try_send(msg);
            }
            self.closed = true;
        }

        self.peer.free_stream_id(self.stream_id);
    }
}
