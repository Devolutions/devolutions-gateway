//! QUIC stream wrapper providing AsyncRead + AsyncWrite over quiche streams.
//!
//! Data flows through channels managed by the connection driver (listener event loop):
//! - Reads consume data forwarded by the driver from the QUIC connection.
//! - Writes send data to the driver which forwards it through the QUIC connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// A write operation destined for a specific QUIC stream on a specific connection.
pub struct StreamWrite {
    /// Internal connection identifier (maps to a `ManagedConnection`).
    pub conn_id: u64,
    /// QUIC stream identifier.
    pub stream_id: u64,
    /// Payload bytes. Empty payload signals stream shutdown.
    pub data: Vec<u8>,
}

/// Handle held by the connection driver to push received data into a `QuicStream`.
pub struct StreamReadHandle {
    pub stream_id: u64,
    pub tx: mpsc::UnboundedSender<io::Result<Vec<u8>>>,
}

/// A bidirectional QUIC stream that implements [`AsyncRead`] and [`AsyncWrite`].
///
/// Each instance is associated with a single QUIC stream on a single connection.
/// The actual QUIC I/O is driven by the listener event loop; this type bridges
/// into the standard tokio async I/O interfaces.
pub struct QuicStream {
    conn_id: u64,
    stream_id: u64,
    /// Receives data forwarded by the connection driver.
    read_rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    /// Sends data to the connection driver for transmission.
    write_tx: mpsc::UnboundedSender<StreamWrite>,
    /// Partial read buffer (leftover from a previous read when the caller's buffer was smaller).
    read_buf: Vec<u8>,
    /// Offset into `read_buf` for the next read.
    read_offset: usize,
    /// Whether the read side has reached EOF.
    read_closed: bool,
}

impl QuicStream {
    /// Creates a new `QuicStream` and the corresponding [`StreamReadHandle`] for the driver.
    pub fn new(
        conn_id: u64,
        stream_id: u64,
        write_tx: mpsc::UnboundedSender<StreamWrite>,
        _read_buffer_size: usize,
    ) -> (Self, StreamReadHandle) {
        let (read_tx, read_rx) = mpsc::unbounded_channel();

        let stream = Self {
            conn_id,
            stream_id,
            read_rx,
            write_tx,
            read_buf: Vec::new(),
            read_offset: 0,
            read_closed: false,
        };

        let handle = StreamReadHandle { stream_id, tx: read_tx };

        (stream, handle)
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Returns true if there is buffered data available for immediate reading.
    fn has_buffered_data(&self) -> bool {
        self.read_offset < self.read_buf.len()
    }

    /// Consume buffered data into the caller's read buffer.
    fn drain_buffered(&mut self, buf: &mut ReadBuf<'_>) {
        let remaining = &self.read_buf[self.read_offset..];
        let to_copy = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..to_copy]);
        self.read_offset += to_copy;

        // Reset buffer when fully consumed.
        if self.read_offset >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_offset = 0;
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Serve from the internal buffer first.
        if self.has_buffered_data() {
            self.drain_buffered(buf);
            return Poll::Ready(Ok(()));
        }

        if self.read_closed {
            return Poll::Ready(Ok(())); // EOF
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                if data.is_empty() {
                    // Empty chunk signals EOF.
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }

                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    // Store the remainder for the next read.
                    self.read_buf = data;
                    self.read_offset = to_copy;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => {
                // Channel closed — treat as EOF.
                self.read_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Unbounded sender never blocks — always ready.
        let write = StreamWrite {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data: buf.to_vec(),
        };

        match self.write_tx.send(write) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC connection driver closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flushing is driven by the connection event loop; nothing to do here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send a zero-length write to signal shutdown to the driver.
        let _ = self.write_tx.send(StreamWrite {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data: Vec::new(),
        });
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn basic_read_write() {
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<StreamWrite>();
        let (mut stream, read_handle) = QuicStream::new(1, 4, write_tx, 16);

        // Simulate driver pushing data.
        read_handle.tx.send(Ok(b"hello world".to_vec())).unwrap();

        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        // Read remainder from internal buffer.
        let mut buf2 = [0u8; 20];
        let n2 = stream.read(&mut buf2).await.unwrap();
        assert_eq!(n2, 6);
        assert_eq!(&buf2[..6], b" world");

        // Write data.
        let n = stream.write(b"response").await.unwrap();
        assert_eq!(n, 8);

        let written = write_rx.recv().await.unwrap();
        assert_eq!(written.stream_id, 4);
        assert_eq!(written.data, b"response");
    }

    #[tokio::test]
    async fn eof_on_empty_data() {
        let (write_tx, _write_rx) = mpsc::unbounded_channel::<StreamWrite>();
        let (mut stream, read_handle) = QuicStream::new(1, 0, write_tx, 16);

        // Signal EOF.
        read_handle.tx.send(Ok(Vec::new())).unwrap();

        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[tokio::test]
    async fn eof_on_channel_close() {
        let (write_tx, _write_rx) = mpsc::unbounded_channel::<StreamWrite>();
        let (mut stream, read_handle) = QuicStream::new(1, 0, write_tx, 16);

        drop(read_handle);

        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[tokio::test]
    async fn write_after_driver_close() {
        let (write_tx, write_rx) = mpsc::unbounded_channel::<StreamWrite>();
        let (mut stream, _read_handle) = QuicStream::new(1, 0, write_tx, 16);

        drop(write_rx);

        let result = stream.write(b"data").await;
        assert!(result.is_err());
    }
}
