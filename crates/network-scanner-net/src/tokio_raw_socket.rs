use std::{io::{Read, Write}, net::Ipv4Addr};

use socket2::SockAddr;
use std::result::Result::Ok;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct TokioRawSocketStream {
    socket: socket2::Socket,
}

impl TokioRawSocketStream {
    pub async fn connect(ip: impl Into<Ipv4Addr>) -> std::io::Result<TokioRawSocketStream> {
        let socket_addr = std::net::SocketAddrV4::new(ip.into(), 0); // raw sockets don't need a port
        let socket_addr = SockAddr::from(socket_addr);
        tracing::trace!("Connecting to {:?}", &socket_addr);
        let socket = tokio::task::spawn_blocking(move || {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::RAW,
                Some(socket2::Protocol::ICMPV4),
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            socket
                .connect(&socket_addr)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            socket
                .set_nonblocking(true)?;

            tracing::trace!("Connected to {:?}", &socket_addr);
            Ok(socket)
        })
        .await?
        .map_err(|e:std::io::Error| e)?;

        Ok(TokioRawSocketStream { socket })
    }

}

impl AsyncRead for TokioRawSocketStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut buffer = [0u8; 8096];
        match self.socket.read(&mut buffer) {
            Ok(size) => {
                tracing::trace!("Read {} bytes, buffer = {:?}", size, &buffer[..size]);
                buf.put_slice(&buffer[..size]);
                std::task::Poll::Ready(Ok(()))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(e))
                }
            }
        }
    }
}

impl AsyncWrite for TokioRawSocketStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.socket.write(buf) {
            Ok(size) => std::task::Poll::Ready(Ok(size)),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(e))
                }
            }
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.socket.flush() {
            Ok(_) => std::task::Poll::Ready(Ok(())),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(e))
                }
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.socket.shutdown(std::net::Shutdown::Both) {
            Ok(_) => std::task::Poll::Ready(Ok(())),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(e))
                }
            }
        }
    }
}

impl Unpin for TokioRawSocketStream {}
