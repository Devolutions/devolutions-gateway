
use polling::Event;
use std::{
    future::Future,
    mem::MaybeUninit,
    sync::Arc,
    usize,
};

use socket2::SockAddr;
use std::result::Result::Ok;

use crate::async_io::AsyncIoHandle;

/// A wrapper on raw socket that can be used with async tokio runtime
/// This currently only throws the blocking calls on a blocking thread pool
/// In the future, this should be replaced with a non-blocking implementation that takes advantage of OS specific async APIs
/// We are seeking to match the function signatures of socket2::Socket, but in async form
pub struct TokioRawSocket {
    socket: Arc<socket2::Socket>,
    id: usize,
    handle: AsyncIoHandle,
}

macro_rules! lock_socket {
    ($socket:expr) => {
        $socket
    };
}

impl TokioRawSocket {
    pub fn from_socket(socket: socket2::Socket, id: usize, handle: AsyncIoHandle) -> std::io::Result<TokioRawSocket> {
        socket.set_nonblocking(true)?;
        let socket = Arc::new(socket);
        Ok(TokioRawSocket { socket, id, handle })
    }

    pub async fn send_to(&self, data: &[u8], addr: socket2::SockAddr) -> std::io::Result<usize> {
        tracing::trace!(?data, ?addr, "send_to");
        let socket = self.socket.clone();
        let cloned_data = data.to_vec();
        let res = tokio::task::spawn_blocking(move || socket.send_to(cloned_data.as_ref(), &addr)).await??;

        Ok(res)
    }

    pub fn recv_from<'a>(
        &'a self,
        buf: &'a mut [MaybeUninit<u8>],
    ) -> impl Future<Output = std::io::Result<(usize, SockAddr)>> + 'a {
        RecvFromFuture {
            socket: self.socket.clone(),
            buf,
            id: self.id,
            handle: self.handle.clone(),
        }
    }

    pub async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        let socket = self.socket.clone();
        let cloned_data = data.to_vec();
        let res = tokio::task::spawn_blocking(move || lock_socket!(socket).send(cloned_data.as_ref())).await??;

        Ok(res)
    }

    pub async fn connect(&self, addr: socket2::SockAddr) -> std::io::Result<()> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || lock_socket!(socket).connect(&addr)).await??;

        Ok(())
    }

    pub async fn bind(&self, addr: socket2::SockAddr) -> std::io::Result<()> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || lock_socket!(socket).bind(&addr)).await??;
        Ok(())
    }

    pub async fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        lock_socket!(self.socket.clone()).set_ttl(ttl)
    }

    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> std::io::Result<()> {
        lock_socket!(self.socket.clone()).set_read_timeout(Some(timeout))
    }

    pub fn set_broadcast(&self, broadcast: bool) -> std::io::Result<()> {
        lock_socket!(self.socket.clone()).set_broadcast(broadcast)
    }
}

struct RecvFromFuture<'a> {
    pub socket: Arc<socket2::Socket>,
    pub buf: &'a mut [MaybeUninit<u8>],
    pub id: usize,
    pub handle: AsyncIoHandle,
}

impl Future for RecvFromFuture<'_> {
    type Output = std::io::Result<(usize, SockAddr)>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        tracing::trace!("polling recv_from future");
        let mut buf = vec![MaybeUninit::uninit(); self.buf.len()];
        match self.socket.recv_from(&mut buf) {
            Ok(a) => {
                self.buf.copy_from_slice(&buf);
                std::task::Poll::Ready(Ok(a))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    tracing::trace!("recv_from would block");
                    let socket = self.socket.clone();
                    let id = self.id;
                    if self
                        .handle
                        .awake(socket.clone(), Event::readable(id), cx.waker().clone())
                        .is_err()
                    {
                        tracing::warn!("failed to awake socket");
                        cx.waker().wake_by_ref();
                    }

                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(e))
                }
            }
        }
    }
}
