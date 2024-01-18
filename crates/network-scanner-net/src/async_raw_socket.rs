use polling::Event;
use std::{future::Future, mem::MaybeUninit, sync::Arc, usize};

use socket2::{SockAddr, Socket};
use std::result::Result::Ok;

use crate::async_io::Socket2Runtime;

/// A wrapper on raw socket that can be used with async runtime
pub struct AsyncRawSocket {
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
}

impl Drop for AsyncRawSocket {
    fn drop(&mut self) {
        self.runtime
            .remove_socket(&self.socket)
            .map_err(|e| tracing::error!("failed to remove socket from poller: {:?}", e))
            .ok(); // ignore the error
    }
}

impl AsyncRawSocket {
    // prevent direct instantiation
    pub(crate) fn from_socket(
        socket: socket2::Socket,
        id: usize,
        runtime: Arc<Socket2Runtime>,
    ) -> std::io::Result<AsyncRawSocket> {
        socket.set_nonblocking(true)?;
        let socket = Arc::new(socket);
        Ok(AsyncRawSocket { socket, id, runtime })
    }

    pub fn send_to<'short>(
        &self,
        data: &'short [u8],
        addr: &'short socket2::SockAddr,
    ) -> impl Future<Output = std::io::Result<usize>> + 'short {
        SendToFuture {
            socket: self.socket.clone(),
            runtime: self.runtime.clone(),
            data,
            addr,
            id: self.id,
        }
    }

    pub fn recv_from<'a>(
        &'a self,
        buf: &'a mut [MaybeUninit<u8>],
    ) -> impl Future<Output = std::io::Result<(usize, SockAddr)>> + 'a {
        RecvFromFuture {
            socket: self.socket.clone(),
            buf,
            id: self.id,
            runtime: self.runtime.clone(),
        }
    }

    pub async fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.socket.as_ref().set_ttl(ttl)
    }

    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> std::io::Result<()> {
        self.socket.as_ref().set_read_timeout(Some(timeout))
    }

    pub fn set_broadcast(&self, broadcast: bool) -> std::io::Result<()> {
        self.socket.as_ref().set_broadcast(broadcast)
    }
}

struct RecvFromFuture<'a> {
    pub socket: Arc<socket2::Socket>,
    pub buf: &'a mut [MaybeUninit<u8>],
    pub id: usize,
    pub runtime: Arc<Socket2Runtime>,
}

impl Future for RecvFromFuture<'_> {
    type Output = std::io::Result<(usize, SockAddr)>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let socket = &self.socket.clone(); // avoid borrow checker error
        match socket.recv_from(self.buf) {
            Ok(a) => std::task::Poll::Ready(Ok(a)),
            Err(e) => resolve(e, &self.socket, &self.runtime, Event::readable(self.id), cx.waker()),
        }
    }
}

struct SendToFuture<'a> {
    pub socket: Arc<socket2::Socket>,
    pub runtime: Arc<Socket2Runtime>,
    pub id: usize,
    pub data: &'a [u8],
    pub addr: &'a socket2::SockAddr,
}

impl<'a> Future for SendToFuture<'a> {
    type Output = std::io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        match self.socket.send_to(self.data, self.addr) {
            Ok(a) => std::task::Poll::Ready(Ok(a)),
            Err(e) => resolve(e, &self.socket, &self.runtime, Event::writable(self.id), cx.waker()),
        }
    }
}

fn resolve<T>(
    e: std::io::Error,
    socket: &Arc<Socket>,
    runtime: &Arc<Socket2Runtime>,
    event: Event,
    waker: &std::task::Waker,
) -> std::task::Poll<std::io::Result<T>> {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        tracing::trace!("operation would block");
        if let Err(e) = runtime.register(socket.clone(), event, waker.clone()) {
            tracing::warn!("failed to register socket to poller: {:?}", e);
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to register socket to event loop",
            )));
        }
        std::task::Poll::Pending
    } else {
        std::task::Poll::Ready(Err(e))
    }
}
