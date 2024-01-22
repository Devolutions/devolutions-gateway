use polling::Event;
use std::{future::Future, mem::MaybeUninit, sync::Arc, usize};

use socket2::{SockAddr, Socket};
use std::result::Result::Ok;

use crate::runtime::Socket2Runtime;

/// A wrapper on raw socket that can be used with a IO event loop provided by `Socket2Runtime`.
pub struct AsyncRawSocket {
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
}

impl Drop for AsyncRawSocket {
    fn drop(&mut self) {
        tracing::trace!(id = %self.id,socket = ?self.socket, "drop socket");
        let _ = self // We ignore errors here, avoid crashing the thread
            .runtime
            .remove_socket(&self.socket)
            .map_err(|e| tracing::error!("failed to remove socket from poller: {:?}", e));
    }
}

impl AsyncRawSocket {
    // Raw socket creation must be done through a `Socket2Runtime`,
    // and this function is `pub(crate)` instead of `pub` on purpose.
    pub(crate) fn from_socket(
        socket: socket2::Socket,
        id: usize,
        runtime: Arc<Socket2Runtime>,
    ) -> std::io::Result<AsyncRawSocket> {
        let socket = Arc::new(socket);
        socket.set_nonblocking(true)?;
        Ok(AsyncRawSocket { socket, id, runtime })
    }

    pub fn bind(&self, addr: &SockAddr) -> std::io::Result<()> {
        self.socket.bind(addr)
    }

    pub async fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.socket.set_ttl(ttl)
    }

    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> std::io::Result<()> {
        self.socket.set_read_timeout(Some(timeout))
    }

    pub fn set_broadcast(&self, broadcast: bool) -> std::io::Result<()> {
        self.socket.set_broadcast(broadcast)
    }
}

impl<'a> AsyncRawSocket {
    #[tracing::instrument(skip(self, buf))]
    pub fn recv_from(
        &'a mut self,
        buf: &'a mut [MaybeUninit<u8>],
    ) -> impl Future<Output = std::io::Result<(usize, SockAddr)>> + 'a {
        RecvFromFuture {
            socket: self.socket.clone(),
            buf,
            id: self.id,
            runtime: self.runtime.clone(),
        }
    }

    #[tracing::instrument(skip(self, data))]
    pub fn send_to(
        &self,
        data: &'a [u8],
        addr: &'a socket2::SockAddr,
    ) -> impl Future<Output = std::io::Result<usize>> + 'a {
        SendToFuture {
            socket: self.socket.clone(),
            runtime: self.runtime.clone(),
            data,
            addr,
            id: self.id,
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn accept(&self) -> impl Future<Output = std::io::Result<(AsyncRawSocket, SockAddr)>> {
        AcceptFuture {
            socket: self.socket.clone(),
            runtime: self.runtime.clone(),
            id: self.id,
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn connect(&self, addr: &'a SockAddr) -> impl Future<Output = std::io::Result<()>> + 'a {
        ConnectFuture {
            socket: self.socket.clone(),
            runtime: self.runtime.clone(),
            addr,
            id: self.id,
            is_first_poll: true,
        }
    }

    #[tracing::instrument(skip(self, data))]
    pub fn send(&mut self, data: &'a [u8]) -> impl Future<Output = std::io::Result<usize>> + 'a {
        SendFuture {
            socket: self.socket.clone(),
            runtime: self.runtime.clone(),
            data,
            id: self.id,
        }
    }

    #[tracing::instrument(skip(self, buf))]
    pub fn recv(&mut self, buf: &'a mut [MaybeUninit<u8>]) -> impl Future<Output = std::io::Result<usize>> + 'a {
        RecvFuture {
            socket: self.socket.clone(),
            buf,
            id: self.id,
            runtime: self.runtime.clone(),
        }
    }
}

struct RecvFromFuture<'a> {
    socket: Arc<socket2::Socket>,
    buf: &'a mut [MaybeUninit<u8>],
    id: usize,
    runtime: Arc<Socket2Runtime>,
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
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
    data: &'a [u8],
    addr: &'a socket2::SockAddr,
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

struct AcceptFuture {
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
}

impl Future for AcceptFuture {
    type Output = std::io::Result<(AsyncRawSocket, SockAddr)>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        match self.socket.accept() {
            Ok((socket, addr)) => {
                let socket = AsyncRawSocket::from_socket(socket, self.id, self.runtime.clone())?;
                std::task::Poll::Ready(Ok((socket, addr)))
            }
            Err(e) => resolve(e, &self.socket, &self.runtime, Event::readable(self.id), cx.waker()),
        }
    }
}
struct ConnectFuture<'a> {
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
    addr: &'a socket2::SockAddr,
    is_first_poll: bool,
}

impl<'a> Future for ConnectFuture<'a> {
    type Output = std::io::Result<()>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        if self.is_first_poll {
            tracing::trace!("first poll connect future");
            // cannot call connect twice
            self.is_first_poll = false;
            let err = match self.socket.connect(self.addr) {
                Ok(a) => {
                    return std::task::Poll::Ready(Ok(a));
                }
                Err(e) => e,
            };

            // code 115, EINPROGRESS, only for linux
            // reference: https://linux.die.net/man/2/connect
            // it is the same as WouldBlock but for connect(2) only
            #[cfg(target_os = "linux")]
            let in_progress = err.kind() == std::io::ErrorKind::WouldBlock || err.raw_os_error() == Some(115);

            #[cfg(not(target_os = "linux"))]
            let in_progress = err.kind() == std::io::ErrorKind::WouldBlock;

            if in_progress {
                tracing::trace!("connect should register");
                if let Err(e) = self
                    .runtime
                    .register(&self.socket, Event::writable(self.id), cx.waker().clone())
                {
                    tracing::warn!(?self.socket, ?self.addr, "failed to register socket to poller");
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to register socket to poller: {}", e),
                    )));
                }
                return std::task::Poll::Pending;
            }
        }
        tracing::trace!("second poll connect future");
        std::task::Poll::Ready(Ok(()))
    }
}

struct SendFuture<'a> {
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
    data: &'a [u8],
}

impl<'a> Future for SendFuture<'a> {
    type Output = std::io::Result<usize>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        match self.socket.send(self.data) {
            Ok(a) => std::task::Poll::Ready(Ok(a)),
            Err(e) => resolve(e, &self.socket, &self.runtime, Event::writable(self.id), cx.waker()),
        }
    }
}

struct RecvFuture<'a> {
    socket: Arc<socket2::Socket>,
    buf: &'a mut [MaybeUninit<u8>],
    id: usize,
    runtime: Arc<Socket2Runtime>,
}

impl<'a> Future for RecvFuture<'a> {
    type Output = std::io::Result<usize>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let socket = &self.socket.clone(); // avoid borrow checker error
        match socket.recv(self.buf) {
            Ok(a) => std::task::Poll::Ready(Ok(a)),
            Err(e) => resolve(e, &self.socket, &self.runtime, Event::readable(self.id), cx.waker()),
        }
    }
}

/// Non-blocking socket does not work with timeout, so we need impl Drop for unregistering socket from poller
/// Impl Drop for unregistering socket from poller, the caller can use other async timer for timeout
macro_rules! impl_drop {
    ($type:ty) => {
        impl Drop for $type {
            fn drop(&mut self) {
                tracing::trace!(id = %self.id,socket = ?self.socket, "drop future");
                let _ = self.runtime.unregister(self.id);
            }
        }
    };
}

impl_drop!(RecvFromFuture<'_>);
impl_drop!(SendToFuture<'_>);
impl_drop!(AcceptFuture);
impl_drop!(ConnectFuture<'_>);
impl_drop!(SendFuture<'_>);
impl_drop!(RecvFuture<'_>);

fn resolve<T>(
    err: std::io::Error,
    socket: &Arc<Socket>,
    runtime: &Arc<Socket2Runtime>,
    event: Event,
    waker: &std::task::Waker,
) -> std::task::Poll<std::io::Result<T>> {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        tracing::trace!(?event, "operation would block");
        if let Err(e) = runtime.register(socket, event, waker.clone()) {
            tracing::warn!(?socket, ?event, "failed to register socket to poller");
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to register socket to poller: {}", e),
            )));
        }

        return std::task::Poll::Pending;
    }

    tracing::warn!(?err, "operation failed");
    std::task::Poll::Ready(Err(err))
}
