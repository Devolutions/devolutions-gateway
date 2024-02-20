use polling::Event;
use std::{fmt::Debug, future::Future, mem::MaybeUninit, sync::Arc, usize};

use socket2::{SockAddr, Socket};
use std::result::Result::Ok;

use crate::runtime::Socket2Runtime;

/// A wrapper on raw socket that can be used with a IO event loop provided by `Socket2Runtime`.
pub struct AsyncRawSocket {
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
}

impl Debug for AsyncRawSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncRawSocket")
            .field("socket", &self.socket)
            .field("id", &self.id)
            .finish()
    }
}

impl Drop for AsyncRawSocket {
    fn drop(&mut self) {
        // We ignore errors here, avoid crashing the thread.
        let _ = self
            .runtime
            .remove_socket(&self.socket, self.id)
            .inspect_err(|e| error!(error = format!("{e:#}"), "Failed to remove socket from poller"));
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

impl Drop for RecvFromFuture<'_> {
    fn drop(&mut self) {
        self.runtime.remove_event_from_history(Event::readable(self.id));
        let _ = self.runtime.unregister(Event::readable(self.id));
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

impl Drop for SendToFuture<'_> {
    fn drop(&mut self) {
        self.runtime.remove_event_from_history(Event::writable(self.id));
        let _ = self.runtime.unregister(Event::writable(self.id));
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

impl Drop for AcceptFuture {
    fn drop(&mut self) {
        self.runtime.remove_event_from_history(Event::readable(self.id));
        let _ = self.runtime.unregister(Event::readable(self.id));
    }
}

struct ConnectFuture<'a> {
    socket: Arc<socket2::Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
    addr: &'a socket2::SockAddr,
}

impl<'a> Future for ConnectFuture<'a> {
    type Output = std::io::Result<()>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let events = self.runtime.check_event_with_id(self.id);
        for event in events {
            trace!(?event, "Event found");
            if event
                .is_err() // For linux, failed connection is ERR and HUP, a sigle HUP does not indicate a failed connection
                .expect("your platform does not support connect failed")
            {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "connection failed",
                )));
            }

            // This is a special case, this happens when using epoll to wait for a unconnected TCP socket.
            // We clearly needs to call connect function, so we break the loop and call connect.
            #[cfg(target_os = "linux")]
            if event.is_interrupt() && !event.is_err().expect("your platform does not support connect failed") {
                trace!("out and hup");
                self.runtime.remove_events_with_id_from_history(self.id);
                break;
            }

            if event.writable || event.readable {
                self.runtime.remove_events_with_id_from_history(self.id);
                return std::task::Poll::Ready(Ok(()));
            }
        }

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

        let events_interested = [Event::readable(self.id), Event::writable(self.id), Event::all(self.id)];
        if in_progress {
            if let Err(e) = self
                .runtime
                .register_events(&self.socket, &events_interested, cx.waker().clone())
            {
                warn!(error = format!("{e:#}"), ?self.socket, ?self.addr, "Failed to register socket to poller");
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to register socket to poller: {}", e),
                )));
            }
        }
        std::task::Poll::Pending
    }
}

impl Drop for ConnectFuture<'_> {
    fn drop(&mut self) {
        self.runtime.remove_events_with_id_from_history(self.id);
        let events = [Event::readable(self.id), Event::writable(self.id), Event::all(self.id)];
        events.into_iter().for_each(|event| {
            self.runtime.remove_event_from_history(event);
        });
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

impl Drop for SendFuture<'_> {
    fn drop(&mut self) {
        self.runtime.remove_event_from_history(Event::writable(self.id));
        let _ = self.runtime.unregister(Event::writable(self.id));
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

impl Drop for RecvFuture<'_> {
    fn drop(&mut self) {
        self.runtime.remove_event_from_history(Event::readable(self.id));
        let _ = self.runtime.unregister(Event::readable(self.id));
    }
}

fn resolve<T>(
    error: std::io::Error,
    socket: &Arc<Socket>,
    runtime: &Arc<Socket2Runtime>,
    event: Event,
    waker: &std::task::Waker,
) -> std::task::Poll<std::io::Result<T>> {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        if let Err(e) = runtime.register(socket, event, waker.clone()) {
            warn!(
                error = format!("{e:#}"),
                ?socket,
                ?event,
                "Failed to register socket to poller"
            );
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to register socket to poller: {}", e),
            )));
        }

        return std::task::Poll::Pending;
    }

    warn!(%error, "Operation failed");

    std::task::Poll::Ready(Err(error))
}
