use std::fmt::Debug;
use std::future::Future;
use std::mem::MaybeUninit;
use std::result::Result::Ok;
use std::sync::Arc;

use polling::Event;
use socket2::{SockAddr, Socket};

use crate::runtime::Socket2Runtime;

/// A wrapper on raw socket that can be used with a IO event loop provided by `Socket2Runtime`.
pub struct AsyncRawSocket {
    socket: Arc<Socket>,
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
        socket: Socket,
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

    /// Bind this socket to a specific network interface by OS index.
    ///
    /// Per-platform mechanism:
    ///
    /// | Platform | Option used                              | Notes                       |
    /// |----------|------------------------------------------|-----------------------------|
    /// | Linux    | `IP_UNICAST_IF` / `IPV6_UNICAST_IF`      | No `CAP_NET_RAW` required.  |
    /// | macOS    | `IP_BOUND_IF` / `IPV6_BOUND_IF`          | Apple-specific socket opts. |
    /// | Windows  | `IP_UNICAST_IF` / `IPV6_UNICAST_IF`      | Via `ws2_32!setsockopt`.    |
    ///
    /// Other platforms return [`std::io::ErrorKind::Unsupported`]. Taking a
    /// [`std::num::NonZeroU32`] makes it impossible to pass the
    /// "unbind / use default routing" sentinel by accident — drop the call
    /// site instead of binding to ifindex 0.
    pub fn bind_to_interface(&self, family: socket2::Domain, if_index: std::num::NonZeroU32) -> std::io::Result<()> {
        bind_socket_to_interface(&self.socket, family, if_index)
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

/// Bind a `socket2::Socket` to a specific interface index.
///
/// Per-platform mechanism (`IP_UNICAST_IF` on Linux + Windows,
/// `IP_BOUND_IF` on macOS — see [`AsyncRawSocket::bind_to_interface`] for
/// the full table). The supported target list is exhaustive: only Linux,
/// macOS, and Windows are valid build targets for this crate, so other
/// platforms intentionally fail to compile rather than silently degrade.
fn bind_socket_to_interface(
    socket: &Socket,
    family: socket2::Domain,
    if_index: std::num::NonZeroU32,
) -> std::io::Result<()> {
    let if_index = if_index.get();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;

        // Resolve (level, name, value) per platform / family. Linux and
        // macOS share the libc::setsockopt call shape, only the constants
        // and IPv4 byte-order differ.
        let (level, name, value): (libc::c_int, libc::c_int, u32) = match (family, cfg!(target_os = "linux")) {
            // Linux
            #[cfg(target_os = "linux")]
            (socket2::Domain::IPV4, _) => {
                // IPPROTO_IP, IP_UNICAST_IF; the kernel expects net-order.
                (0, 50, if_index.to_be())
            }
            #[cfg(target_os = "linux")]
            (socket2::Domain::IPV6, _) => {
                // IPPROTO_IPV6, IPV6_UNICAST_IF; host byte order.
                (41, 76, if_index)
            }
            // macOS
            #[cfg(target_os = "macos")]
            (socket2::Domain::IPV4, _) => {
                // IPPROTO_IP, IP_BOUND_IF
                (0, 25, if_index)
            }
            #[cfg(target_os = "macos")]
            (socket2::Domain::IPV6, _) => {
                // IPPROTO_IPV6, IPV6_BOUND_IF
                (41, 125, if_index)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "interface bind only supported for IPv4 / IPv6 sockets",
                ));
            }
        };

        let fd = socket.as_raw_fd();
        // `socklen_t` is u32 on Linux / macOS but the cast from usize still
        // trips `clippy::cast_possible_truncation` on 64-bit pointer widths;
        // route through `try_from` to document intent.
        let optlen = libc::socklen_t::try_from(size_of::<u32>()).expect("size of u32 fits in socklen_t");
        // SAFETY: `fd` is a valid descriptor borrowed from `socket`;
        // `&value` is a stack pointer valid for the duration of the call.
        let ret = unsafe { libc::setsockopt(fd, level, name, &value as *const u32 as *const libc::c_void, optlen) };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows IP_UNICAST_IF (option 31) takes a u32: net-order for IPv4,
        // host-order for IPv6.
        use std::os::windows::io::AsRawSocket;
        const IPPROTO_IP: i32 = 0;
        const IPPROTO_IPV6: i32 = 41;
        const IP_UNICAST_IF: i32 = 31;
        const IPV6_UNICAST_IF: i32 = 31;
        // `SOCKET` is u64 in the Windows headers; on 32-bit Windows it
        // still fits in `usize` since SOCKET handles never exceed pointer
        // width.
        let raw: usize = usize::try_from(socket.as_raw_socket())
            .map_err(|_| std::io::Error::other("Windows socket handle does not fit in usize on this target"))?;
        let (level, name, value): (i32, i32, u32) = if family == socket2::Domain::IPV4 {
            (IPPROTO_IP, IP_UNICAST_IF, if_index.to_be())
        } else if family == socket2::Domain::IPV6 {
            (IPPROTO_IPV6, IPV6_UNICAST_IF, if_index)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "interface bind only supported for IPv4 / IPv6 sockets",
            ));
        };
        // setsockopt takes optlen as i32; size_of::<u32>() is 4 — the cast
        // is infallible, but try_from documents intent and avoids a lint.
        let optlen = i32::try_from(size_of::<u32>()).expect("size of u32 fits in i32");
        // SAFETY: setsockopt is invoked on a valid Windows socket handle
        // that outlives this call; `&value` lives on the stack across it.
        let ret = unsafe { windows_setsockopt(raw, level, name, &value as *const u32 as *const u8, optlen) };
        if ret == 0 {
            Ok(())
        } else {
            // Winsock surfaces failures through `WSAGetLastError`, not the
            // generic `GetLastError` that `std::io::Error::last_os_error`
            // reads. Going through `last_os_error` here would occasionally
            // yield stale or unrelated codes.
            // SAFETY: WSAGetLastError takes no arguments and is always safe to
            // call from any thread; it reads thread-local state.
            let raw_errno = unsafe { WSAGetLastError() };
            Err(std::io::Error::from_raw_os_error(raw_errno))
        }
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    /// `setsockopt` from `ws2_32.dll`. We deliberately bind the symbol here
    /// instead of pulling in the full `windows-sys` crate so the only
    /// network-scanner-net Windows dependency stays within libstd's
    /// already-linked import library.
    #[link_name = "setsockopt"]
    fn windows_setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "ws2_32")]
unsafe extern "system" {
    /// Winsock's thread-local error accessor. Linked separately from
    /// `windows_setsockopt` so the symbol can be reused by future Winsock
    /// callers without splitting the extern block.
    fn WSAGetLastError() -> i32;
}

impl<'a> AsyncRawSocket {
    #[tracing::instrument(skip(self, buf))]
    pub fn recv_from(
        &'a mut self,
        buf: &'a mut [MaybeUninit<u8>],
    ) -> impl Future<Output = std::io::Result<(usize, SockAddr)>> + 'a {
        RecvFromFuture {
            socket: Arc::clone(&self.socket),
            buf,
            id: self.id,
            runtime: Arc::clone(&self.runtime),
        }
    }

    #[tracing::instrument(skip(self, data))]
    pub fn send_to(&self, data: &'a [u8], addr: &'a SockAddr) -> impl Future<Output = std::io::Result<usize>> + 'a {
        SendToFuture {
            socket: Arc::clone(&self.socket),
            runtime: Arc::clone(&self.runtime),
            data,
            addr,
            id: self.id,
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn accept(&self) -> impl Future<Output = std::io::Result<(AsyncRawSocket, SockAddr)>> {
        AcceptFuture {
            socket: Arc::clone(&self.socket),
            runtime: Arc::clone(&self.runtime),
            id: self.id,
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn connect(&self, addr: &'a SockAddr) -> impl Future<Output = std::io::Result<()>> + 'a {
        ConnectFuture {
            socket: Arc::clone(&self.socket),
            runtime: Arc::clone(&self.runtime),
            addr,
            id: self.id,
        }
    }

    #[tracing::instrument(skip(self, data))]
    pub fn send(&mut self, data: &'a [u8]) -> impl Future<Output = std::io::Result<usize>> + 'a {
        SendFuture {
            socket: Arc::clone(&self.socket),
            runtime: Arc::clone(&self.runtime),
            data,
            id: self.id,
        }
    }

    #[tracing::instrument(skip(self, buf))]
    pub fn recv(&mut self, buf: &'a mut [MaybeUninit<u8>]) -> impl Future<Output = std::io::Result<usize>> + 'a {
        RecvFuture {
            socket: Arc::clone(&self.socket),
            buf,
            id: self.id,
            runtime: Arc::clone(&self.runtime),
        }
    }
}

struct RecvFromFuture<'a> {
    socket: Arc<Socket>,
    buf: &'a mut [MaybeUninit<u8>],
    id: usize,
    runtime: Arc<Socket2Runtime>,
}

impl Future for RecvFromFuture<'_> {
    type Output = std::io::Result<(usize, SockAddr)>;
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let socket = &Arc::clone(&self.socket); // avoid borrow checker error
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
    socket: Arc<Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
    data: &'a [u8],
    addr: &'a SockAddr,
}

impl Future for SendToFuture<'_> {
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
    socket: Arc<Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
}

impl Future for AcceptFuture {
    type Output = std::io::Result<(AsyncRawSocket, SockAddr)>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        match self.socket.accept() {
            Ok((socket, addr)) => {
                let socket = AsyncRawSocket::from_socket(socket, self.id, Arc::clone(&self.runtime))?;
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
    socket: Arc<Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
    addr: &'a SockAddr,
}

impl Future for ConnectFuture<'_> {
    type Output = std::io::Result<()>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let events = self.runtime.check_event_with_id(self.id);
        for event in events {
            trace!(?event, "Event found");
            if event
                .is_err() // For linux, failed connection is ERR and HUP, a sigle HUP does not indicate a failed connection
                .expect("your platform does not support connect failed")
            {
                return std::task::Poll::Ready(Err(std::io::Error::other("connection failed")));
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
        if in_progress
            && let Err(e) = self
                .runtime
                .register_events(&self.socket, &events_interested, cx.waker().clone())
        {
            warn!(error = format!("{e:#}"), ?self.socket, ?self.addr, "Failed to register socket to poller");
            return std::task::Poll::Ready(Err(std::io::Error::other(format!(
                "failed to register socket to poller: {e}"
            ))));
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
    socket: Arc<Socket>,
    runtime: Arc<Socket2Runtime>,
    id: usize,
    data: &'a [u8],
}

impl Future for SendFuture<'_> {
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
    socket: Arc<Socket>,
    buf: &'a mut [MaybeUninit<u8>],
    id: usize,
    runtime: Arc<Socket2Runtime>,
}

impl Future for RecvFuture<'_> {
    type Output = std::io::Result<usize>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let socket = &Arc::clone(&self.socket); // avoid borrow checker error
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
            return std::task::Poll::Ready(Err(std::io::Error::other(format!(
                "failed to register socket to poller: {e}"
            ))));
        }

        return std::task::Poll::Pending;
    }

    warn!(%error, "Operation failed");

    std::task::Poll::Ready(Err(error))
}
