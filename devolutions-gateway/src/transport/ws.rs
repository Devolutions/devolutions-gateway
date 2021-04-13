use crate::transport::{JetFuture, JetSinkImpl, JetSinkType, JetStreamImpl, JetStreamType, Transport};
use crate::utils::{danger_transport, resolve_url_to_socket_arr};
use futures::{ready, Sink, Stream};
use hyper::upgrade::Upgraded;
use spsc_bip_buffer::{BipBufferReader, BipBufferWriter};
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_compat_02::IoCompat;
use tokio_rustls::{rustls, TlsConnector, TlsStream};
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::{tungstenite, WebSocketStream};
use url::Url;

enum WsStreamSendState {
    Idle,
    SendInProgress,
}

pub struct WsStream {
    inner: WsStreamWrapper,
    previous_message: Option<Cursor<Vec<u8>>>,
    previous_send_state: WsStreamSendState,
}

impl WsStream {
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    pub async fn shutdown(&mut self) -> Result<(), std::io::Error> {
        self.inner.shutdown().await
    }
}

impl From<WsStreamWrapper> for WsStream {
    fn from(wrapper: WsStreamWrapper) -> Self {
        WsStream {
            inner: wrapper,
            previous_message: None,
            previous_send_state: WsStreamSendState::Idle,
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.previous_message.take() {
            Some(mut message) => {
                ready!(Pin::new(&mut message).poll_read(cx, buf))?;

                slog_scope::trace!(
                    "Received next part of WebSockets message ({} of {} bytes read)",
                    message.position(),
                    message.get_ref().len()
                );

                if message.position() == message.get_ref().len() as u64 {
                    slog_scope::trace!("Segmented message was completely read");
                    self.previous_message = None;
                } else {
                    self.previous_message = Some(message);
                }

                Poll::Ready(Ok(()))
            }
            None => {
                let message_result = match self.inner {
                    WsStreamWrapper::Http((ref mut stream, _)) => Pin::new(stream).poll_next(cx),
                    WsStreamWrapper::Tcp((ref mut stream, _)) => Pin::new(stream).poll_next(cx),
                    WsStreamWrapper::Tls((ref mut stream, _)) => Pin::new(stream).poll_next(cx),
                };

                let message = ready!(message_result)
                    .map(|e| e.map_err(tungstenite_err_to_io_err))
                    .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::Other, "Connection closed".to_string())))?;

                slog_scope::trace!(
                    "New {} message received (length: {} bytes)",
                    tungstenite_message_type_to_string(&message),
                    message.len()
                );

                if (message.is_binary() || message.is_text()) && !message.is_empty() {
                    let mut message = Cursor::new(message.into_data());

                    match Pin::new(&mut message).poll_read(cx, buf) {
                        Poll::Ready(Ok(_)) => {
                            if message.position() < message.get_ref().len() as u64 {
                                // Current WS message is not yet read completely, provided input buffer
                                // has been overflowed
                                slog_scope::trace!(
                                    "Received first part of WebSockets message ({} of {} bytes read)",
                                    message.position(),
                                    message.get_ref().len()
                                );
                                self.previous_message = Some(message);
                            }
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => {
                            // Generally, with Cursor's poll_read this should not be triggered,
                            // but we will keep that here as a safe measure if something will
                            // change in the Cursor in the future
                            self.previous_message = Some(message);
                            Poll::Pending
                        }
                    }
                } else {
                    // Skip non-text / non-binary messages and wait for more data
                    cx.waker().clone().wake();
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        match self.previous_send_state {
            WsStreamSendState::Idle => {
                let message = tungstenite::Message::Binary(buf.to_vec());
                let result = match self.inner {
                    WsStreamWrapper::Http((ref mut stream, _)) => {
                        let mut pinned = Pin::new(stream);
                        ready!(pinned.as_mut().poll_ready(cx)).map_err(tungstenite_err_to_io_err)?;
                        pinned.as_mut().start_send(message).map_err(tungstenite_err_to_io_err)
                    }
                    WsStreamWrapper::Tcp((ref mut stream, ref mut _addr)) => {
                        let mut pinned = Pin::new(stream);
                        ready!(pinned.as_mut().poll_ready(cx)).map_err(tungstenite_err_to_io_err)?;
                        pinned.as_mut().start_send(message).map_err(tungstenite_err_to_io_err)
                    }
                    WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) => {
                        let mut pinned = Pin::new(stream);
                        ready!(pinned.as_mut().poll_ready(cx)).map_err(tungstenite_err_to_io_err)?;
                        pinned.as_mut().start_send(message).map_err(tungstenite_err_to_io_err)
                    }
                };

                match result {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.previous_send_state = WsStreamSendState::SendInProgress;
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            WsStreamSendState::SendInProgress => {
                let result = match self.inner {
                    WsStreamWrapper::Http((ref mut stream, _)) => Pin::new(stream).poll_flush(cx),
                    WsStreamWrapper::Tcp((ref mut stream, ref mut _addr)) => Pin::new(stream).poll_flush(cx),
                    WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) => Pin::new(stream).poll_flush(cx),
                };

                result
                    .map_ok(|_| {
                        self.previous_send_state = WsStreamSendState::Idle;
                        buf.len()
                    })
                    .map_err(tungstenite_err_to_io_err)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let result = match self.inner {
            WsStreamWrapper::Http((ref mut stream, _)) => Pin::new(stream).poll_flush(cx),
            WsStreamWrapper::Tcp((ref mut stream, _)) => Pin::new(stream).poll_flush(cx),
            WsStreamWrapper::Tls((ref mut stream, _)) => Pin::new(stream).poll_flush(cx),
        };

        result.map_err(tungstenite_err_to_io_err)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let result = match self.inner {
            WsStreamWrapper::Http((ref mut stream, _)) => Pin::new(stream).poll_close(cx),
            WsStreamWrapper::Tcp((ref mut stream, _)) => Pin::new(stream).poll_close(cx),
            WsStreamWrapper::Tls((ref mut stream, _)) => Pin::new(stream).poll_close(cx),
        };

        result.map_err(tungstenite_err_to_io_err)
    }
}

#[allow(clippy::large_enum_variant)]
pub enum WsStreamWrapper {
    Http((WebSocketStream<IoCompat<Upgraded>>, Option<SocketAddr>)),
    Tcp((WebSocketStream<TcpStream>, Option<SocketAddr>)),
    Tls((WebSocketStream<TlsStream<TcpStream>>, Option<SocketAddr>)),
}

impl WsStreamWrapper {
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            WsStreamWrapper::Http((_stream, addr)) => *addr,
            WsStreamWrapper::Tcp((_stream, addr)) => *addr,
            WsStreamWrapper::Tls((_stream, addr)) => *addr,
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), std::io::Error> {
        match self {
            WsStreamWrapper::Http((stream, _)) => stream
                .close(None)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            WsStreamWrapper::Tcp((stream, _)) => stream
                .close(None)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            WsStreamWrapper::Tls((stream, _)) => stream
                .close(None)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

pub struct WsTransport {
    stream: WsStream,
    nb_bytes_read: Arc<AtomicU64>,
    nb_bytes_written: Arc<AtomicU64>,
}

impl WsTransport {
    pub async fn new_http(upgraded: Upgraded, addr: Option<SocketAddr>) -> Self {
        let compat_stream = IoCompat::new(upgraded);
        WsTransport {
            stream: WsStreamWrapper::Http((
                WebSocketStream::from_raw_socket(compat_stream, Role::Server, None).await,
                addr,
            ))
            .into(),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tcp(stream: WebSocketStream<TcpStream>, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: WsStreamWrapper::Tcp((stream, addr)).into(),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tls(stream: WebSocketStream<TlsStream<TcpStream>>, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: WsStreamWrapper::Tls((stream, addr)).into(),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn clone_nb_bytes_read(&self) -> Arc<AtomicU64> {
        self.nb_bytes_read.clone()
    }

    pub fn clone_nb_bytes_written(&self) -> Arc<AtomicU64> {
        self.nb_bytes_written.clone()
    }

    async fn async_connect(url: Url) -> Result<Self, std::io::Error> {
        let socket_addr = if let Some(addr) = resolve_url_to_socket_arr(&url).await {
            addr
        } else {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("couldn't resolve {}", url),
            ));
        };

        let request = match Request::builder().uri(url.as_str()).body(()) {
            Ok(req) => req,
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };

        match url.scheme() {
            "ws" => {
                let stream = TcpStream::connect(&socket_addr)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let peer_addr = stream.peer_addr().ok();
                match tokio_tungstenite::client_async(request, stream).await {
                    Ok((stream, _)) => Ok(WsTransport::new_tcp(stream, peer_addr)),
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                }
            }
            "wss" => {
                let tcp_stream = TcpStream::connect(&socket_addr)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                let mut client_config = rustls::ClientConfig::default();
                client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(danger_transport::NoCertificateVerification));
                let config_ref = Arc::new(client_config);
                let cx = TlsConnector::from(config_ref);
                let dns_name = webpki::DNSNameRef::try_from_ascii_str("stub_string").unwrap();

                let tls_stream = cx.connect(dns_name, tcp_stream).await?;
                let peer_addr = tls_stream.get_ref().0.peer_addr().ok();

                match tokio_tungstenite::client_async(request, TlsStream::Client(tls_stream)).await {
                    Ok((stream, _)) => Ok(WsTransport::new_tls(stream, peer_addr)),
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                }
            }
            scheme => {
                panic!("Unsupported scheme: {}", scheme);
            }
        }
    }
}

impl AsyncRead for WsTransport {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for WsTransport {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Transport for WsTransport {
    fn connect(url: &Url) -> JetFuture<Self>
    where
        Self: Sized,
    {
        Box::pin(Self::async_connect(url.clone()))
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.peer_addr()
    }

    fn split_transport(
        self,
        buffer_writer: BipBufferWriter,
        buffer_reader: BipBufferReader,
    ) -> (JetStreamType<usize>, JetSinkType<usize>) {
        let peer_addr = self.peer_addr();
        let (reader, writer) = tokio::io::split(self.stream);

        let stream = Box::pin(JetStreamImpl::new(reader, self.nb_bytes_read, peer_addr, buffer_writer));
        let sink = Box::pin(JetSinkImpl::new(
            writer,
            self.nb_bytes_written,
            peer_addr,
            buffer_reader,
        ));

        (stream, sink)
    }
}

fn tungstenite_err_to_io_err(err: tungstenite::Error) -> io::Error {
    match err {
        tungstenite::Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::Other, other),
    }
}

fn tungstenite_message_type_to_string(msg: &tungstenite::Message) -> &str {
    match msg {
        tungstenite::Message::Text(_) => "Text",
        tungstenite::Message::Binary(_) => "Binary",
        tungstenite::Message::Ping(_) => "Ping",
        tungstenite::Message::Pong(_) => "Pong",
        tungstenite::Message::Close(_) => "Close",
    }
}
