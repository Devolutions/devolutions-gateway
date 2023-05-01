use crate::proxy::{ProxyConfig, ProxyType};
use anyhow::{anyhow, Context as _};
use core::time::Duration;
use futures_util::{future, Future, Sink, Stream};
use proxy_types::{DestAddr, ToDestAddr};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use transport::{ErasedRead, ErasedWrite};

async fn resolve_dest_addr(dest_addr: DestAddr) -> anyhow::Result<SocketAddr> {
    match dest_addr {
        DestAddr::Ip(socket_addr) => Ok(socket_addr),
        DestAddr::Domain(host, port) => tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| "Lookup host failed")?
            .next()
            .ok_or_else(|| anyhow!("Failed to resolve target address")),
    }
}

macro_rules! impl_tcp_connect {
    ($req_addr:expr, $proxy_cfg:expr, $output_ty:ty, $operation:expr) => {{
        use proxy_socks::{Socks4Stream, Socks5Stream};

        let out: $output_ty = match $proxy_cfg {
            Some(ProxyConfig {
                ty: ProxyType::Socks4,
                addr: proxy_addr,
            }) => {
                let stream =
                    Socks4Stream::connect(TcpStream::connect(proxy_addr).await?, $req_addr, "jetsocat").await?;
                $operation(stream).await
            }
            Some(ProxyConfig {
                ty: ProxyType::Socks5,
                addr: proxy_addr,
            }) => {
                let stream = Socks5Stream::connect(TcpStream::connect(proxy_addr).await?, $req_addr).await?;
                $operation(stream).await
            }
            Some(ProxyConfig {
                ty: ProxyType::Socks,
                addr: proxy_addr,
            }) => {
                // unknown SOCKS version, try SOCKS5 first and then SOCKS4
                match Socks5Stream::connect(TcpStream::connect(&proxy_addr).await?, &$req_addr).await {
                    Ok(socks5) => $operation(socks5).await,
                    Err(_) => {
                        let socks4 =
                            Socks4Stream::connect(TcpStream::connect(proxy_addr).await?, $req_addr, "jetsocat").await?;
                        $operation(socks4).await
                    }
                }
            }
            Some(ProxyConfig {
                ty: ProxyType::Http,
                addr: proxy_addr,
            })
            | Some(ProxyConfig {
                ty: ProxyType::Https,
                addr: proxy_addr,
            }) => {
                let stream = proxy_http::ProxyStream::connect(TcpStream::connect(proxy_addr).await?, $req_addr).await?;
                $operation(stream).await
            }
            None => {
                let dest_addr =
                    resolve_dest_addr($req_addr.to_dest_addr().with_context(|| "Invalid target address")?).await?;
                let stream = TcpStream::connect(dest_addr).await?;
                $operation(stream).await
            }
        };
        out
    }};
}

type TcpConnectOutput = (ErasedRead, ErasedWrite);

pub async fn tcp_connect(req_addr: String, proxy_cfg: Option<ProxyConfig>) -> anyhow::Result<TcpConnectOutput> {
    impl_tcp_connect!(req_addr, proxy_cfg, anyhow::Result<TcpConnectOutput>, |stream| {
        let (read, write) = tokio::io::split(stream);
        future::ready(Ok((Box::new(read) as ErasedRead, Box::new(write) as ErasedWrite)))
    })
}

type WebSocketConnectOutput = (ErasedRead, ErasedWrite, Response);

pub async fn ws_connect(addr: String, proxy_cfg: Option<ProxyConfig>) -> anyhow::Result<WebSocketConnectOutput> {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::client_async_tls;

    let req = addr.into_client_request()?;

    let domain = req.uri().host().context("no host name in the url")?;
    let port = match req.uri().port_u16() {
        Some(port) => port,
        None => match req.uri().scheme_str() {
            Some("http" | "ws") => 80,
            Some("https" | "wss") => 443,
            _ => anyhow::bail!("no port in the url and unknown scheme"),
        },
    };

    let req_addr = (domain, port);

    impl_tcp_connect!(req_addr, proxy_cfg, anyhow::Result<WebSocketConnectOutput>, |stream| {
        async {
            let (ws, rsp) = client_async_tls(req, stream)
                .await
                .context("WebSocket handshake failed")?;
            let (sink, stream) = ws.split();
            let read = Box::new(websocket_read(stream)) as ErasedRead;
            let write = Box::new(websocket_write(sink)) as ErasedWrite;
            Ok((read, write, rsp))
        }
    })
}

pub async fn timeout<T, Fut, E>(duration: Option<Duration>, future: Fut) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
    E: From<tokio::time::error::Elapsed>,
{
    if let Some(duration) = duration {
        debug!(?duration, "With timeout");
        tokio::time::timeout(duration, future).await?
    } else {
        future.await
    }
}

pub async fn while_process_is_running<Fut, E>(process: Option<sysinfo::Pid>, future: Fut) -> Result<(), E>
where
    Fut: Future<Output = Result<(), E>>,
{
    if let Some(pid) = process {
        info!(%pid, "Watch for process");
        tokio::select! {
            res = future => res,
            _ = crate::process_watcher::watch_process(pid) => {
                info!(%pid, "Watched process is not running anymore");
                Ok(())
            },
        }
    } else {
        future.await
    }
}

pub fn websocket_read<S>(stream: S) -> impl AsyncRead + Unpin + Send + 'static
where
    S: Stream<Item = Result<tungstenite::Message, tungstenite::Error>> + Unpin + Send + 'static,
{
    use futures_util::StreamExt as _;

    let compat = stream.map(|item| {
        item.map(|msg| match msg {
            tungstenite::Message::Text(s) => transport::WsMessage::Payload(s.into_bytes()),
            tungstenite::Message::Binary(data) => transport::WsMessage::Payload(data),
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => transport::WsMessage::Ignored,
            tungstenite::Message::Close(_) => transport::WsMessage::Close,
            tungstenite::Message::Frame(_) => unreachable!("raw frames are never returned when reading"),
        })
    });

    transport::WsStream::new(compat)
}

pub fn websocket_write<S>(sink: S) -> impl AsyncWrite + Unpin + Send + 'static
where
    S: Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin + Send + 'static,
{
    use futures_util::SinkExt as _;

    let compat =
        sink.with(|item| futures_util::future::ready(Ok::<_, tungstenite::Error>(tungstenite::Message::Binary(item))));

    transport::WsStream::new(compat)
}

pub(crate) struct DummyReaderWriter;

impl tokio::io::AsyncRead for DummyReaderWriter {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl tokio::io::AsyncWrite for DummyReaderWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
