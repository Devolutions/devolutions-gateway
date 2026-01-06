use core::time::Duration;
use std::net::SocketAddr;

use anyhow::Context as _;
use futures_util::{Future, Sink, Stream, future};
use proxy_types::{DestAddr, ToDestAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::tungstenite::{Bytes, Utf8Bytes};
use transport::ErasedReadWrite;

use crate::proxy::{ProxyConfig, ProxyType};

async fn resolve_dest_addr(dest_addr: DestAddr) -> anyhow::Result<SocketAddr> {
    match dest_addr {
        DestAddr::Ip(socket_addr) => Ok(socket_addr),
        DestAddr::Domain(host, port) => tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| "Lookup host failed")?
            .next()
            .context("failed to resolve target address"),
    }
}

macro_rules! impl_tcp_connect {
    ($req_addr:expr, $proxy_cfg:expr, $output_ty:ty, | $stream:ident | $operation:block) => {{
        use proxy_socks::{Socks4Stream, Socks5Stream};

        let out: $output_ty = match $proxy_cfg {
            Some(ProxyConfig {
                ty: ProxyType::Socks4,
                addr: proxy_addr,
            }) => {
                let $stream =
                    Socks4Stream::connect(TcpStream::connect(proxy_addr).await?, $req_addr, "jetsocat").await?;
                $operation.await
            }
            Some(ProxyConfig {
                ty: ProxyType::Socks5,
                addr: proxy_addr,
            }) => {
                let $stream = Socks5Stream::connect(TcpStream::connect(proxy_addr).await?, $req_addr).await?;
                $operation.await
            }
            Some(ProxyConfig {
                ty: ProxyType::Socks,
                addr: proxy_addr,
            }) => {
                // unknown SOCKS version, try SOCKS5 first and then SOCKS4
                match Socks5Stream::connect(TcpStream::connect(&proxy_addr).await?, &$req_addr).await {
                    Ok($stream) => $operation.await,
                    Err(_) => {
                        let $stream =
                            Socks4Stream::connect(TcpStream::connect(proxy_addr).await?, $req_addr, "jetsocat").await?;
                        $operation.await
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
                let $stream =
                    proxy_http::ProxyStream::connect(TcpStream::connect(proxy_addr).await?, $req_addr).await?;
                $operation.await
            }
            None => {
                let dest_addr =
                    resolve_dest_addr($req_addr.to_dest_addr().with_context(|| "invalid target address")?).await?;
                let $stream = TcpStream::connect(dest_addr).await?;
                $operation.await
            }
        };

        out
    }};
}

pub(crate) async fn tcp_connect(req_addr: String, proxy_cfg: Option<ProxyConfig>) -> anyhow::Result<ErasedReadWrite> {
    impl_tcp_connect!(req_addr, proxy_cfg, anyhow::Result<ErasedReadWrite>, |stream| {
        async { Ok(Box::new(stream) as ErasedReadWrite) }
    })
}

type WebSocketConnectOutput = (ErasedReadWrite, Response);

pub(crate) async fn ws_connect(addr: String, proxy_cfg: Option<ProxyConfig>) -> anyhow::Result<WebSocketConnectOutput> {
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
            let stream = Box::new(websocket_handle(ws)) as ErasedReadWrite;
            Ok((stream, rsp))
        }
    })
}

pub(crate) async fn timeout<T, Fut, E>(duration: Option<Duration>, future: Fut) -> Result<T, E>
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

pub(crate) async fn while_process_is_running<Fut, E>(process: Option<sysinfo::Pid>, future: Fut) -> Result<(), E>
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

/// Spawns a keep-alive task and wraps the WebSocket into a type implementing AsyncRead and AsyncWrite.
pub(crate) fn websocket_handle<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use futures_util::SinkExt as _;

    let ws = transport::Shared::new(ws);

    let notify = std::sync::Arc::new(tokio::sync::Notify::new());

    transport::spawn_websocket_sentinel_task(
        ws.shared().with(|message: transport::WsWriteMsg| {
            future::ready(Result::<_, tungstenite::Error>::Ok(match message {
                transport::WsWriteMsg::Ping => tungstenite::Message::Ping(Bytes::new()),
                transport::WsWriteMsg::Close(ws_close_frame) => {
                    tungstenite::Message::Close(Some(tungstenite::protocol::frame::CloseFrame {
                        code: ws_close_frame.code.into(),
                        reason: Utf8Bytes::from(ws_close_frame.message),
                    }))
                }
            }))
        }),
        notify,
        Duration::from_secs(45),
    );

    websocket_compat(ws)
}

fn websocket_compat<S>(stream: S) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static
where
    S: Stream<Item = Result<tungstenite::Message, tungstenite::Error>>
        + Sink<tungstenite::Message, Error = tungstenite::Error>
        + Unpin
        + Send
        + 'static,
{
    use futures_util::{SinkExt as _, StreamExt as _};

    let compat = stream
        .filter_map(|item| {
            let mapped = item
                .map(|msg| match msg {
                    tungstenite::Message::Text(s) => Some(transport::WsReadMsg::Payload(Bytes::from(s))),
                    tungstenite::Message::Binary(data) => Some(transport::WsReadMsg::Payload(data)),
                    tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => None,
                    tungstenite::Message::Close(_) => Some(transport::WsReadMsg::Close),
                    tungstenite::Message::Frame(_) => unreachable!("raw frames are never returned when reading"),
                })
                .transpose();

            core::future::ready(mapped)
        })
        .with(|item| {
            future::ready(Ok::<_, tungstenite::Error>(tungstenite::Message::Binary(Bytes::from(
                item,
            ))))
        });

    transport::WsStream::new(compat)
}
