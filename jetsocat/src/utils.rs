use crate::proxy::{ProxyConfig, ProxyType};
use anyhow::{anyhow, Context as _};
use core::time::Duration;
use futures_util::{future, Future};
use proxy_types::{DestAddr, ToDestAddr};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use transport::{ErasedRead, ErasedWrite, WebSocketStream};

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
    let port = req.uri().port_u16().context("no port in the url")?;
    let req_addr = (domain, port);

    impl_tcp_connect!(req_addr, proxy_cfg, anyhow::Result<WebSocketConnectOutput>, |stream| {
        async {
            let (ws, rsp) = client_async_tls(req, stream)
                .await
                .context("WebSocket handshake failed")?;
            let (sink, stream) = ws.split();
            let read = Box::new(WebSocketStream::new(stream)) as ErasedRead;
            let write = Box::new(WebSocketStream::new(sink)) as ErasedWrite;
            Ok((read, write, rsp))
        }
    })
}

#[track_caller]
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
#[track_caller]
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
