use crate::io::{ReadableWebSocketHalf, WritableWebSocketHalf};
use crate::proxy::{ProxyConfig, ProxyType};
use anyhow::{anyhow, Context as _, Result};
use async_tungstenite::tungstenite::client::IntoClientRequest;
use async_tungstenite::tungstenite::handshake::client::Response;
use futures_util::future;
use jetsocat_proxy::{DestAddr, ToDestAddr};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

async fn resolve_dest_addr(dest_addr: DestAddr) -> Result<SocketAddr> {
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
        use jetsocat_proxy::{HttpProxyStream, Socks4Stream, Socks5Stream};

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
                match Socks5Stream::connect(TcpStream::connect(proxy_addr.clone()).await?, &$req_addr).await {
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
                let stream = HttpProxyStream::connect(TcpStream::connect(proxy_addr).await?, $req_addr).await?;
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

type TcpConnectOutput = (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>);

pub async fn tcp_connect(req_addr: String, proxy_cfg: Option<ProxyConfig>) -> Result<TcpConnectOutput> {
    impl_tcp_connect!(req_addr, proxy_cfg, Result<TcpConnectOutput>, |stream| {
        let (read, write) = tokio::io::split(stream);
        future::ready(Ok((
            Box::new(read) as Box<dyn AsyncRead + Unpin + Send>,
            Box::new(write) as Box<dyn AsyncWrite + Unpin + Send>,
        )))
    })
}

type WebSocketConnectOutput = (
    Box<dyn AsyncRead + Unpin + Send>,
    Box<dyn AsyncWrite + Unpin + Send>,
    Response,
);

pub async fn ws_connect(addr: String, proxy_cfg: Option<ProxyConfig>) -> Result<WebSocketConnectOutput> {
    use async_tungstenite::tokio::client_async_tls;
    use futures_util::StreamExt as _;

    let req = addr.into_client_request()?;
    let domain = req.uri().host().context("no host name in the url")?;
    let port = req.uri().port_u16().context("no port in the url")?;
    let req_addr = (domain, port);

    impl_tcp_connect!(req_addr, proxy_cfg, Result<WebSocketConnectOutput>, |stream| {
        async {
            let (ws, rsp) = client_async_tls(req, stream)
                .await
                .context("WebSocket handshake failed")?;
            let (sink, stream) = ws.split();
            let read = Box::new(ReadableWebSocketHalf::new(stream)) as Box<dyn AsyncRead + Unpin + Send>;
            let write = Box::new(WritableWebSocketHalf::new(sink)) as Box<dyn AsyncWrite + Unpin + Send>;
            Ok((read, write, rsp))
        }
    })
}
