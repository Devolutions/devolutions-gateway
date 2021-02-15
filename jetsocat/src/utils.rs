use crate::proxy::{ProxyConfig, ProxyType};
use anyhow::{anyhow, Context as _, Result};
use async_tungstenite::{
    tokio::ClientStream,
    tungstenite::{client::IntoClientRequest, handshake::client::Response},
    WebSocketStream,
};
use jetsocat_proxy::{DestAddr, ToDestAddr};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

// See E0225 to understand why this trait is required
pub trait MetaAsyncStream: 'static + AsyncRead + AsyncWrite + Unpin {}

impl<T> MetaAsyncStream for T where T: 'static + AsyncRead + AsyncWrite + Unpin {}

pub type AsyncStream = Box<dyn MetaAsyncStream>;

pub async fn tcp_connect_async(req_addr: impl ToDestAddr, proxy_cfg: Option<ProxyConfig>) -> Result<AsyncStream> {
    use jetsocat_proxy::socks4::Socks4Stream;
    use jetsocat_proxy::socks5::Socks5Stream;
    use jetsocat_proxy::http::HttpProxyStream;

    let stream: AsyncStream = match proxy_cfg {
        Some(ProxyConfig {
            ty: ProxyType::Socks4,
            addr: proxy_addr,
        }) => {
            let stream = TcpStream::connect(proxy_addr).await?;
            Box::new(Socks4Stream::connect(stream, req_addr, "jetsocat").await?)
        }
        Some(ProxyConfig {
            ty: ProxyType::Socks5,
            addr: proxy_addr,
        }) => {
            let stream = TcpStream::connect(proxy_addr).await?;
            Box::new(Socks5Stream::connect(stream, req_addr).await?)
        }
        Some(ProxyConfig {
            ty: ProxyType::Socks,
            addr: proxy_addr,
        }) => {
            // unknown SOCKS version, try SOCKS5 first and then SOCKS4
            let stream = TcpStream::connect(proxy_addr.clone()).await?;
            match Socks5Stream::connect(stream, &req_addr).await {
                Ok(socks4) => Box::new(socks4),
                Err(_) => {
                    let stream = TcpStream::connect(proxy_addr).await?;
                    Box::new(Socks4Stream::connect(stream, req_addr, "jetsocat").await?)
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
            let stream = TcpStream::connect(proxy_addr).await?;
            Box::new(HttpProxyStream::connect(stream, req_addr).await?)
        }
        None => {
            let dest_addr =
                resolve_dest_addr(req_addr.to_dest_addr().with_context(|| "Invalid target address")?).await?;

            Box::new(TcpStream::connect(dest_addr).await?)
        }
    };
    Ok(stream)
}

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

pub async fn ws_connect_async(
    addr: String,
    proxy_cfg: Option<ProxyConfig>,
) -> Result<(WebSocketStream<ClientStream<AsyncStream>>, Response)> {
    use async_tungstenite::tokio::client_async_tls;

    let req = addr.into_client_request()?;
    let domain = req.uri().host().context("no host name in the url")?;
    let port = req.uri().port_u16().context("no port in the url")?;
    let req_addr = (domain, port);

    let stream = tcp_connect_async(req_addr, proxy_cfg).await?;
    let (ws_stream, rsp) = client_async_tls(req, stream).await?;

    Ok((ws_stream, rsp))
}
