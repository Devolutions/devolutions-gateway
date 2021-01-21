use std::net::SocketAddr;
use crate::proxy::{ProxyConfig, ProxyType};
use anyhow::{anyhow, Result, Context as _};
use async_tungstenite::{
    tokio::ClientStream,
    tungstenite::{client::IntoClientRequest, handshake::client::Response},
    WebSocketStream,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::lookup_host,
};
use url::Url;

const TCP_ROUTING_HOST_SCHEME: &str = "tcp";

// See E0225 to understand why this trait is required
pub trait MetaAsyncStream: 'static + AsyncRead + AsyncWrite + Unpin {}

impl<T> MetaAsyncStream for T where T: 'static + AsyncRead + AsyncWrite + Unpin {}

pub type AsyncStream = Box<dyn MetaAsyncStream>;

pub async fn ws_connect_async(
    addr: String,
    proxy_cfg: Option<ProxyConfig>,
) -> Result<(WebSocketStream<ClientStream<AsyncStream>>, Response)> {
    use async_tungstenite::tokio::client_async_tls;
    use jetsocat_proxy::http::HttpProxyStream;
    use jetsocat_proxy::socks4::Socks4Stream;
    use jetsocat_proxy::socks5::Socks5Stream;
    use tokio::net::TcpStream;

    let req = addr.into_client_request()?;
    let domain = req.uri().host().context("no host name in the url")?;
    let port = req.uri().port_u16().context("no port in the url")?;
    let req_addr = (domain, port);

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
            match Socks5Stream::connect(stream, req_addr).await {
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
        None => Box::new(TcpStream::connect(req_addr).await?),
    };

    let (ws_stream, rsp) = client_async_tls(req, stream).await?;

    Ok((ws_stream, rsp))
}

pub async fn resolve_url_to_tcp_socket_addr(listener_url: String) -> Result<SocketAddr> {
    let url = Url::parse(&listener_url)?;

    if url.scheme() != TCP_ROUTING_HOST_SCHEME {
        return Err(anyhow!("Incorrect routing host scheme, it should start with `tcp://`"));
    }

    if !url.path().is_empty() {
        return Err(anyhow!("Incorrect Url: Url should have empty path"));
    }

    if url.host().is_none() {
        return Err(anyhow!("Incorrect Url: Host is missing"));
    }

    if url.port().is_none() {
        return Err(anyhow!("Incorrect Url: Port is missing"));
    }

    lookup_host(format!("{}:{}", url.host_str().unwrap(), url.port().unwrap()))
        .await?
        .next()
        .ok_or_else(|| anyhow!("Can't resolve host from url {}", url))
}
