//! The TLS and HTTP/2 connection that carries one stream.

use std::error::Error;
use std::fmt;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderValue, Request, Response, Uri};
use http_client_proxy::ProxyConfig;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::proxy::{SocksV4, SocksV5, Tunnel};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use percent_encoding::percent_decode_str;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{AlertDescription, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tonic::body::BoxBody;
use tower::Service;
use url::{Host, Url};

use crate::closure::{Closure, TransientKind, error_chain};

const ALPN_H2: &[u8] = b"h2";
/// The port of a SOCKS proxy URL without one (RFC 1928 §3).
const SOCKS_PORT: u16 = 1080;
/// How long a keepalive ping may go unanswered before the connection counts as lost.
// UNTESTED: an unanswered keepalive ping fails the connection after this timeout.
// That turns a silently dropped connection, for example after a NAT idle timeout, into a closure the channel reopens.
// When changing the HTTP/2 builder, keep a keepalive timeout and `keep_alive_while_idle`.
const KEEPALIVE_ACK_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct Transport {
    /// Verifies authorities and offers HTTP/2.
    tls: Arc<rustls::ClientConfig>,
    /// Verifies HTTPS proxies.
    proxy_tls: Arc<rustls::ClientConfig>,
    proxy: ProxyConfig,
}

/// A connection the authority's TLS session runs over: direct, or tunnelled through a proxy.
trait Io: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

type BoxError = Box<dyn Error + Send + Sync>;

impl Transport {
    pub(crate) fn new(proxy: ProxyConfig, extra_trusted_roots: &[CertificateDer<'_>]) -> anyhow::Result<Self> {
        let mut roots = RootCertStore::empty();
        // UNTESTED: authorities and HTTPS proxies are trusted through the OS trust store.
        // The tests trust only their own roots, since adding one to the OS store would change the machine.
        // When changing this, check a connection to an authority whose certificate chains to an OS root.
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        for root in extra_trusted_roots {
            roots.add(root.clone().into_owned()).context("add extra trusted root")?;
        }
        let roots = Arc::new(roots);
        let config = |alpn_protocols: Vec<Vec<u8>>| -> anyhow::Result<Arc<rustls::ClientConfig>> {
            let mut config =
                rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .context("configure TLS versions")?
                    .with_root_certificates(Arc::clone(&roots))
                    .with_no_client_auth();
            config.alpn_protocols = alpn_protocols;
            Ok(Arc::new(config))
        };
        Ok(Self {
            tls: config(vec![ALPN_H2.to_vec()])?,
            proxy_tls: config(Vec::new())?,
            proxy,
        })
    }

    /// Connects to the authority of `url`, through the proxy the agent's proxy settings select for it, and completes
    /// the HTTP/2 handshake.
    pub(crate) async fn connect(&self, url: &Url, keepalive_interval: Duration) -> Result<Http2Service, Closure> {
        let (server_name, origin) = endpoint(url).map_err(|error| Closure::outage(format!("{error:#}")))?;
        let io: Box<dyn Io> = match http_client_proxy::proxy_for_url(url, &self.proxy) {
            Some(proxy) => self.tunnel(&proxy, origin).await?,
            None => Box::new(tcp(origin).await.map_err(outage("connect"))?),
        };
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(server_name, io)
            .await
            .map_err(|error| {
                // A server that supports no protocol the client offers refuses ALPN with this alert (RFC 7301 §3.2).
                let refused_h2 = matches!(
                    error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()),
                    Some(rustls::Error::AlertReceived(AlertDescription::NoApplicationProtocol))
                );
                if refused_h2 {
                    Closure::transient(TransientKind::NoGrpcPath, "the server refused HTTP/2")
                } else {
                    outage("TLS handshake")(error)
                }
            })?;
        if tls.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
            return Err(Closure::transient(
                TransientKind::NoGrpcPath,
                "the server did not negotiate HTTP/2",
            ));
        }
        let (send_request, connection) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(keepalive_interval)
            .keep_alive_timeout(KEEPALIVE_ACK_TIMEOUT)
            .keep_alive_while_idle(true)
            .handshake(TokioIo::new(tls))
            .await
            .map_err(outage("HTTP/2 handshake"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Http2Service(send_request))
    }

    /// Opens a tunnel to `target` through `proxy`, with the proxy credentials of its user info, as reqwest does for
    /// the agent's identity requests: HTTP CONNECT for `http` and `https` proxies, and SOCKS for `socks4`,
    /// `socks4a`, `socks5` and `socks5h` proxies.
    async fn tunnel(&self, proxy: &Url, target: Uri) -> Result<Box<dyn Io>, Closure> {
        let scheme = proxy.scheme();
        let is_socks = matches!(scheme, "socks4" | "socks4a" | "socks5" | "socks5h");
        let port = if is_socks {
            proxy.port().or(Some(SOCKS_PORT))
        } else {
            proxy.port_or_known_default()
        };
        let proxy_endpoint = match (proxy.host_str(), port) {
            (Some(host), Some(port)) => format!("{scheme}://{host}:{port}")
                .parse::<Uri>()
                .map_err(outage("proxy URL"))?,
            _ => return Err(Closure::outage("proxy URL without host")),
        };
        let credentials = credentials(proxy);
        match scheme {
            "http" => {
                let tunnel = open_tunnel(http_connector(), proxy_endpoint, credentials, target).await?;
                Ok(Box::new(tunnel.into_inner()))
            }
            "https" => {
                let tls = Arc::clone(&self.proxy_tls);
                let connector = tower::service_fn(move |proxy: Uri| tls_to_proxy(Arc::clone(&tls), proxy));
                let tunnel = open_tunnel(connector, proxy_endpoint, credentials, target).await?;
                Ok(Box::new(tunnel.into_inner()))
            }
            // `socks5` and `socks4` resolve the authority's name locally; `socks5h` and `socks4a` leave it to the proxy.
            "socks5" | "socks5h" => {
                let target = if scheme == "socks5" {
                    resolve_locally(target).await?
                } else {
                    target
                };
                let mut socks = SocksV5::new(proxy_endpoint, http_connector());
                if let Some((user, password)) = credentials {
                    socks = socks.with_auth(user, password);
                }
                let tunnel = connect_through(socks, target, "SOCKS5 handshake").await?;
                Ok(Box::new(tunnel.into_inner()))
            }
            "socks4" | "socks4a" => {
                // UNTESTED: `socks4` and `socks4a` proxies go through hyper-util's `SocksV4`, as the agent's identity
                // requests do through reqwest.
                // `SocksV4` ends the empty user ID with two NUL bytes instead of one, so a proxy that reads the
                // request as SOCKS4 defines it tunnels the second byte to the authority, or reads it as an empty
                // SOCKS4a name; the tests therefore cover SOCKS5 only.
                // When changing this, check a `socks4` and a `socks4a` proxy, for the channel and the identity requests.
                let target = if scheme == "socks4" {
                    resolve_locally(target).await?
                } else {
                    target
                };
                let socks = SocksV4::new(proxy_endpoint, http_connector());
                let tunnel = connect_through(socks, target, "SOCKS4 handshake").await?;
                Ok(Box::new(tunnel.into_inner()))
            }
            scheme => Err(Closure::outage(format!("unsupported proxy scheme {scheme}"))),
        }
    }
}

fn http_connector() -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    connector.set_nodelay(true);
    connector
}

async fn tcp(endpoint: Uri) -> Result<TcpStream, BoxError> {
    let mut connector = http_connector();
    poll_fn(|cx| connector.poll_ready(cx)).await?;
    Ok(connector.call(endpoint).await?.into_inner())
}

async fn tls_to_proxy(tls: Arc<rustls::ClientConfig>, proxy: Uri) -> Result<TokioIo<TlsStream<TcpStream>>, BoxError> {
    let host = proxy.host().ok_or("proxy URL without host")?;
    let server_name = ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_owned())?;
    let tcp = tcp(proxy).await?;
    Ok(TokioIo::new(TlsConnector::from(tls).connect(server_name, tcp).await?))
}

/// Opens an HTTP CONNECT tunnel through the proxy that `connector` reaches, with Basic `credentials`.
async fn open_tunnel<C>(
    connector: C,
    proxy: Uri,
    credentials: Option<(String, String)>,
    target: Uri,
) -> Result<C::Response, Closure>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    let mut tunnel = Tunnel::new(proxy, connector);
    if let Some((user, password)) = credentials {
        let authorization = HeaderValue::try_from(format!("Basic {}", STANDARD.encode(format!("{user}:{password}"))))
            .map_err(outage("proxy credentials"))?;
        tunnel = tunnel.with_auth(authorization);
    }
    connect_through(tunnel, target, "proxy tunnel").await
}

/// Connects to `target` through the proxy `connector`, which reports its failures as the failures of `step`.
async fn connect_through<C>(mut connector: C, target: Uri, step: &'static str) -> Result<C::Response, Closure>
where
    C: Service<Uri>,
    C::Error: Into<BoxError>,
{
    poll_fn(|cx| connector.poll_ready(cx)).await.map_err(outage(step))?;
    connector.call(target).await.map_err(outage(step))
}

/// Replaces the name in `target` by one of its addresses, preferring IPv4, which every SOCKS version can carry.
async fn resolve_locally(target: Uri) -> Result<Uri, Closure> {
    let (Some(host), Some(port)) = (target.host(), target.port_u16()) else {
        return Err(Closure::outage("channel origin without host"));
    };
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
        .await
        .map_err(outage("resolve the authority"))?
        .collect();
    let address = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.first())
        .ok_or_else(|| Closure::outage("resolve the authority: no address"))?;
    format!("https://{address}")
        .parse()
        .map_err(outage("resolve the authority"))
}

/// Returns the percent-decoded user name and password of `proxy`, as reqwest takes them for the agent's identity
/// requests.
fn credentials(proxy: &Url) -> Option<(String, String)> {
    if proxy.username().is_empty() && proxy.password().is_none() {
        return None;
    }
    let decode = |part: &str| percent_decode_str(part).decode_utf8_lossy().into_owned();
    Some((decode(proxy.username()), decode(proxy.password().unwrap_or_default())))
}

fn outage<E: Into<BoxError>>(step: &'static str) -> impl FnOnce(E) -> Closure {
    move |error| {
        let error: BoxError = error.into();
        Closure::outage(error_chain(step, &*error))
    }
}

/// Returns the TLS server name and the `https` origin of `url`.
pub(crate) fn endpoint(url: &Url) -> anyhow::Result<(ServerName<'static>, Uri)> {
    let host = match url.host() {
        Some(Host::Domain(domain)) => domain.to_owned(),
        Some(Host::Ipv4(address)) => address.to_string(),
        Some(Host::Ipv6(address)) => address.to_string(),
        None => anyhow::bail!("channel URL without host"),
    };
    let port = url.port_or_known_default().context("channel URL without port")?;
    let origin = format!("https://{}:{port}", url.host_str().unwrap_or_default())
        .parse()
        .context("build channel origin")?;
    Ok((ServerName::try_from(host).context("invalid TLS server name")?, origin))
}

/// Sends requests on one HTTP/2 connection, and fails each response that is not gRPC with [`NotGrpc`].
pub(crate) struct Http2Service(http2::SendRequest<BoxBody>);

impl Service<Request<BoxBody>> for Http2Service {
    type Response = Response<Incoming>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Incoming>, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<BoxBody>) -> Self::Future {
        let response = self.0.send_request(request);
        Box::pin(async move {
            let response = response.await?;
            if is_grpc(&response) {
                Ok(response)
            } else {
                Err(NotGrpc(response.status()).into())
            }
        })
    }
}

/// Returns whether `response` has a gRPC content type (`application/grpc`, optionally followed by `+` or `;`).
fn is_grpc(response: &Response<Incoming>) -> bool {
    const GRPC: &str = "application/grpc";
    let Some(content_type) = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    content_type
        .get(..GRPC.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(GRPC))
        && matches!(content_type.as_bytes().get(GRPC.len()), None | Some(b'+' | b';'))
}

/// A response that shows the path to the authority can't carry gRPC.
#[derive(Debug)]
pub(crate) struct NotGrpc(http::StatusCode);

impl fmt::Display for NotGrpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "the server answered with a non-gRPC {} response", self.0)
    }
}

impl Error for NotGrpc {}
