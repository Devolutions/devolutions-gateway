//! The TLS and HTTP/2 connection that carries one stream.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as _;
use http::{Request, Response, Uri};
use http_client_proxy::ProxyConfig;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::TlsConnector;
use tonic::body::BoxBody;
use tower::Service;
use url::{Host, Url};

const ALPN_H2: &[u8] = b"h2";
/// How long a keepalive ping may go unanswered before the connection counts as lost.
// UNTESTED: an unanswered keepalive ping fails the connection after this timeout.
// That turns a silently dropped connection, for example after a NAT idle timeout, into a closure the channel reopens.
// When changing the HTTP/2 builder, keep a keepalive timeout and `keep_alive_while_idle`.
const KEEPALIVE_ACK_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct Transport {
    tls: Arc<rustls::ClientConfig>,
    proxy: ProxyConfig,
}

impl Transport {
    pub(crate) fn new(proxy: ProxyConfig, extra_trusted_roots: &[CertificateDer<'_>]) -> anyhow::Result<Self> {
        let mut roots = RootCertStore::empty();
        // UNTESTED: authorities are trusted through the OS trust store.
        // The tests trust only their own root, since adding one to the OS store would change the machine.
        // When changing this, check a connection to an authority whose certificate chains to an OS root.
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        for root in extra_trusted_roots {
            roots.add(root.clone().into_owned()).context("add extra trusted root")?;
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("configure TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN_H2.to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            proxy,
        })
    }

    /// Connects to the authority of `url` and completes the HTTP/2 handshake.
    pub(crate) async fn connect(&self, url: &Url, keepalive_interval: Duration) -> anyhow::Result<Http2Service> {
        let _ = &self.proxy;
        let (server_name, origin) = endpoint(url)?;
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_nodelay(true);
        poll_fn(|cx| connector.poll_ready(cx)).await?;
        let tcp = connector.call(origin).await?.into_inner();
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(server_name, tcp)
            .await?;
        let (send_request, connection) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(keepalive_interval)
            .keep_alive_timeout(KEEPALIVE_ACK_TIMEOUT)
            .keep_alive_while_idle(true)
            .handshake(TokioIo::new(tls))
            .await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Http2Service(send_request))
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

/// Sends requests on one HTTP/2 connection.
pub(crate) struct Http2Service(http2::SendRequest<BoxBody>);

impl Service<Request<BoxBody>> for Http2Service {
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Incoming>, hyper::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, request: Request<BoxBody>) -> Self::Future {
        Box::pin(self.0.send_request(request))
    }
}
