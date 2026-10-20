//! The TLS and HTTP/2 connection that carries one stream.

use std::error::Error;
use std::fmt;
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
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{AlertDescription, RootCertStore};
use tokio_rustls::TlsConnector;
use tonic::body::BoxBody;
use tower::Service;
use url::{Host, Url};

use crate::closure::{Closure, TransientKind, error_chain};

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
    pub(crate) async fn connect(&self, url: &Url, keepalive_interval: Duration) -> Result<Http2Service, Closure> {
        let _ = &self.proxy;
        let (server_name, origin) = endpoint(url).map_err(|error| Closure::outage(format!("{error:#}")))?;
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_nodelay(true);
        poll_fn(|cx| connector.poll_ready(cx))
            .await
            .map_err(outage("resolve"))?;
        let tcp = connector.call(origin).await.map_err(outage("connect"))?.into_inner();
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(server_name, tcp)
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
}

fn outage<E: Error + 'static>(step: &'static str) -> impl FnOnce(E) -> Closure {
    move |error| Closure::outage(error_chain(step, &error))
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
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Incoming>, Self::Error>> + Send>>;

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
