use std::net::{SocketAddr, ToSocketAddrs as _};

use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use futures::TryFutureExt as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::Instrument as _;
use url::Url;

use crate::DgwState;
use crate::generic_client::GenericClient;
use crate::target_addr::TargetAddr;

const HTTP_CONNECTION_MAX_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(10 * 60);

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
pub struct ListenerUrls {
    /// URL to use on local network
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub internal_url: Url,

    /// URL to use from external networks
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub external_url: Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    Tcp,
    Http,
    Https,
}

pub struct GatewayListener {
    addr: SocketAddr,
    binding_url: TargetAddr,
    kind: ListenerKind,
    listener: TcpListener,
    state: DgwState,
}

impl GatewayListener {
    pub fn init_and_bind(url: impl ToInternalUrl, state: DgwState) -> anyhow::Result<Self> {
        let url = url.to_internal_url();

        let kind = match url.scheme() {
            "tcp" => ListenerKind::Tcp,
            "http" => ListenerKind::Http,
            "https" => ListenerKind::Https,
            unsupported => anyhow::bail!("unsupported listener scheme: {}", unsupported),
        };

        let url = TargetAddr::try_from(url).context("invalid internal url")?;
        let socket_addr = url
            .to_socket_addrs()
            .context("resolve internal URL to socket addr")?
            .next()
            .context("internal URL resolved to nothing")?;

        let socket = if socket_addr.is_ipv4() {
            TcpSocket::new_v4().context("failed to create IPv4 TCP socket")?
        } else {
            TcpSocket::new_v6().context("failed to created IPv6 TCP socket")?
        };
        socket.bind(socket_addr).context("failed to bind TCP socket")?;

        let listener = socket
            .listen(64)
            .context("failed to listen with the binded TCP socket")?;

        info!("Listening on {scheme}://{socket_addr}", scheme = url.scheme());

        Ok(Self {
            addr: socket_addr,
            binding_url: url,
            kind,
            listener,
            state,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn kind(&self) -> ListenerKind {
        self.kind
    }

    #[instrument("listener", skip(self), fields(port = self.binding_url.port()))]
    pub async fn run(self) -> anyhow::Result<()> {
        match self.kind() {
            ListenerKind::Tcp => run_tcp_listener(self.listener, self.state).await,
            ListenerKind::Http => run_http_listener(self.listener, self.state).await,
            ListenerKind::Https => run_https_listener(self.listener, self.state).await,
        }
    }
}

#[async_trait]
impl Task for GatewayListener {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "gateway listener";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Self::Output {
        tokio::select! {
            result = self.run() => result,
            _ = shutdown_signal.wait() => Ok(()),
        }
    }
}

async fn run_tcp_listener(listener: TcpListener, state: DgwState) -> anyhow::Result<()> {
    loop {
        match listener.accept().await.context("failed to accept connection") {
            Ok((stream, peer_addr)) => {
                let state = state.clone();

                ChildTask::spawn(async move {
                    if let Err(e) = handle_tcp_peer(stream, state, peer_addr).await {
                        error!(error = format!("{e:#}"), client = %peer_addr, "TCP peer failure");
                    }
                })
                .detach();
            }
            Err(e) => error!(error = format!("{e:#}"), "TCP listener failure"),
        }
    }
}

#[instrument("tcp", skip_all, fields(client = %peer_addr))]
async fn handle_tcp_peer(stream: TcpStream, state: DgwState, peer_addr: SocketAddr) -> anyhow::Result<()> {
    if let Err(e) = stream.set_nodelay(true) {
        error!("set_nodelay on TcpStream failed: {}", e);
    }

    let mut peeked = [0; 4];
    let n_read = stream
        .peek(&mut peeked)
        .await
        .context("couldn't peek four first bytes")?;

    // Check if first four bytes contains some protocol magic bytes
    match &peeked[..n_read] {
        [b'J', b'E', b'T', b'\0'] => anyhow::bail!("not yet supported"),
        [b'J', b'M', b'U', b'X'] => anyhow::bail!("not yet supported"),
        _ => {
            GenericClient::builder()
                .conf(state.conf_handle.get_conf())
                .client_addr(peer_addr)
                .client_stream(stream)
                .token_cache(state.token_cache)
                .jrl(state.jrl)
                .sessions(state.sessions)
                .subscriber_tx(state.subscriber_tx)
                .active_recordings(state.recordings.active_recordings)
                .credential_store(state.credential_store)
                .build()
                .serve()
                .await?;
        }
    }

    Ok(())
}

async fn run_http_listener(listener: TcpListener, state: DgwState) -> anyhow::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state = state.clone();

                let fut = tokio::time::timeout(HTTP_CONNECTION_MAX_DURATION, async move {
                    if let Err(e) = handle_http_peer(stream, state, peer_addr).await {
                        error!(error = format!("{e:#}"), "handle_http_peer failed");
                    }
                })
                .inspect_err(|error| debug!(%error, "Drop long-lived HTTP connection"))
                .instrument(info_span!("http", client = %peer_addr));

                ChildTask::spawn(fut).detach();
            }
            Err(error) => {
                error!(%error, "Failed to accept connection");
            }
        }
    }
}

async fn run_https_listener(listener: TcpListener, state: DgwState) -> anyhow::Result<()> {
    let conf = state.conf_handle.get_conf();

    let tls_conf = conf.tls.as_ref().context("TLS configuration is missing")?;

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let tls_acceptor = tls_conf.acceptor.clone();
                let state = state.clone();

                let fut = tokio::time::timeout(HTTP_CONNECTION_MAX_DURATION, async move {
                    if let Err(e) = handle_https_peer(stream, tls_acceptor, state, peer_addr).await {
                        error!(error = format!("{e:#}"), "handle_https_peer failed");
                    }
                })
                .inspect_err(|error| debug!(%error, "Drop long-lived HTTP connection"))
                .instrument(info_span!("https", client = %peer_addr));

                ChildTask::spawn(fut).detach();
            }
            Err(error) => {
                error!(%error, "failed to accept connection");
            }
        }
    }
}

/// Checks if an error represents a benign client disconnect.
///
/// Walks the error chain and returns true if any cause is a `std::io::Error`
/// with kind `BrokenPipe`, `ConnectionReset`, or `UnexpectedEof`.
fn is_benign_disconnect(err: &anyhow::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionReset, UnexpectedEof};

    err.chain().any(|cause| {
        if let Some(ioe) = cause.downcast_ref::<std::io::Error>() {
            return matches!(ioe.kind(), BrokenPipe | ConnectionReset | UnexpectedEof);
        }
        false
    })
}

async fn handle_https_peer(
    stream: TcpStream,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    state: DgwState,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    let tls_stream = match tls_acceptor.accept(stream).await {
        Ok(stream) => tokio_rustls::TlsStream::Server(stream),
        Err(e) => {
            let e = anyhow::Error::from(e);
            if is_benign_disconnect(&e) {
                debug!(error = format!("{e:#}"), %peer_addr, "TLS handshake ended by peer");
                return Ok(());
            } else {
                return Err(e.context("TLS handshake failed"));
            }
        }
    };

    handle_http_peer(tls_stream, state, peer_addr).await
}

pub(crate) async fn handle_http_peer<I>(io: I, state: DgwState, peer_addr: SocketAddr) -> anyhow::Result<()>
where
    I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use axum::extract::connect_info::ConnectInfo;
    use hyper::service::service_fn;
    use tower::Service as _;

    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        // We have to clone `tower_service` because hyper's `Service` uses `&self` whereas
        // tower's `Service` requires `&mut self`.
        //
        // We don't need to call `poll_ready` since `Router` is always ready.
        crate::make_http_service(state.clone())
            .layer(axum::Extension(ConnectInfo(peer_addr)))
            .call(request)
    });

    let result = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(io), service)
        .await;

    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            // Check for hyper-specific benign cases first.
            if let Some(hyper_err) = error.downcast_ref::<hyper::Error>()
                && (hyper_err.is_canceled() || hyper_err.is_incomplete_message())
            {
                debug!(error = format!("{:#}", anyhow::anyhow!(error)), %peer_addr, "Request was cancelled/incomplete");
                return Ok(());
            }

            // Then check for underlying io::Error kinds via anyhow chain.
            let error = anyhow::Error::from_boxed(error);
            if is_benign_disconnect(&error) {
                debug!(error = format!("{error:#}"), %peer_addr, "Client disconnected");
                Ok(())
            } else {
                Err(error.context("HTTP server"))
            }
        }
    }
}

pub trait ToInternalUrl {
    fn to_internal_url(self) -> Url;
}

impl ToInternalUrl for &'_ ListenerUrls {
    fn to_internal_url(self) -> Url {
        self.internal_url.clone()
    }
}

impl ToInternalUrl for ListenerUrls {
    fn to_internal_url(self) -> Url {
        self.internal_url
    }
}

impl ToInternalUrl for Url {
    fn to_internal_url(self) -> Url {
        self
    }
}
