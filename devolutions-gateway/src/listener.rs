use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use futures::TryFutureExt as _;
use std::net::SocketAddr;
use tap::Pipe as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::Instrument as _;
use url::Url;

use crate::generic_client::GenericClient;
use crate::utils::url_to_socket_addr;
use crate::DgwState;

const HTTP_REQUEST_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);

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
    listener_url: Url,
    kind: ListenerKind,
    listener: TcpListener,
    state: DgwState,
}

impl GatewayListener {
    pub fn init_and_bind(url: impl ToInternalUrl, state: DgwState) -> anyhow::Result<Self> {
        let url = url.to_internal_url();

        info!(%url, "Initiating listener…");

        let socket_addr = url_to_socket_addr(&url).context("invalid url")?;

        let socket = if socket_addr.is_ipv4() {
            TcpSocket::new_v4().context("Failed to create IPv4 TCP socket")?
        } else {
            TcpSocket::new_v6().context("Failed to created IPv6 TCP socket")?
        };
        socket.bind(socket_addr).context("Failed to bind TCP socket")?;

        let listener = socket
            .listen(64)
            .context("failed to listen with the binded TCP socket")?;

        let kind = match url.scheme() {
            "tcp" => ListenerKind::Tcp,
            "http" => ListenerKind::Http,
            "https" => ListenerKind::Https,
            unsupported => anyhow::bail!("unsupported listener scheme: {}", unsupported),
        };

        info!(?kind, addr = %socket_addr, "Listener started successfully");

        Ok(Self {
            addr: socket_addr,
            listener_url: url,
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

    #[instrument("listener", skip(self), fields(port = self.listener_url.port().expect("port")))]
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
                        error!(error = format!("{e:#}"), "Peer failure");
                    }
                })
                .detach();
            }
            Err(e) => error!(error = format!("{e:#}"), "Listener failure"),
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

                let fut = tokio::time::timeout(HTTP_REQUEST_TIMEOUT, async move {
                    if let Err(e) = handle_http_peer(stream, state, peer_addr).await {
                        error!(error = format!("{e:#}"), "handle_http_peer failed");
                    }
                })
                .map_err(|error| warn!(%error, "request timed out"))
                .instrument(info_span!("http", client = %peer_addr));

                ChildTask::spawn(fut).detach();
            }
            Err(error) => {
                error!(%error, "failed to accept connection");
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

                let fut = tokio::time::timeout(HTTP_REQUEST_TIMEOUT, async move {
                    if let Err(e) = handle_https_peer(stream, tls_acceptor, state, peer_addr).await {
                        error!(error = format!("{e:#}"), "handle_https_peer failed");
                    }
                })
                .map_err(|error| warn!(%error, "request timed out"))
                .instrument(info_span!("https", client = %peer_addr));

                ChildTask::spawn(fut).detach();
            }
            Err(error) => {
                error!(%error, "failed to accept connection");
            }
        }
    }
}

async fn handle_https_peer(
    stream: TcpStream,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    state: DgwState,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    let tls_stream = tls_acceptor
        .accept(stream)
        .await
        .context("TLS handshake failed")?
        .pipe(tokio_rustls::TlsStream::Server);

    handle_http_peer(tls_stream, state, peer_addr).await
}

pub(crate) async fn handle_http_peer<I>(io: I, state: DgwState, peer_addr: SocketAddr) -> anyhow::Result<()>
where
    I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use axum::extract::connect_info::ConnectInfo;

    let app = crate::make_http_service(state).layer(axum::Extension(ConnectInfo(peer_addr)));

    hyper::server::conn::Http::new()
        .serve_connection(io, app)
        .with_upgrades()
        .await
        .context("HTTP server")
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
