use crate::config::{Conf, ConfHandle};
use crate::generic_client::GenericClient;
use crate::jet_client::{JetAssociationsMap, JetClient};
use crate::session::SessionManagerHandle;
use crate::subscriber::SubscriberSender;
use crate::token::{CurrentJrl, TokenCache};
use crate::utils::url_to_socket_addr;
use crate::websocket_client::WebsocketService;
use anyhow::Context;
use hyper::service::service_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use tap::Pipe as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::Instrument as _;
use url::Url;

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
    Ws,
    Wss,
}

pub struct GatewayListener {
    addr: SocketAddr,
    listener_url: Url,
    kind: ListenerKind,
    listener: TcpListener,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    conf_handle: ConfHandle,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
}

impl GatewayListener {
    pub fn init_and_bind(
        url: impl ToInternalUrl,
        conf_handle: ConfHandle,
        associations: Arc<JetAssociationsMap>,
        token_cache: Arc<TokenCache>,
        jrl: Arc<CurrentJrl>,
        sessions: SessionManagerHandle,
        subscriber_tx: SubscriberSender,
    ) -> anyhow::Result<Self> {
        let url = url.to_internal_url();

        info!("Initiating listener {}…", url);

        let socket_addr = url_to_socket_addr(&url).context("invalid url")?;

        let socket = if socket_addr.is_ipv4() {
            TcpSocket::new_v4().context("Failed to create IPv4 TCP socket")?
        } else {
            TcpSocket::new_v6().context("Failed to created IPv6 TCP socket")?
        };
        socket.bind(socket_addr).context("Failed to bind TCP socket")?;
        set_socket_options(&socket);
        let listener = socket
            .listen(64)
            .context("failed to listen with the binded TCP socket")?;

        let kind = match url.scheme() {
            "tcp" => ListenerKind::Tcp,
            "ws" => ListenerKind::Ws,
            "wss" => ListenerKind::Wss,
            unsupported => anyhow::bail!("unsupported listener scheme: {}", unsupported),
        };

        info!("{kind:?} listener on {} started successfully", socket_addr);

        Ok(Self {
            addr: socket_addr,
            listener_url: url,
            kind,
            listener,
            conf_handle,
            associations,
            token_cache,
            jrl,
            sessions,
            subscriber_tx,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn kind(&self) -> ListenerKind {
        self.kind
    }

    #[instrument("listener", skip(self), fields(url = %self.listener_url))]
    pub async fn run(self) -> anyhow::Result<()> {
        macro_rules! handle {
            ($protocol:literal, $handler:ident) => {{
                match self
                    .listener
                    .accept()
                    .await
                    .context("failed to accept connection")
                {
                    Ok((stream, peer_addr)) => {
                        let conf = self.conf_handle.get_conf();
                        let associations = self.associations.clone();
                        let token_cache = self.token_cache.clone();
                        let jrl = self.jrl.clone();
                        let sessions = self.sessions.clone();
                        let subscriber_tx = self.subscriber_tx.clone();

                        let fut = async move {
                            if let Err(e) = $handler(conf, associations, token_cache, jrl, sessions, subscriber_tx, stream, peer_addr).await {
                                error!(concat!(stringify!($handler), " failure: {:#}"), e);
                            }
                        }
                        .instrument(info_span!($protocol, client = %peer_addr));

                        tokio::spawn(fut);
                    }
                    Err(e) => warn!("listener failure: {:#}", e),
                }
            }};
        }

        match self.kind() {
            ListenerKind::Tcp => loop {
                handle!("tcp", handle_tcp_client)
            },
            ListenerKind::Ws => loop {
                handle!("ws", handle_ws_client)
            },
            ListenerKind::Wss => loop {
                handle!("wss", handle_wss_client)
            },
        }
    }

    #[instrument(skip(self), fields(listener = %self.listener_url))]
    pub async fn handle_one(&self) -> anyhow::Result<()> {
        let (conn, peer_addr) = self.listener.accept().await.context("failed to accept connection")?;

        let conf = self.conf_handle.get_conf();
        let associations = self.associations.clone();
        let token_cache = self.token_cache.clone();
        let jrl = self.jrl.clone();
        let sessions = self.sessions.clone();
        let subscriber_tx = self.subscriber_tx.clone();

        match self.kind() {
            ListenerKind::Tcp => {
                handle_tcp_client(
                    conf,
                    associations,
                    token_cache,
                    jrl,
                    sessions,
                    subscriber_tx,
                    conn,
                    peer_addr,
                )
                .instrument(info_span!("tcp", client = %peer_addr))
                .await?
            }
            ListenerKind::Ws => {
                handle_ws_client(
                    conf,
                    associations,
                    token_cache,
                    jrl,
                    sessions,
                    subscriber_tx,
                    conn,
                    peer_addr,
                )
                .instrument(info_span!("ws", client = %peer_addr))
                .await?
            }
            ListenerKind::Wss => {
                handle_wss_client(
                    conf,
                    associations,
                    token_cache,
                    jrl,
                    sessions,
                    subscriber_tx,
                    conn,
                    peer_addr,
                )
                .instrument(info_span!("wss", client = %peer_addr))
                .await?
            }
        }

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_client(
    conf: Arc<Conf>,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    stream: TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    set_stream_option(&stream);

    let mut peeked = [0; 4];
    let n_read = stream
        .peek(&mut peeked)
        .await
        .context("couldn't peek four first bytes")?;

    // Check if first four bytes contains some protocol magic bytes
    match &peeked[..n_read] {
        [b'J', b'E', b'T', b'\0'] => {
            JetClient::builder()
                .conf(conf)
                .associations(associations)
                .addr(peer_addr)
                .transport(stream)
                .sessions(sessions)
                .subscriber_tx(subscriber_tx)
                .build()
                .serve()
                .instrument(info_span!("jet-client"))
                .await?;
        }
        [b'J', b'M', b'U', b'X'] => anyhow::bail!("JMUX TCP listener not yet implemented"),
        _ => {
            GenericClient::builder()
                .conf(conf)
                .associations(associations)
                .client_addr(peer_addr)
                .client_stream(stream)
                .token_cache(token_cache)
                .jrl(jrl)
                .sessions(sessions)
                .subscriber_tx(subscriber_tx)
                .build()
                .serve()
                .instrument(info_span!("generic-client"))
                .await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_ws_client(
    conf: Arc<Conf>,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    conn: TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    set_stream_option(&conn);

    // Annonate using the type alias from `transport` just for sanity
    let conn: transport::TcpStream = conn;

    process_ws_stream(
        conn,
        peer_addr,
        conf,
        associations,
        token_cache,
        jrl,
        sessions,
        subscriber_tx,
    )
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_wss_client(
    conf: Arc<Conf>,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    stream: TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    set_stream_option(&stream);

    let tls_conf = conf.tls.as_ref().context("TLS configuration is missing")?;

    // Annotate using the type alias from `transport` just for sanity
    let tls_stream: transport::TlsStream = tls_conf
        .acceptor
        .accept(stream)
        .await
        .context("TLS handshake failed")?
        .pipe(tokio_rustls::TlsStream::Server);

    process_ws_stream(
        tls_stream,
        peer_addr,
        conf,
        associations,
        token_cache,
        jrl,
        sessions,
        subscriber_tx,
    )
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_ws_stream<I>(
    io: I,
    remote_addr: SocketAddr,
    conf: Arc<Conf>,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<()>
where
    I: AsyncWrite + AsyncRead + Unpin + Send + Sync + 'static,
{
    let websocket_service = WebsocketService {
        associations,
        conf,
        token_cache,
        jrl,
        sessions,
        subscriber_tx,
    };

    let service = service_fn(move |req| {
        let mut ws_serve = websocket_service.clone();
        async move { ws_serve.handle(req, remote_addr).await }
    });

    hyper::server::conn::Http::new()
        .serve_connection(io, service)
        .with_upgrades()
        .instrument(info_span!("http"))
        .await?;

    Ok(())
}

fn set_socket_options(socket: &TcpSocket) {
    const SOCKET_SEND_BUFFER_SIZE: u32 = 0x7FFFF;
    const SOCKET_RECV_BUFFER_SIZE: u32 = 0x7FFFF;

    // FIXME: temporarily not available in tokio 1.x (https://github.com/tokio-rs/tokio/issues/3082)
    // if let Err(e) = socket.set_keepalive(Some(Duration::from_secs(2))) {
    //     error!("set_keepalive on TcpStream failed: {}", e);
    // }

    if let Err(e) = socket.set_send_buffer_size(SOCKET_SEND_BUFFER_SIZE) {
        error!("set_send_buffer_size on TcpStream failed: {}", e);
    }

    if let Err(e) = socket.set_recv_buffer_size(SOCKET_RECV_BUFFER_SIZE) {
        error!("set_recv_buffer_size on TcpStream failed: {}", e);
    }
}

fn set_stream_option(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        error!("set_nodelay on TcpStream failed: {}", e);
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
