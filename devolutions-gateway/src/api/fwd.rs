use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use axum::extract::ws::WebSocket;
use axum::extract::{self, ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use bytes::Bytes;
use devolutions_gateway_task::ShutdownSignal;
use tap::Pipe as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::{Instrument as _, field};
use typed_builder::TypedBuilder;
use uuid::Uuid;

use crate::config::Conf;
use crate::extract::{AssociationToken, BridgeToken};
use crate::http::HttpError;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, DisconnectInterest, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::target_addr::TargetAddr;
use crate::token::{ApplicationProtocol, AssociationTokenClaims, ConnectionMode, Protocol, RecordingPolicy};
use crate::{DgwState, utils};

pub fn make_router<S>(state: DgwState) -> Router<S> {
    use axum::routing::{self, MethodFilter, get};

    let router = Router::new()
        .route("/tcp/{id}", get(fwd_tcp))
        .route("/tls/{id}", get(fwd_tls));

    let router = if state.conf_handle.get_conf().debug.enable_unstable {
        let method_filter = MethodFilter::DELETE
            .or(MethodFilter::GET)
            .or(MethodFilter::HEAD)
            .or(MethodFilter::PATCH)
            .or(MethodFilter::POST)
            .or(MethodFilter::PUT)
            .or(MethodFilter::TRACE);

        router.route("/http/{id}", routing::on(method_filter, fwd_http))
    } else {
        router
    };

    router.with_state(state)
}

async fn fwd_tcp(
    State(DgwState {
        conf_handle,
        sessions,
        subscriber_tx,
        shutdown_signal,
        agent_tunnel_handle,
        ..
    }): State<DgwState>,
    AssociationToken(claims): AssociationToken,
    extract::Path(session_id): extract::Path<Uuid>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if session_id != claims.jet_aid {
        return Err(HttpError::forbidden().msg("wrong session ID"));
    }

    let conf = conf_handle.get_conf();
    let span = tracing::Span::current();

    let response = ws.on_upgrade(move |ws| {
        handle_fwd(
            ws,
            conf,
            sessions,
            shutdown_signal,
            subscriber_tx,
            claims,
            source_addr,
            false,
            agent_tunnel_handle,
        )
        .instrument(span)
    });

    Ok(response)
}

async fn fwd_tls(
    State(DgwState {
        conf_handle,
        sessions,
        subscriber_tx,
        shutdown_signal,
        agent_tunnel_handle,
        ..
    }): State<DgwState>,
    AssociationToken(claims): AssociationToken,
    extract::Path(session_id): extract::Path<Uuid>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if session_id != claims.jet_aid {
        return Err(HttpError::forbidden().msg("wrong session ID"));
    }

    let conf = conf_handle.get_conf();
    let span = tracing::Span::current();

    let response = ws.on_upgrade(move |ws| {
        handle_fwd(
            ws,
            conf,
            sessions,
            shutdown_signal,
            subscriber_tx,
            claims,
            source_addr,
            true,
            agent_tunnel_handle,
        )
        .instrument(span)
    });

    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn handle_fwd(
    ws: WebSocket,
    conf: Arc<Conf>,
    sessions: SessionMessageSender,
    shutdown_signal: ShutdownSignal,
    subscriber_tx: SubscriberSender,
    claims: AssociationTokenClaims,
    source_addr: SocketAddr,
    with_tls: bool,
    agent_tunnel_handle: Option<Arc<agent_tunnel::AgentTunnelHandle>>,
) {
    let (stream, close_handle) = crate::ws::handle(
        ws,
        crate::ws::KeepAliveShutdownSignal(shutdown_signal),
        Duration::from_secs(conf.debug.ws_keep_alive_interval),
    );

    let span = info_span!(
        "fwd",
        session_id = claims.jet_aid.to_string(),
        protocol = claims.jet_ap.to_string(),
        target = field::Empty
    );

    let result = Forward::builder()
        .client_addr(source_addr)
        .client_stream(stream)
        .conf(conf)
        .claims(claims)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .mode(if with_tls { ForwardMode::Tls } else { ForwardMode::Tcp })
        .agent_tunnel_handle(agent_tunnel_handle)
        .build()
        .run()
        .instrument(span.clone())
        .await;

    match &result {
        Ok(_) => close_handle.normal_close().await,
        Err(ForwardError::BadGateway(_)) => close_handle.bad_gateway().await,
        Err(ForwardError::Internal(_)) => close_handle.server_error("internal error".to_owned()).await,
    };

    if let Err(error) = result {
        span.in_scope(|| {
            error!(
                error = format!("{:#}", anyhow::Error::new(error)),
                "WebSocket forwarding failure"
            );
        });
    }
}

#[derive(TypedBuilder)]
struct Forward<S> {
    conf: Arc<Conf>,
    claims: AssociationTokenClaims,
    client_stream: S,
    client_addr: SocketAddr,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    mode: ForwardMode,
    #[builder(default)]
    agent_tunnel_handle: Option<Arc<agent_tunnel::AgentTunnelHandle>>,
}

#[derive(Debug, Clone, Copy)]
enum ForwardMode {
    Tcp,
    Tls,
}

enum UpstreamLeg {
    Tcp(TcpStream),
    Tunnel(agent_tunnel::stream::TunnelStream),
}

impl AsyncRead for UpstreamLeg {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tunnel(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamLeg {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tunnel(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tunnel(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tunnel(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

enum UpstreamSession {
    Tcp(UpstreamLeg),
    Tls(Box<TlsStream<UpstreamLeg>>),
}

impl AsyncRead for UpstreamSession {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamSession {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

enum RoutePlan<'a> {
    Direct(&'a TargetAddr),
    ViaAgent {
        target: &'a TargetAddr,
        candidates: Vec<Arc<agent_tunnel::registry::AgentPeer>>,
    },
}

impl<'a> RoutePlan<'a> {
    async fn resolve(
        agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
        explicit_agent_id: Option<Uuid>,
        target: &'a TargetAddr,
    ) -> Result<Self, ForwardError> {
        if let Some(agent_id) = explicit_agent_id {
            let handle = agent_tunnel_handle.ok_or_else(|| {
                ForwardError::BadGateway(anyhow::anyhow!(
                    "agent {agent_id} specified in token requires agent tunnel routing, but no tunnel handle is configured"
                ))
            })?;

            let agent = handle.registry().get(&agent_id).await.ok_or_else(|| {
                ForwardError::BadGateway(anyhow::anyhow!(
                    "agent {agent_id} specified in token not found in registry"
                ))
            })?;

            return Ok(Self::ViaAgent {
                target,
                candidates: vec![agent],
            });
        }

        let Some(handle) = agent_tunnel_handle else {
            return Ok(Self::Direct(target));
        };

        match agent_tunnel::routing::resolve_route(handle.registry(), None, target.host()).await {
            agent_tunnel::routing::RoutingDecision::ViaAgent(candidates) => Ok(Self::ViaAgent { target, candidates }),
            agent_tunnel::routing::RoutingDecision::Direct => Ok(Self::Direct(target)),
            agent_tunnel::routing::RoutingDecision::ExplicitAgentNotFound(_) => {
                unreachable!("explicit agent IDs are handled before route resolution")
            }
        }
    }

    async fn execute(
        self,
        agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
        session_id: Uuid,
    ) -> anyhow::Result<ConnectedTarget> {
        match self {
            Self::Direct(target) => {
                trace!(%target, "Select and connect to target");

                let (stream, server_addr) = utils::tcp_connect(target).await?;

                trace!(%target, "Connected");

                Ok(ConnectedTarget {
                    leg: UpstreamLeg::Tcp(stream),
                    server_addr,
                    selected_target: target.clone(),
                })
            }
            Self::ViaAgent { target, candidates } => {
                let handle = agent_tunnel_handle.expect("route plan requires configured agent tunnel");
                let mut last_error = None;

                for agent in &candidates {
                    info!(
                        agent_id = %agent.agent_id,
                        agent_name = %agent.name,
                        target = %target.as_addr(),
                        "Routing via agent tunnel"
                    );

                    match handle
                        .connect_via_agent(agent.agent_id, session_id, target.as_addr())
                        .await
                    {
                        Ok(stream) => {
                            let server_addr: SocketAddr = "0.0.0.0:0".parse().expect("valid placeholder");

                            return Ok(ConnectedTarget {
                                leg: UpstreamLeg::Tunnel(stream),
                                server_addr,
                                selected_target: target.clone(),
                            });
                        }
                        Err(error) => {
                            warn!(
                                agent_id = %agent.agent_id,
                                agent_name = %agent.name,
                                target = %target.as_addr(),
                                error = format!("{error:#}"),
                                "Agent tunnel candidate failed"
                            );
                            last_error = Some(error);
                        }
                    }
                }

                Err(last_error.unwrap_or_else(|| anyhow::anyhow!("all agent tunnel candidates failed")))
            }
        }
    }
}

struct ConnectedTarget {
    leg: UpstreamLeg,
    server_addr: SocketAddr,
    selected_target: TargetAddr,
}

struct PreparedTarget {
    session: UpstreamSession,
    server_addr: SocketAddr,
    selected_target: TargetAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("bad gateway")]
    BadGateway(#[source] anyhow::Error),
    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}

impl<S> Forward<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn run(self) -> Result<(), ForwardError> {
        let Self {
            conf,
            claims,
            client_stream,
            client_addr,
            sessions,
            subscriber_tx,
            mode,
            agent_tunnel_handle,
        } = self;

        validate_forward_request(&claims)?;

        let targets = match &claims.jet_cm {
            ConnectionMode::Fwd { targets, .. } => targets,
            _ => unreachable!("validated connection mode"),
        };

        // ARD uses MVS codec which doesn't like buffering.
        let buffer_size = if claims.jet_ap == ApplicationProtocol::Known(Protocol::Ard) {
            Some(1024)
        } else {
            None
        };

        let PreparedTarget {
            session,
            server_addr,
            selected_target,
        } = connect_target(
            targets,
            claims.jet_agent_id,
            claims.jet_aid,
            mode,
            claims.cert_thumb256,
            agent_tunnel_handle.as_deref(),
        )
        .await?;

        tracing::Span::current().record("target", selected_target.to_string());

        let info = SessionInfo::builder()
            .id(claims.jet_aid)
            .application_protocol(claims.jet_ap)
            .details(ConnectionModeDetails::Fwd {
                destination_host: selected_target,
            })
            .time_to_live(claims.jet_ttl)
            .recording_policy(claims.jet_rec)
            .filtering_policy(claims.jet_flt)
            .build();

        info!(
            mode = match mode {
                ForwardMode::Tcp => "tcp",
                ForwardMode::Tls => "tls",
            },
            "WebSocket forwarding"
        );

        Proxy::builder()
            .conf(conf)
            .session_info(info)
            .address_a(client_addr)
            .transport_a(client_stream)
            .address_b(server_addr)
            .transport_b(session)
            .sessions(sessions)
            .subscriber_tx(subscriber_tx)
            .buffer_size(buffer_size)
            .disconnect_interest(DisconnectInterest::from_reconnection_policy(claims.jet_reuse))
            .build()
            .select_dissector_and_forward()
            .await
            .context("forward websocket traffic")
            .map_err(ForwardError::Internal)
    }
}

fn validate_forward_request(claims: &AssociationTokenClaims) -> Result<(), ForwardError> {
    match claims.jet_rec {
        RecordingPolicy::None | RecordingPolicy::Stream => {}
        RecordingPolicy::Proxy => {
            return Err(ForwardError::Internal(anyhow::anyhow!(
                "recording policy not supported"
            )));
        }
    }

    if !matches!(claims.jet_cm, ConnectionMode::Fwd { .. }) {
        return Err(ForwardError::Internal(anyhow::anyhow!("connection mode not supported")));
    }

    Ok(())
}

async fn connect_target(
    targets: &nonempty::NonEmpty<TargetAddr>,
    explicit_agent_id: Option<Uuid>,
    session_id: Uuid,
    mode: ForwardMode,
    cert_thumb256: Option<crate::tls::thumbprint::Sha256Thumbprint>,
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
) -> Result<PreparedTarget, ForwardError> {
    let mut last_error = None;

    for target in targets {
        match RoutePlan::resolve(agent_tunnel_handle, explicit_agent_id, target)
            .await?
            .execute(agent_tunnel_handle, session_id)
            .await
        {
            Err(error) => {
                last_error = Some(error);
            }
            Ok(connected_upstream) => return prepare_target(mode, cert_thumb256, connected_upstream).await,
        }
    }

    Err(ForwardError::BadGateway(
        last_error.unwrap_or_else(|| anyhow::anyhow!("no target candidates available")),
    ))
}
async fn prepare_target(
    mode: ForwardMode,
    cert_thumb256: Option<crate::tls::thumbprint::Sha256Thumbprint>,
    connected_upstream: ConnectedTarget,
) -> Result<PreparedTarget, ForwardError> {
    let ConnectedTarget {
        leg,
        server_addr,
        selected_target,
    } = connected_upstream;

    let session = match mode {
        ForwardMode::Tcp => UpstreamSession::Tcp(leg),
        ForwardMode::Tls => {
            trace!(target = %selected_target, "Establishing TLS connection with server");

            let tls_stream = crate::tls::safe_connect(selected_target.host().to_owned(), leg, cert_thumb256)
                .await
                .context("TLS connect")
                .map_err(ForwardError::BadGateway)?;

            UpstreamSession::Tls(Box::new(tls_stream))
        }
    };

    Ok(PreparedTarget {
        session,
        server_addr,
        selected_target,
    })
}

async fn fwd_http(
    State(state): State<DgwState>,
    BridgeToken(claims): BridgeToken,
    extract::Path(session_id): extract::Path<Uuid>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    mut request: axum::http::Request<axum::body::Body>,
) -> Result<Response, HttpError> {
    use core::str::FromStr;
    use std::sync::LazyLock;

    use axum::extract::FromRequestParts as _; // from_request_parts
    use axum::http::{Response, header};
    use http_body_util::BodyExt as _; // into_data_stream
    use tokio_rustls::rustls;
    use tokio_tungstenite::connect_async_tls_with_config;

    // Default HTTP client for typical usage.
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

    // Dangerous HTTP client, only to be used when absolutely necessary.
    // E.g.: VMware services are often using untrusted self-signed certificates.
    static DANGEROUS_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        reqwest::Client::builder()
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("parameters known to be valid only")
    });

    static DANGEROUS_TLS_CONNECTOR: LazyLock<tokio_tungstenite::Connector> = LazyLock::new(|| {
        rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::danger::NoCertificateVerification))
            .with_no_client_auth()
            .pipe(Arc::new)
            .pipe(tokio_tungstenite::Connector::Rustls)
    });

    const REQUEST_TARGET_PARAM: Parameter<String> =
        Parameter::new("Dgw-Request-Target", |params| params.request_target.take());

    const DANGEROUS_TLS_PARAM: Parameter<bool> =
        Parameter::new("Dgw-Dangerous-Tls", |params| params.dangerous_tls.take());

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct QueryParams {
        request_target: Option<String>,
        dangerous_tls: Option<bool>, // QUESTION: Maybe we should bake this parameter into the Bridge token.
    }

    if session_id != claims.jet_aid {
        return Err(HttpError::forbidden().msg("wrong session ID"));
    }

    // 1. Extract parameters from the request.

    let query = request.uri().query().unwrap_or_default();
    let mut query_params = serde_urlencoded::from_str::<QueryParams>(query)
        .map_err(HttpError::bad_request().with_msg("invalid query params").err())?;

    let dangerous_tls = DANGEROUS_TLS_PARAM
        .extract_opt(&mut query_params, request.headers_mut())?
        .unwrap_or(false);

    // <METHOD> <TARGET>
    let request_target = REQUEST_TARGET_PARAM.extract(&mut query_params, request.headers_mut())?;

    debug!(%request_target, %dangerous_tls, "HTTP forwarding request");

    // 2. Compute the target URI from the Request-Target parameter and the token claim.

    // <TARGET>
    let request_target = request_target
        .split(' ')
        .next_back()
        .expect("split always returns at least one element");

    let target_uri = claims.target_host.to_uri_with_path_and_query(request_target).map_err(
        HttpError::bad_request()
            .with_msg("Request-Target header has an invalid value")
            .err(),
    )?;

    // 3. Modify the request with the target server information.

    *request.uri_mut() = target_uri;

    let host_value =
        header::HeaderValue::from_str(claims.target_host.host()).map_err(HttpError::bad_request().err())?;
    request.headers_mut().insert(header::HOST, host_value);

    // 4. Forward the request.

    let response = if matches!(request.uri().scheme_str(), Some("ws" | "wss")) {
        // 4.a Prepare the WebSocket upgrade.

        // We are discarding the original body.
        // There is no HTTP body when performing a WebSocket upgrade.
        let (mut parts, _) = request.into_parts();

        let client_ws = WebSocketUpgrade::from_request_parts(&mut parts, &state).await.map_err(
            HttpError::bad_request()
                .with_msg("failed to initiate the websocket upgrade")
                .err(),
        )?;

        // 4.b Open a WebSocket connection to the target.

        let request = axum::http::Request::from_parts(parts, ());
        let request_uri = request.uri().clone();

        let tls_connector = if dangerous_tls {
            Some(DANGEROUS_TLS_CONNECTOR.clone())
        } else {
            None
        };

        let (server_ws, server_ws_response) = connect_async_tls_with_config(request, None, false, tls_connector)
            .await
            .map_err(
                HttpError::bad_gateway()
                    .with_msg("WebSocket connection to target server")
                    .err(),
            )?;

        let conf = state.conf_handle.get_conf();
        let shutdown_signal = state.shutdown_signal;

        let (server_stream, server_close_handle) = tokio_tungstenite_websocket_handle(
            server_ws,
            shutdown_signal.clone(),
            Duration::from_secs(conf.debug.ws_keep_alive_interval),
        );

        debug!(?server_ws_response, %dangerous_tls, "Connected to target server");

        // 4.c Start WebSocket forwarding.

        let span = tracing::Span::current();
        let sessions = state.sessions;
        let subscriber_tx = state.subscriber_tx;

        client_ws.on_upgrade(move |client_ws| {
            let (client_stream, client_close_handle) = crate::ws::handle(
                client_ws,
                crate::ws::KeepAliveShutdownSignal(shutdown_signal),
                Duration::from_secs(conf.debug.ws_keep_alive_interval),
            );

            let client_addr = source_addr;

            async move {
                info!(target = %request_uri, "WebSocket-WebSocket forwarding");

                let info = SessionInfo::builder()
                    .id(claims.jet_aid)
                    .application_protocol(claims.jet_ap)
                    .details(ConnectionModeDetails::Fwd {
                        destination_host: claims.target_host,
                    })
                    .time_to_live(claims.jet_ttl)
                    .recording_policy(claims.jet_rec)
                    .build();

                // NOTE: We don’t really use this address for anything else other than pcap recording, so it’s fine to use a placeholder for now.
                let server_addr = "8.8.8.8:8888".parse().expect("valid hardcoded value");

                let result = Proxy::builder()
                    .conf(conf)
                    .session_info(info)
                    .address_a(client_addr)
                    .transport_a(client_stream)
                    .address_b(server_addr)
                    .transport_b(server_stream)
                    .sessions(sessions)
                    .subscriber_tx(subscriber_tx)
                    .disconnect_interest(None)
                    .build()
                    .select_dissector_and_forward()
                    .instrument(span.clone())
                    .await
                    .context("encountered a failure during WebSocket traffic proxying");

                if let Err(error) = result {
                    client_close_handle.server_error("proxy failure".to_owned()).await;
                    server_close_handle.server_error("proxy failure".to_owned()).await;
                    span.in_scope(|| {
                        error!(error = format!("{error:#}"), "WebSocket forwarding failure");
                    });
                } else {
                    client_close_handle.normal_close().await;
                    server_close_handle.normal_close().await;
                }
            }
        })
    } else {
        // 4.a Plain HTTP request forwarding using reqwest.

        let (parts, body) = request.into_parts();
        let body = reqwest::Body::wrap_stream(body.into_data_stream());
        let request = axum::http::Request::from_parts(parts, body);
        let request = reqwest::Request::try_from(request).map_err(HttpError::internal().err())?;

        debug!(?request);

        info!(target = %request.url(), %dangerous_tls, "Forward HTTP request");

        let client = if dangerous_tls { &*DANGEROUS_CLIENT } else { &*CLIENT };

        let response = client.execute(request).await.map_err(HttpError::bad_gateway().err())?;

        if let Err(error) = response.error_for_status_ref() {
            info!(%error, host = claims.target_host.host(), "Service responded with a failure HTTP status code");
        }

        // 4.b Convert the response into the expected type and return it.

        let response = Response::from(response);
        let (parts, body) = response.into_parts();
        let body = axum::body::Body::from_stream(body.into_data_stream());
        Response::from_parts(parts, body)
    };

    return Ok(response);

    // -- local helpers -- //

    struct Parameter<T>
    where
        T: FromStr,
    {
        header_name: &'static str,
        query_params_extractor: fn(&mut QueryParams) -> Option<T>,
    }

    impl<T> Parameter<T>
    where
        T: FromStr,
        T::Err: core::fmt::Display,
    {
        const fn new(header_name: &'static str, query_params_extractor: fn(&mut QueryParams) -> Option<T>) -> Self {
            Self {
                header_name,
                query_params_extractor,
            }
        }

        fn extract_opt(
            &self,
            query_params: &mut QueryParams,
            headers: &mut axum::http::HeaderMap,
        ) -> Result<Option<T>, HttpError> {
            let value = if let Some(value) = (self.query_params_extractor)(query_params) {
                value
            } else if let Some(value) = headers.remove(self.header_name) {
                let value = value
                    .to_str()
                    .with_context(|| format!("invalid UTF-16 value for header {}", self.header_name))
                    .map_err(HttpError::bad_request().err())?;
                T::from_str(value)
                    .map_err(|e| format!("failed to parse header {}: {}", self.header_name, e))
                    .map_err(HttpError::bad_request().err())?
            } else {
                return Ok(None);
            };

            Ok(Some(value))
        }

        fn extract(&self, query_params: &mut QueryParams, headers: &mut axum::http::HeaderMap) -> Result<T, HttpError> {
            let value = self.extract_opt(query_params, headers)?;
            let value = value
                .with_context(|| format!("query param or header missing for {}", self.header_name))
                .map_err(HttpError::bad_request().err())?;
            Ok(value)
        }
    }

    fn tokio_tungstenite_websocket_handle<S>(
        ws: tokio_tungstenite::WebSocketStream<S>,
        shutdown_signal: ShutdownSignal,
        keep_alive_interval: Duration,
    ) -> (
        impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        transport::CloseWebSocketHandle,
    )
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        use futures::SinkExt as _;

        let ws = transport::Shared::new(ws);

        let close_frame_handle = transport::spawn_websocket_sentinel_task(
            ws.shared().with(|message: transport::WsWriteMsg| {
                core::future::ready(Result::<_, tungstenite::Error>::Ok(match message {
                    transport::WsWriteMsg::Ping => tungstenite::Message::Ping(Bytes::new()),
                    transport::WsWriteMsg::Close(ws_close_frame) => {
                        tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
                            code: ws_close_frame.code.into(),
                            reason: ws_close_frame.message.into(),
                        }))
                    }
                }))
            }),
            crate::ws::KeepAliveShutdownSignal(shutdown_signal),
            keep_alive_interval,
        );

        (tokio_tungstenite_websocket_compat(ws), close_frame_handle)
    }

    fn tokio_tungstenite_websocket_compat<S>(stream: S) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static
    where
        S: futures::Stream<Item = Result<tungstenite::Message, tungstenite::Error>>
            + futures::Sink<tungstenite::Message, Error = tungstenite::Error>
            + Unpin
            + Send
            + 'static,
    {
        use futures::{SinkExt as _, StreamExt as _};

        let compat = stream
            .filter_map(|item| {
                let mapped = item
                    .map(|msg| match msg {
                        tungstenite::Message::Text(s) => Some(transport::WsReadMsg::Payload(Bytes::from(s))),
                        tungstenite::Message::Binary(data) => Some(transport::WsReadMsg::Payload(data)),
                        tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => None,
                        tungstenite::Message::Close(_) => Some(transport::WsReadMsg::Close),
                        tungstenite::Message::Frame(_) => unreachable!("raw frames are never returned when reading"),
                    })
                    .transpose();

                std::future::ready(mapped)
            })
            .with(|item| {
                core::future::ready(Ok::<_, tungstenite::Error>(tungstenite::Message::Binary(Bytes::from(
                    item,
                ))))
            });

        transport::WsStream::new(compat)
    }
}
