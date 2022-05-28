use crate::config::Config;
use crate::jet::candidate::CandidateState;
use crate::jet::TransportType;
use crate::jet_client::JetAssociationsMap;
use crate::token::{ApplicationProtocol, CurrentJrl, TokenCache};
use crate::utils::association::remove_jet_association;
use crate::utils::TargetAddr;
use crate::{ConnectionModeDetails, GatewaySessionInfo, Proxy};
use anyhow::Context as _;
use hyper::{header, http, Body, Method, Request, Response, StatusCode, Version};
use jmux_proxy::JmuxProxy;
use saphir::error;
use sha1::Digest as _;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::Instrument as _;
use transport::{ErasedRead, ErasedWrite};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct WebsocketService {
    pub associations: Arc<JetAssociationsMap>,
    pub token_cache: Arc<TokenCache>,
    pub jrl: Arc<CurrentJrl>,
    pub config: Arc<Config>,
}

impl WebsocketService {
    pub async fn handle(&mut self, req: Request<Body>, client_addr: SocketAddr) -> Result<Response<Body>, io::Error> {
        if req.method() == Method::GET && req.uri().path().starts_with("/jet/accept") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_accept(req, client_addr, self.associations.clone())
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET accept error - {:?}", err)))
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jet/connect") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_connect(req, client_addr, self.associations.clone(), self.config.clone())
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET connect error - {:?}", err)))
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jet/test") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_test(req, &self.associations)
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET test error - {:?}", err)))
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jmux") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jmux(req, client_addr, &self.config, &self.token_cache, &self.jrl)
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JMUX error - {:#}", err)))
        } else {
            saphir::server::inject_raw_with_peer_addr(req, Some(client_addr))
                .await
                .map_err(|err| match err {
                    error::SaphirError::Io(err) => err,
                    err => io::Error::new(io::ErrorKind::Other, format!("{}", err)),
                })
        }
    }
}

fn handle_jet_test(
    req: Request<Body>,
    associations: &JetAssociationsMap,
) -> Result<Response<Body>, saphir::error::InternalError> {
    match handle_jet_test_impl(req, associations) {
        Ok(res) => Ok(res),
        Err(status) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = status;
            Ok(res)
        }
    }
}

fn handle_jet_test_impl(req: Request<Body>, associations: &JetAssociationsMap) -> Result<Response<Body>, StatusCode> {
    let header = req.headers().get("upgrade").ok_or(StatusCode::BAD_REQUEST)?;
    let header_str = header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
    if header_str != "websocket" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(StatusCode::BAD_REQUEST)?;
    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(StatusCode::BAD_REQUEST)?;

    let jet_assc = associations.lock();
    let assc = jet_assc.get(&association_id).ok_or(StatusCode::NOT_FOUND)?;
    if assc.get_candidate(candidate_id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(process_req(&req))
}

async fn handle_jet_accept(
    req: Request<Body>,
    client_addr: SocketAddr,
    associations: Arc<JetAssociationsMap>,
) -> Result<Response<Body>, saphir::error::InternalError> {
    match handle_jet_accept_impl(req, client_addr, associations).await {
        Ok(res) => Ok(res),
        Err(()) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::FORBIDDEN;
            Ok(res)
        }
    }
}

async fn handle_jet_accept_impl(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    associations: Arc<JetAssociationsMap>,
) -> Result<Response<Body>, ()> {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let header = req.headers().get("upgrade").ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    if header_str != "websocket" {
        return Err(());
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(())?;
    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(())?;

    let version = {
        let associations = associations.lock();
        let association = associations.get(&association_id).ok_or(())?;
        association.version()
    };

    let res = process_req(&req);

    match version {
        2 | 3 => {
            tokio::spawn(async move {
                let upgraded = hyper::upgrade::on(&mut req)
                    .await
                    .map_err(|e| error!("upgrade error: {}", e))?;

                let (transport, leftover_bytes) = match upgraded.downcast::<transport::TcpStream>() {
                    Ok(parts) => {
                        let ws =
                            tokio_tungstenite::WebSocketStream::from_raw_socket(parts.io, Role::Server, None).await;
                        let ws: transport::WsStream = transport::WebSocketStream::new(ws);
                        (transport::Transport::new(ws, client_addr), parts.read_buf)
                    }
                    Err(upgraded) => match upgraded.downcast::<transport::TlsStream>() {
                        Ok(parts) => {
                            let ws =
                                tokio_tungstenite::WebSocketStream::from_raw_socket(parts.io, Role::Server, None).await;
                            let ws: transport::WssStream = transport::WebSocketStream::new(ws);
                            (transport::Transport::new(ws, client_addr), parts.read_buf)
                        }
                        Err(_) => {
                            error!("unexpected transport kind");
                            return Err(());
                        }
                    },
                };

                let mut jet_assc = associations.lock();
                if let Some(assc) = jet_assc.get_mut(&association_id) {
                    if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                        candidate.set_state(CandidateState::Accepted);
                        candidate.set_transport(transport, Some(leftover_bytes));
                    }
                }
                Ok::<(), ()>(())
            });
            Ok(res)
        }
        _ => Err(()),
    }
}

async fn handle_jet_connect(
    req: Request<Body>,
    client_addr: SocketAddr,
    associations: Arc<JetAssociationsMap>,
    config: Arc<Config>,
) -> Result<Response<Body>, saphir::error::InternalError> {
    match handle_jet_connect_impl(req, client_addr, associations, config).await {
        Ok(res) => Ok(res),
        Err(()) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::BAD_REQUEST;
            Ok(res)
        }
    }
}

async fn handle_jet_connect_impl(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    associations: Arc<JetAssociationsMap>,
    config: Arc<Config>,
) -> Result<Response<Body>, ()> {
    use crate::interceptor::plugin_recording::PluginRecordingInspector;
    use crate::interceptor::Interceptor;
    use tokio_tungstenite::tungstenite::protocol::Role;

    let header = req.headers().get("upgrade").ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    if header_str != "websocket" {
        return Err(());
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(())?;
    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(())?;

    let (version, association_claims) = {
        let associations = associations.lock();
        let association = associations.get(&association_id).ok_or(())?;
        (association.version(), association.get_token_claims().clone())
    };

    let association_id = association_claims.jet_aid;

    let res = process_req(&req);

    match version {
        2 | 3 => {
            tokio::spawn(async move {
                let upgraded = hyper::upgrade::on(&mut req)
                    .await
                    .map_err(|e| error!("upgrade error: {}", e))?;

                let (mut client_transport, client_leftover) = match upgraded.downcast::<transport::TcpStream>() {
                    Ok(parts) => {
                        let ws =
                            tokio_tungstenite::WebSocketStream::from_raw_socket(parts.io, Role::Server, None).await;
                        let ws: transport::WsStream = transport::WebSocketStream::new(ws);
                        (transport::Transport::new(ws, client_addr), parts.read_buf)
                    }
                    Err(upgraded) => match upgraded.downcast::<transport::TlsStream>() {
                        Ok(parts) => {
                            let ws =
                                tokio_tungstenite::WebSocketStream::from_raw_socket(parts.io, Role::Server, None).await;
                            let ws: transport::WssStream = transport::WebSocketStream::new(ws);
                            (transport::Transport::new(ws, client_addr), parts.read_buf)
                        }
                        Err(_) => {
                            error!("unexpected transport kind");
                            return Err(());
                        }
                    },
                };

                let mut server_transport;
                let server_leftover;
                let mut file_pattern = None;
                let mut recording_dir = None;
                let mut recording_inspector: Option<(PluginRecordingInspector, PluginRecordingInspector)> = None;

                {
                    let mut associations = associations.lock();

                    let association = if let Some(assoc) = associations.get_mut(&association_id) {
                        assoc
                    } else {
                        error!("Failed to get association");
                        return Err(());
                    };

                    let candidate = if let Some(candidate) = association.get_candidate_mut(candidate_id) {
                        candidate
                    } else {
                        error!("Failed to get candidate");
                        return Err(());
                    };

                    // Sanity checks
                    let is_websocket = candidate.transport_type() == TransportType::Ws
                        || candidate.transport_type() == TransportType::Wss;
                    let is_accepted = candidate.state() != CandidateState::Accepted;
                    if !is_websocket || !is_accepted {
                        error!(
                            "Unexpected candidate properties [is websocket? {}] [is accepted? {}]",
                            is_websocket, is_accepted
                        );
                        return Err(());
                    }

                    (server_transport, server_leftover) = candidate
                        .take_transport()
                        .expect("Candidate cannot be created without a transport");

                    candidate.set_state(CandidateState::Connected);

                    let association_id = candidate.association_id();
                    let candidate_id = candidate.id();

                    match (association.record_session(), config.plugins.is_some()) {
                        (true, true) => {
                            let init_result = PluginRecordingInspector::init(
                                association_id,
                                candidate_id,
                                config.recording_path.as_ref().map(|path| path.as_str()),
                            )
                            .map_err(|e| error!("Couldn't initialize PluginRecordingInspector: {}", e))?;

                            recording_dir = init_result.recording_dir;
                            file_pattern = Some(init_result.filename_pattern);
                            recording_inspector = Some((init_result.client_inspector, init_result.server_inspector));
                        }
                        (true, false) => {
                            error!("Can't meet recording policy");
                            return Err(());
                        }
                        (false, _) => {}
                    }
                }

                let info =
                    GatewaySessionInfo::new(association_id, association_claims.jet_ap, ConnectionModeDetails::Rdv)
                        .with_recording_policy(association_claims.jet_rec)
                        .with_filtering_policy(association_claims.jet_flt);

                let proxy_result = if let Some((client_inspector, server_inspector)) = recording_inspector {
                    let mut client_transport = Interceptor::new(client_transport);
                    client_transport.inspectors.push(Box::new(client_inspector));

                    let mut server_transport = Interceptor::new(server_transport);
                    server_transport.inspectors.push(Box::new(server_inspector));

                    server_transport
                        .write_all(&client_leftover)
                        .await
                        .map_err(|e| error!("Failed to write client leftover request: {}", e))?;

                    if let Some(bytes) = server_leftover {
                        client_transport
                            .write_all(&bytes)
                            .await
                            .map_err(|e| error!("Failed to write server leftover request: {}", e))?;
                    }

                    let proxy_result = Proxy::init()
                        .session_info(info)
                        .transports(client_transport, server_transport)
                        .forward()
                        .await;

                    if let (Some(dir), Some(pattern)) = (recording_dir, file_pattern) {
                        let registry = crate::registry::Registry::new(config);
                        registry
                            .manage_files(association_id.to_string(), pattern, dir.as_path())
                            .await;
                    };

                    proxy_result
                } else {
                    server_transport
                        .write_all(&client_leftover)
                        .await
                        .map_err(|e| error!("Failed to write client leftover request: {}", e))?;

                    if let Some(bytes) = server_leftover {
                        client_transport
                            .write_all(&bytes)
                            .await
                            .map_err(|e| error!("Failed to write server leftover request: {}", e))?;
                    }

                    Proxy::init()
                        .session_info(info)
                        .transports(client_transport, server_transport)
                        .forward()
                        .await
                };

                if let Err(e) = proxy_result {
                    error!("failed to build Proxy for WebSocket connection: {}", e)
                }

                remove_jet_association(&associations, association_id, Some(candidate_id));

                Ok::<(), ()>(())
            });

            Ok(res)
        }
        _ => Err(()),
    }
}

fn get_uuid_in_path(path: &str, index: usize) -> Option<Uuid> {
    if let Some(raw_uuid) = path.split('/').nth(index + 1) {
        Uuid::parse_str(raw_uuid).ok()
    } else {
        None
    }
}

fn process_req(req: &Request<Body>) -> Response<Body> {
    /*
        Source: https://gist.github.com/bluetech/192c74b9c4ae541747718ac4f4e20a14
        Author: Ran Benita<bluetech> (ran234@gmail.com)
    */

    fn convert_key(input: &[u8]) -> String {
        const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut hasher = sha1::Sha1::new();
        hasher.update(input);
        hasher.update(WS_GUID);
        base64::encode(&hasher.finalize())
    }
    fn connection_has(value: &header::HeaderValue, needle: &str) -> bool {
        if let Ok(v) = value.to_str() {
            v.split(',').any(|s| s.trim().eq_ignore_ascii_case(needle))
        } else {
            false
        }
    }
    let is_http_11 = req.version() == Version::HTTP_11;
    let is_upgrade = req
        .headers()
        .get(header::CONNECTION)
        .map_or(false, |v| connection_has(v, "upgrade"));
    let is_websocket_upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.eq_ignore_ascii_case("websocket"));

    let is_websocket_version_13_or_higher = req
        .headers()
        .get(header::SEC_WEBSOCKET_VERSION)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.parse::<u32>().unwrap_or(0) >= 13);

    if !is_http_11 || !is_upgrade || !is_websocket_upgrade || !is_websocket_version_13_or_higher {
        return Response::builder()
            .status(http::StatusCode::UPGRADE_REQUIRED)
            .body("Expected Upgrade to WebSocket".into())
            .unwrap();
    }

    let key = if let Some(value) = req.headers().get(header::SEC_WEBSOCKET_KEY) {
        convert_key(value.as_bytes())
    } else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("".into())
            .unwrap();
    };

    let builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, key.as_str());

    // Add the SEC_WEBSOCKET_PROTOCOL header only if it was in the request, otherwise, IIS doesn't like it
    let builder = if let Some(websocket_protocol) = req.headers().get(header::SEC_WEBSOCKET_PROTOCOL) {
        builder.header(header::SEC_WEBSOCKET_PROTOCOL, websocket_protocol)
    } else {
        builder
    };

    builder.body(Body::empty()).unwrap()
}

async fn handle_jmux(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    config: &Config,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> io::Result<Response<Body>> {
    use crate::http::middlewares::auth::{parse_auth_header, AuthHeaderType};
    use crate::token::{validate_token, AccessTokenClaims};

    let token = if let Some(authorization_value) = req.headers().get(header::AUTHORIZATION) {
        let authorization_value = authorization_value
            .to_str()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bad authorization header value"))?;
        match parse_auth_header(authorization_value) {
            Some((AuthHeaderType::Bearer, token)) => token,
            _ => return Err(io::Error::new(io::ErrorKind::Other, "bad authorization header value")),
        }
    } else if let Some(token) = req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|segment| segment.split_once('='))
            .find_map(|(key, val)| key.eq("token").then(|| val))
    }) {
        token
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, "missing authorization"));
    };

    let provisioner_key = config
        .provisioner_public_key
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Provisioner key is missing"))?;

    let delegation_key = config.delegation_private_key.as_ref();

    if config.debug.dump_tokens {
        debug!(token, "**DEBUG OPTION**");
    }

    let validation_result = if config.debug.disable_token_validation {
        #[allow(deprecated)]
        crate::token::unsafe_debug::dangerous_validate_token(token, delegation_key)
    } else {
        validate_token(
            token,
            client_addr.ip(),
            provisioner_key,
            delegation_key,
            token_cache,
            jrl,
        )
    };

    let claims = match validation_result {
        Ok(AccessTokenClaims::Jmux(claims)) => claims,
        Ok(_) => {
            return Err(io::Error::new(io::ErrorKind::Other, "wrong access token"));
        }
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("couldn't validate token: {:#}", e),
            ));
        }
    };

    if let Some(upgrade_val) = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) {
        if upgrade_val != "websocket" {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected upgrade header value: {}", upgrade_val),
            ));
        }
    }

    let rsp = process_req(&req);

    tokio::spawn(async move {
        use jmux_proxy::{FilteringRule, JmuxConfig};
        use tokio_tungstenite::tungstenite::protocol::Role;

        let upgraded = hyper::upgrade::on(&mut req)
            .await
            .map_err(|e| error!("upgrade error: {}", e))?;

        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
        let ws = transport::WebSocketStream::new(ws);
        let (reader, writer) = tokio::io::split(ws);
        let reader = Box::new(reader) as ErasedRead;
        let writer = Box::new(writer) as ErasedWrite;

        let config = JmuxConfig {
            filtering: FilteringRule::Any(
                claims
                    .hosts
                    .into_iter()
                    .map(|addr| {
                        if addr.host() == "*" {
                            // Basically allow all
                            FilteringRule::Allow
                        } else {
                            FilteringRule::wildcard_host(addr.host().to_owned()).and(FilteringRule::port(addr.port()))
                        }
                    })
                    .collect(),
            ),
        };

        JmuxProxy::new(reader, writer)
            .with_config(config)
            .run()
            .instrument(info_span!("jmux", client=%client_addr))
            .await
            .map_err(|e| error!("JMUX proxy error: {}", e))?;

        Ok::<(), ()>(())
    });

    Ok(rsp)
}

pub struct WsClient {
    routing_url: Url,
    config: Arc<Config>,
}

impl WsClient {
    pub fn new(routing_url: Url, config: Arc<Config>) -> Self {
        WsClient { routing_url, config }
    }

    pub async fn serve<T>(self, client_addr: SocketAddr, client_transport: T) -> anyhow::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let server_transport = connect_server(&self.routing_url).await?;

        let destination_host = TargetAddr::try_from(&self.routing_url)?;

        Proxy::init()
            .config(self.config)
            .session_info(GatewaySessionInfo::new(
                Uuid::new_v4(),
                ApplicationProtocol::Unknown,
                ConnectionModeDetails::Fwd { destination_host },
            ))
            .addrs(client_addr, server_transport.addr)
            .transports(client_transport, server_transport)
            .select_dissector_and_forward()
            .await
    }
}

async fn connect_server(url: &Url) -> anyhow::Result<transport::Transport> {
    use crate::utils;
    use tokio::net::TcpStream;
    use tokio_rustls::{rustls, TlsConnector, TlsStream};

    let socket_addr = utils::resolve_url_to_socket_addr(url)
        .await
        .with_context(|| format!("couldn't resolve {}", url))?;

    let request = Request::builder()
        .uri(url.as_str())
        .body(())
        .context("request build failure")?;

    match url.scheme() {
        "ws" => {
            let stream = TcpStream::connect(&socket_addr).await?;
            let (stream, _) = tokio_tungstenite::client_async(request, stream)
                .await
                .context("WebSocket handshake failed")?;
            let ws = transport::WebSocketStream::new(stream);
            Ok(transport::Transport::new(ws, socket_addr))
        }
        "wss" => {
            let tcp_stream = TcpStream::connect(&socket_addr).await?;

            let dns_name = rustls::ServerName::try_from("stub_string").unwrap();

            let rustls_client_conf = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(utils::danger_transport::NoCertificateVerification))
                .with_no_client_auth();
            let rustls_client_conf = Arc::new(rustls_client_conf);
            let cx = TlsConnector::from(rustls_client_conf);
            let tls_stream = cx.connect(dns_name, tcp_stream).await?;

            let (stream, _) = tokio_tungstenite::client_async(request, TlsStream::Client(tls_stream))
                .await
                .context("WebSocket handshake failed")?;
            let ws = transport::WebSocketStream::new(stream);

            Ok(transport::Transport::new(ws, socket_addr))
        }
        scheme => {
            anyhow::bail!("Unsupported scheme: {}", scheme);
        }
    }
}
