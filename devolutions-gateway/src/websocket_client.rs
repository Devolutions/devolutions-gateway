use crate::config::Conf;
use crate::jet::candidate::CandidateState;
use crate::jet::TransportType;
use crate::jet_client::JetAssociationsMap;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{CurrentJrl, TokenCache};
use crate::utils::association::remove_jet_association;
use anyhow::Context as _;
use hyper::{header, http, Body, Method, Request, Response, StatusCode, Version};
use saphir::error;
use sha1::Digest as _;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use tap::prelude::*;
use tokio::io::AsyncWriteExt;
use tracing::Instrument as _;
use uuid::Uuid;

#[derive(Clone)]
pub struct WebsocketService {
    pub associations: Arc<JetAssociationsMap>,
    pub token_cache: Arc<TokenCache>,
    pub jrl: Arc<CurrentJrl>,
    pub conf: Arc<Conf>,
    pub subscriber_tx: SubscriberSender,
    pub sessions: SessionManagerHandle,
}

impl WebsocketService {
    pub async fn handle(&mut self, req: Request<Body>, client_addr: SocketAddr) -> Result<Response<Body>, io::Error> {
        let req_uri = req.uri().path();

        if req.method() == Method::GET && req_uri.starts_with("/jet/accept") {
            info!("{} {}", req.method(), req_uri);
            handle_jet_accept(req, client_addr, self.associations.clone())
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET accept error - {err:?}")))
        } else if req.method() == Method::GET && req_uri.starts_with("/jet/connect") {
            info!("{} {}", req.method(), req_uri);
            handle_jet_connect(
                req,
                client_addr,
                self.associations.clone(),
                self.conf.clone(),
                self.sessions.clone(),
                self.subscriber_tx.clone(),
            )
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET connect error - {err:?}")))
        } else if req.method() == Method::GET && req_uri.starts_with("/jet/test") {
            info!("{} {}", req.method(), req_uri);
            handle_jet_test(req, &self.associations)
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET test error - {err:?}")))
        } else if req.method() == Method::GET && (req_uri.starts_with("/jmux") || req_uri.starts_with("/jet/jmux")) {
            info!("{} {}", req.method(), req_uri);
            handle_jmux(
                req,
                client_addr,
                self.conf.clone(),
                &self.token_cache,
                &self.jrl,
                self.sessions.clone(),
                self.subscriber_tx.clone(),
            )
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JMUX error - {err:#}")))
        } else if req.method() == Method::GET && req_uri.starts_with("/jet/rdp") {
            info!("{} {}", req.method(), req_uri);
            handle_rdp(
                req,
                client_addr,
                self.conf.clone(),
                self.token_cache.clone(),
                self.jrl.clone(),
                self.sessions.clone(),
                self.subscriber_tx.clone(),
            )
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle RDP error - {err:#}")))
        } else if req.method() == Method::GET && req_uri.starts_with("/jet/tcp") {
            info!("{} {}", req.method(), req_uri);
            handle_tcp(
                req,
                client_addr,
                self.conf.clone(),
                &self.token_cache,
                &self.jrl,
                self.sessions.clone(),
                self.subscriber_tx.clone(),
            )
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle TCP error - {err:#}")))
        } else if req.method() == Method::GET && req_uri.starts_with("/jet/tls") {
            info!("{} {}", req.method(), req_uri);
            handle_tls(
                req,
                client_addr,
                self.conf.clone(),
                &self.token_cache,
                &self.jrl,
                self.sessions.clone(),
                self.subscriber_tx.clone(),
            )
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle TLS error - {err:#}")))
        } else if req.method() == Method::GET && req_uri.starts_with("/jet/jrec") {
            info!("{} {}", req.method(), req_uri);
            handle_jrec(
                req,
                client_addr,
                self.conf.clone(),
                &self.token_cache,
                &self.jrl,
                self.sessions.clone(),
                self.subscriber_tx.clone(),
            )
            .await
            .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JREC error - {err:#}")))
        } else {
            saphir::server::inject_raw_with_peer_addr(req, Some(client_addr))
                .await
                .map_err(|err| match err {
                    error::SaphirError::Io(err) => err,
                    err => io::Error::new(io::ErrorKind::Other, format!("{err}")),
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
    config: Arc<Conf>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> Result<Response<Body>, saphir::error::InternalError> {
    match handle_jet_connect_impl(req, client_addr, associations, config, sessions, subscriber_tx).await {
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
    conf: Arc<Conf>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
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

                    match (association.record_session(), conf.plugins.is_some()) {
                        (true, true) => {
                            let init_result = PluginRecordingInspector::init(
                                association_id,
                                candidate_id,
                                Some(conf.recording_path.as_str()),
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

                let info = SessionInfo::new(association_id, association_claims.jet_ap, ConnectionModeDetails::Rdv)
                    .with_ttl(association_claims.jet_ttl)
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

                    let proxy_result = Proxy::builder()
                        .conf(conf.clone())
                        .session_info(info)
                        .address_a(client_addr)
                        .transport_a(client_transport)
                        .address_b(server_transport.inner.addr)
                        .transport_b(server_transport)
                        .subscriber_tx(subscriber_tx)
                        .sessions(sessions)
                        .build()
                        .forward()
                        .await;

                    if let (Some(dir), Some(pattern)) = (recording_dir, file_pattern) {
                        let registry = crate::registry::Registry::new(conf);
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

                    Proxy::builder()
                        .conf(conf)
                        .session_info(info)
                        .address_a(client_addr)
                        .transport_a(client_transport)
                        .address_b(server_transport.addr)
                        .transport_b(server_transport)
                        .subscriber_tx(subscriber_tx)
                        .sessions(sessions)
                        .build()
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

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    fn convert_key(input: &[u8]) -> String {
        const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut hasher = sha1::Sha1::new();
        hasher.update(input);
        hasher.update(WS_GUID);
        STANDARD.encode(hasher.finalize())
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
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<Response<Body>> {
    use crate::http::middlewares::auth::{parse_auth_header, AuthHeaderType};

    let token = if let Some(authorization_value) = req.headers().get(header::AUTHORIZATION) {
        let authorization_value = authorization_value.to_str().context("bad authorization header value")?; // BAD REQUEST
        match parse_auth_header(authorization_value) {
            Some((AuthHeaderType::Bearer, token)) => token,
            _ => anyhow::bail!("bad authorization header value"), // BAD REQUEST
        }
    } else if let Some(token) = req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|segment| segment.split_once('='))
            .find_map(|(key, val)| key.eq("token").then_some(val))
    }) {
        token
    } else {
        anyhow::bail!("missing authorization"); // AUTHORIZATION
    };

    let claims = crate::jmux::authorize(client_addr, token, &conf, token_cache, jrl)?; // FORBIDDEN

    if let Some(upgrade_val) = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) {
        if upgrade_val != "websocket" {
            anyhow::bail!("unexpected upgrade header value: {}", upgrade_val) // BAD REQUEST
        }
    }

    let rsp = process_req(&req);

    tokio::spawn(async move {
        let fut = async {
            let stream = upgrade_websocket(&mut req).await?;
            crate::jmux::handle(stream, claims, sessions, subscriber_tx).await
        }
        .instrument(info_span!("jmux", client = %client_addr));

        match fut.await {
            Ok(()) => {}
            Err(error) => error!(client = %client_addr, error = format!("{error:#}"), "JMUX failure"),
        }
    });

    Ok(rsp)
}

async fn handle_rdp(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> io::Result<Response<Body>> {
    if let Some(upgrade_val) = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) {
        if upgrade_val != "websocket" {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected upgrade header value: {upgrade_val}"),
            ));
        }
    }

    let rsp = process_req(&req);

    tokio::spawn(async move {
        let fut = async {
            let stream = upgrade_websocket(&mut req).await?;
            crate::rdp_extension::handle(stream, client_addr, conf, &token_cache, &jrl, sessions, subscriber_tx).await
        }
        .instrument(info_span!("rdp", client = %client_addr));

        match fut.await {
            Ok(()) => {}
            Err(error) => error!(client = %client_addr, error = format!("{error:#}"), "RDP failure"),
        }
    });

    Ok(rsp)
}

async fn handle_tcp(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<Response<Body>> {
    use crate::http::middlewares::auth::{parse_auth_header, AuthHeaderType};

    let token = if let Some(authorization_value) = req.headers().get(header::AUTHORIZATION) {
        let authorization_value = authorization_value.to_str().context("bad authorization header value")?; // BAD REQUEST
        match parse_auth_header(authorization_value) {
            Some((AuthHeaderType::Bearer, token)) => token,
            _ => anyhow::bail!("bad authorization header value"), // BAD REQUEST
        }
    } else if let Some(token) = req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|segment| segment.split_once('='))
            .find_map(|(key, val)| key.eq("token").then_some(val))
    }) {
        token
    } else {
        anyhow::bail!("missing authorization"); // AUTHORIZATION
    };

    let claims = crate::websocket_forward::authorize(client_addr, token, &conf, token_cache, jrl)?; // FORBIDDEN

    if let Some(upgrade_val) = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) {
        if upgrade_val != "websocket" {
            anyhow::bail!("unexpected upgrade header value: {}", upgrade_val) // BAD REQUEST
        }
    }

    let rsp = process_req(&req);

    tokio::spawn(async move {
        let fut = async {
            let stream = upgrade_websocket(&mut req).await?;
            crate::websocket_forward::PlainForward::builder()
                .client_addr(client_addr)
                .client_stream(stream)
                .conf(conf)
                .claims(claims)
                .sessions(sessions)
                .subscriber_tx(subscriber_tx)
                .build()
                .run()
                .await
        }
        .instrument(info_span!("tcp", client = %client_addr));

        match fut.await {
            Ok(()) => {}
            Err(error) => error!(client = %client_addr, error = format!("{error:#}"), "WebSocket-TCP failure"),
        }
    });

    Ok(rsp)
}

async fn handle_tls(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<Response<Body>> {
    use crate::http::middlewares::auth::{parse_auth_header, AuthHeaderType};

    let token = if let Some(authorization_value) = req.headers().get(header::AUTHORIZATION) {
        let authorization_value = authorization_value.to_str().context("bad authorization header value")?; // BAD REQUEST
        match parse_auth_header(authorization_value) {
            Some((AuthHeaderType::Bearer, token)) => token,
            _ => anyhow::bail!("bad authorization header value"), // BAD REQUEST
        }
    } else if let Some(token) = req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|segment| segment.split_once('='))
            .find_map(|(key, val)| key.eq("token").then_some(val))
    }) {
        token
    } else {
        anyhow::bail!("missing authorization"); // AUTHORIZATION
    };

    let claims = crate::websocket_forward::authorize(client_addr, token, &conf, token_cache, jrl)?; // FORBIDDEN

    if let Some(upgrade_val) = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) {
        if upgrade_val != "websocket" {
            anyhow::bail!("unexpected upgrade header value: {}", upgrade_val) // BAD REQUEST
        }
    }

    let rsp = process_req(&req);

    tokio::spawn(async move {
        let fut = async {
            let stream = upgrade_websocket(&mut req).await?;
            crate::websocket_forward::PlainForward::builder()
                .client_addr(client_addr)
                .client_stream(stream)
                .conf(conf)
                .claims(claims)
                .sessions(sessions)
                .subscriber_tx(subscriber_tx)
                .with_tls(true)
                .build()
                .run()
                .await
        }
        .instrument(info_span!("tls", client = %client_addr));

        match fut.await {
            Ok(()) => {}
            Err(error) => error!(client = %client_addr, error = format!("{error:#}"), "WebSocket-TLS failure"),
        }
    });

    Ok(rsp)
}

async fn handle_jrec(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    _sessions: SessionManagerHandle,
    _subscriber_tx: SubscriberSender,
) -> anyhow::Result<Response<Body>> {
    use crate::http::middlewares::auth::{parse_auth_header, AuthHeaderType};

    let token = if let Some(authorization_value) = req.headers().get(header::AUTHORIZATION) {
        let authorization_value = authorization_value.to_str().context("bad authorization header value")?; // BAD REQUEST
        match parse_auth_header(authorization_value) {
            Some((AuthHeaderType::Bearer, token)) => token,
            _ => anyhow::bail!("bad authorization header value"), // BAD REQUEST
        }
    } else if let Some(token) = req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|segment| segment.split_once('='))
            .find_map(|(key, val)| key.eq("token").then_some(val))
    }) {
        token
    } else {
        anyhow::bail!("missing authorization"); // AUTHORIZATION
    };

    let claims = crate::jrec::authorize(client_addr, token, &conf, token_cache, jrl)?; // FORBIDDEN

    if let Some(upgrade_val) = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) {
        if upgrade_val != "websocket" {
            anyhow::bail!("unexpected upgrade header value: {}", upgrade_val) // BAD REQUEST
        }
    }

    let rsp = process_req(&req);

    tokio::spawn(async move {
        let fut = async {
            let stream = upgrade_websocket(&mut req).await?;
            crate::jrec::PlainForward::builder()
                .client_stream(stream)
                .conf(conf)
                .claims(claims)
                .build()
                .run()
                .await
        }
        .instrument(info_span!("rec", client = %client_addr));

        match fut.await {
            Ok(()) => {}
            Err(error) => error!(client = %client_addr, error = format!("{error:#}"), "WebSocket-JREC failure"),
        }
    });

    Ok(rsp)
}

type WebsocketTransport = transport::WebSocketStream<tokio_tungstenite::WebSocketStream<hyper::upgrade::Upgraded>>;

async fn upgrade_websocket(req: &mut Request<Body>) -> anyhow::Result<WebsocketTransport> {
    use tokio_tungstenite::tungstenite::protocol::Role;

    hyper::upgrade::on(req)
        .await
        .context("WebSocket upgrade failure")?
        .pipe(|upgraded| tokio_tungstenite::WebSocketStream::from_raw_socket(upgraded, Role::Server, None))
        .await
        .pipe(transport::WebSocketStream::new)
        .pipe(Ok)
}
