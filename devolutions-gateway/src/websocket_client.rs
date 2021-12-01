use crate::config::Config;
use crate::jet::candidate::CandidateState;
use crate::jet::TransportType;
use crate::jet_client::JetAssociationsMap;
use crate::token::ApplicationProtocol;
use crate::transport::ws::WsTransport;
use crate::transport::{JetTransport, Transport};
use crate::utils::association::remove_jet_association;
use crate::utils::TargetAddr;
use crate::{ConnectionModeDetails, GatewaySessionInfo, Proxy};
use hyper::{header, http, Body, Method, Request, Response, StatusCode, Version};
use jmux_proxy::JmuxProxy;
use saphir::error;
use slog_scope::{error, info};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct WebsocketService {
    pub jet_associations: JetAssociationsMap,
    pub config: Arc<Config>,
}

impl WebsocketService {
    pub async fn handle(&mut self, req: Request<Body>, client_addr: SocketAddr) -> Result<Response<Body>, io::Error> {
        if req.method() == Method::GET && req.uri().path().starts_with("/jet/accept") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_accept(req, client_addr, self.jet_associations.clone())
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET accept error - {:?}", err)))
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jet/connect") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_connect(req, client_addr, self.jet_associations.clone(), self.config.clone())
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET connect error - {:?}", err)))
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jet/test") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_test(req, self.jet_associations.clone())
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JET test error - {:?}", err)))
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jmux") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jmux(req, client_addr, self.config.clone())
                .await
                .map_err(|err| io::Error::new(ErrorKind::Other, format!("Handle JMUX error - {:?}", err)))
        } else {
            saphir::server::inject_raw(req).await.map_err(|err| match err {
                error::SaphirError::Io(err) => err,
                err => io::Error::new(io::ErrorKind::Other, format!("{}", err)),
            })
        }
    }
}

async fn handle_jet_test(
    req: Request<Body>,
    jet_associations: JetAssociationsMap,
) -> Result<Response<Body>, saphir::error::InternalError> {
    match handle_jet_test_impl(req, jet_associations).await {
        Ok(res) => Ok(res),
        Err(status) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = status;
            Ok(res)
        }
    }
}

async fn handle_jet_test_impl(
    req: Request<Body>,
    jet_associations: JetAssociationsMap,
) -> Result<Response<Body>, StatusCode> {
    let header = req.headers().get("upgrade").ok_or(StatusCode::BAD_REQUEST)?;
    let header_str = header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
    if header_str != "websocket" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(StatusCode::BAD_REQUEST)?;
    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(StatusCode::BAD_REQUEST)?;

    let jet_assc = jet_associations.lock().await;
    let assc = jet_assc.get(&association_id).ok_or(StatusCode::NOT_FOUND)?;
    if assc.get_candidate(candidate_id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(process_req(&req))
}

async fn handle_jet_accept(
    req: Request<Body>,
    client_addr: SocketAddr,
    jet_associations: JetAssociationsMap,
) -> Result<Response<Body>, saphir::error::InternalError> {
    match handle_jet_accept_impl(req, client_addr, jet_associations).await {
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
    jet_associations: JetAssociationsMap,
) -> Result<Response<Body>, ()> {
    let header = req.headers().get("upgrade").ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    if header_str != "websocket" {
        return Err(());
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(())?;
    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(())?;

    let version = {
        let associations = jet_associations.lock().await;
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

                let mut jet_assc = jet_associations.lock().await;
                if let Some(assc) = jet_assc.get_mut(&association_id) {
                    if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                        candidate.set_state(CandidateState::Accepted);
                        let ws_transport = WsTransport::new_http(upgraded, Some(client_addr)).await;
                        candidate.set_transport(JetTransport::Ws(ws_transport));
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
    jet_associations: JetAssociationsMap,
    config: Arc<Config>,
) -> Result<Response<Body>, saphir::error::InternalError> {
    match handle_jet_connect_impl(req, client_addr, jet_associations, config).await {
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
    jet_associations: JetAssociationsMap,
    config: Arc<Config>,
) -> Result<Response<Body>, ()> {
    use crate::interceptor::pcap_recording::PcapRecordingInterceptor;
    use crate::interceptor::PacketInterceptor;

    let header = req.headers().get("upgrade").ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    if header_str != "websocket" {
        return Err(());
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(())?;

    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(())?;
    let (version, association_claims) = {
        let associations = jet_associations.lock().await;
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

                let mut associations = jet_associations.lock().await;
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
                let is_websocket =
                    candidate.transport_type() == TransportType::Ws || candidate.transport_type() == TransportType::Wss;
                let is_accepted = candidate.state() != CandidateState::Accepted;
                if !is_websocket || !is_accepted {
                    error!(
                        "Unexpected candidate properties [is websocket? {}] [is accepted? {}]",
                        is_websocket, is_accepted
                    );
                    return Err(());
                }

                let server_transport = candidate
                    .take_transport()
                    .expect("Candidate cannot be created without a transport");
                let ws_transport = WsTransport::new_http(upgraded, Some(client_addr)).await;
                let client_transport = JetTransport::Ws(ws_transport);
                candidate.set_state(CandidateState::Connected);
                candidate.set_client_nb_bytes_read(client_transport.clone_nb_bytes_read());
                candidate.set_client_nb_bytes_written(client_transport.clone_nb_bytes_written());

                let association_id = candidate.association_id();
                let candidate_id = candidate.id();

                let mut file_pattern = None;
                let mut recording_dir = None;
                let mut recording_interceptor: Option<Box<dyn PacketInterceptor>> = None;
                let mut has_interceptor = false;

                match (association.record_session(), config.plugins.is_some()) {
                    (true, true) => {
                        let mut interceptor = PcapRecordingInterceptor::new(
                            server_transport.peer_addr().unwrap(),
                            client_addr,
                            association_id.to_string(),
                            candidate_id.to_string(),
                        );

                        recording_dir = match &config.recording_path {
                            Some(path) => {
                                interceptor.set_recording_directory(path.as_str());
                                Some(std::path::PathBuf::from(path))
                            }
                            _ => interceptor.get_recording_directory(),
                        };

                        file_pattern = Some(interceptor.get_filename_pattern());

                        recording_interceptor = Some(Box::new(interceptor));
                        has_interceptor = true;
                    }
                    (true, false) => {
                        error!("Can't meet recording policy");
                        return Err(());
                    }
                    (false, _) => {}
                }

                // We need to manually drop mutex lock to avoid deadlock below
                std::mem::drop(associations);

                let info =
                    GatewaySessionInfo::new(association_id, association_claims.jet_ap, ConnectionModeDetails::Rdv)
                        .with_recording_policy(association_claims.jet_rec)
                        .with_filtering_policy(association_claims.jet_flt);

                let proxy_result = Proxy::new(config.clone(), info)
                    .build_with_packet_interceptor(server_transport, client_transport, recording_interceptor)
                    .await;

                if has_interceptor {
                    if let (Some(dir), Some(pattern)) = (recording_dir, file_pattern) {
                        let registry = crate::registry::Registry::new(config);
                        registry
                            .manage_files(association_id.to_string(), pattern, dir.as_path())
                            .await;
                    };
                }

                if let Err(e) = proxy_result {
                    error!("failed to build Proxy for WebSocket connection: {}", e)
                }

                remove_jet_association(jet_associations.clone(), association_id, Some(candidate_id)).await;

                Ok::<(), ()>(())
            });

            Ok(res)
        }
        _ => Err(()),
    }
}

fn process_req(req: &Request<Body>) -> Response<Body> {
    /*
        Source: https://gist.github.com/bluetech/192c74b9c4ae541747718ac4f4e20a14
        Author: Ran Benita<bluetech> (ran234@gmail.com)
    */

    fn convert_key(input: &[u8]) -> String {
        const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut digest = sha1::Sha1::new();
        digest.update(input);
        digest.update(WS_GUID);
        base64::encode(&digest.digest().bytes())
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

fn get_uuid_in_path(path: &str, index: usize) -> Option<Uuid> {
    if let Some(raw_uuid) = path.split('/').nth(index + 1) {
        Uuid::parse_str(raw_uuid).ok()
    } else {
        None
    }
}

async fn handle_jmux(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    config: Arc<Config>,
) -> io::Result<Response<Body>> {
    use crate::http::middlewares::auth::{parse_auth_header, AuthHeaderType};
    use crate::token::{validate_token, JetAccessTokenClaims};

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

    match validate_token(token, client_addr.ip(), provisioner_key, delegation_key) {
        Ok(JetAccessTokenClaims::Jmux(_)) => {}
        Ok(_) => {
            return Err(io::Error::new(io::ErrorKind::Other, "wrong access token"));
        }
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("couldn't validate token: {}", e),
            ));
        }
    }

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
        use jmux_proxy::JmuxConfig;
        use slog::o;

        let upgraded = hyper::upgrade::on(&mut req)
            .await
            .map_err(|e| error!("upgrade error: {}", e))?;

        let ws_transport = WsTransport::new_http(upgraded, Some(client_addr)).await;

        let (read, write) = tokio::io::split(ws_transport);

        let jmux_proxy_log = slog_scope::logger().new(o!("client_addr" => client_addr));

        JmuxProxy::new(Box::new(read), Box::new(write))
            .with_config(JmuxConfig::permissive())
            .with_logger(jmux_proxy_log)
            .run()
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

    pub async fn serve<T>(self, client_transport: T) -> io::Result<()>
    where
        T: 'static + Transport + Send,
    {
        let server_transport = WsTransport::connect(&self.routing_url).await?;

        let destination_host =
            TargetAddr::try_from(&self.routing_url).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Proxy::new(
            self.config.clone(),
            GatewaySessionInfo::new(
                Uuid::new_v4(),
                ApplicationProtocol::Unknown,
                ConnectionModeDetails::Fwd { destination_host },
            ),
        )
        .build(server_transport, client_transport)
        .await
    }
}
