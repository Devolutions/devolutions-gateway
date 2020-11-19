use crate::{
    config::Config,
    jet::{candidate::CandidateState, TransportType},
    jet_client::JetAssociationsMap,
    transport::{ws::WsTransport, JetTransport, Transport},
    utils::association::RemoveAssociation,
    Proxy,
};

use hyper::{header, http, Body, Method, Request, Response, StatusCode, Version};
use slog_scope::{error, info};
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct WebsocketService {
    pub jet_associations: JetAssociationsMap,
    pub config: Arc<Config>,
}

impl WebsocketService {
    pub async fn handle(
        &mut self,
        req: Request<Body>,
        client_addr: Option<SocketAddr>,
    ) -> Result<Response<Body>, io::Error> {
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
        } else {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            Ok(resp)
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
    client_addr: Option<SocketAddr>,
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
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
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
        let associations = jet_associations.lock().await; // TODO: replace by parking lot
        let association = associations.get(&association_id).ok_or(())?;
        association.version()
    };

    let res = process_req(&req);

    match version {
        2 | 3 => {
            tokio::spawn(async move {
                let upgrade = req
                    .into_body()
                    .on_upgrade()
                    .await
                    .map_err(|e| error!("upgrade error: {}", e))?;

                let mut jet_assc = jet_associations.lock().await;
                if let Some(assc) = jet_assc.get_mut(&association_id) {
                    if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                        candidate.set_state(CandidateState::Accepted);
                        let ws_transport = WsTransport::new_http(upgrade, client_addr).await;
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
    client_addr: Option<SocketAddr>,
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
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
    jet_associations: JetAssociationsMap,
    config: Arc<Config>,
) -> Result<Response<Body>, ()> {
    let header = req.headers().get("upgrade").ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    if header_str != "websocket" {
        return Err(());
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(())?;

    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(())?;
    let version = {
        let associations = jet_associations.lock().await; // TODO: replace by parking lot
        let association = associations.get(&association_id).ok_or(())?;
        association.version()
    };

    let res = process_req(&req);

    match version {
        2 | 3 => {
            tokio::spawn(async move {
                let upgrade = req
                    .into_body()
                    .on_upgrade()
                    .await
                    .map_err(|e| error!("upgrade error: {}", e))?;

                let mut jet_assc = jet_associations.lock().await;

                let assc = if let Some(assc) = jet_assc.get_mut(&association_id) {
                    assc
                } else {
                    return Err(());
                };

                let candidate = if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                    candidate
                } else {
                    return Err(());
                };

                if (candidate.transport_type() == TransportType::Ws || candidate.transport_type() == TransportType::Wss)
                    && candidate.state() == CandidateState::Accepted
                {
                    let server_transport = candidate
                        .take_transport()
                        .expect("Candidate cannot be created without a transport");
                    let ws_transport = WsTransport::new_http(upgrade, client_addr).await;
                    let client_transport = JetTransport::Ws(ws_transport);
                    candidate.set_state(CandidateState::Connected);
                    candidate.set_client_nb_bytes_read(client_transport.clone_nb_bytes_read());
                    candidate.set_client_nb_bytes_written(client_transport.clone_nb_bytes_written());

                    // Start the proxy
                    let remove_association = RemoveAssociation::new(
                        jet_associations.clone(),
                        candidate.association_id(),
                        Some(candidate.id()),
                    );

                    Proxy::new(config)
                        .build(server_transport, client_transport)
                        .await
                        .map_err(|_| ())?;
                    let _ = remove_association.await;
                }
                Ok(())
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

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, key.as_str())
        .header(header::SEC_WEBSOCKET_PROTOCOL, "binary")
        .body(Body::empty())
        .unwrap()
}

fn get_uuid_in_path(path: &str, index: usize) -> Option<Uuid> {
    if let Some(raw_uuid) = path.split('/').nth(index + 1) {
        Uuid::parse_str(raw_uuid).ok()
    } else {
        None
    }
}

pub struct WsClient {
    routing_url: Url,
    config: Arc<Config>,
}

impl WsClient {
    pub fn new(routing_url: Url, config: Arc<Config>) -> Self {
        WsClient { routing_url, config }
    }

    pub async fn serve<T>(self, client_transport: T) -> Result<(), io::Error>
    where
        T: 'static + Transport + Send,
    {
        let server_transport = WsTransport::connect(&self.routing_url).await?;
        Proxy::new(self.config.clone())
            .build(server_transport, client_transport)
            .await
    }
}
