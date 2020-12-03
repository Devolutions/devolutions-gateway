use crate::{
    config::Config,
    jet::{candidate::CandidateState, TransportType},
    jet_client::JetAssociationsMap,
    transport::{ws::WsTransport, JetTransport, Transport},
    utils::association::RemoveAssociation,
    Proxy,
};
use futures::{future, Future};
use hyper::{header, http, Body, Method, Request, Response, StatusCode, Version};
use saphir::server::HttpService;
use slog_scope::{error, info};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::runtime::TaskExecutor;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct WebsocketService {
    pub http_service: HttpService,
    pub jet_associations: JetAssociationsMap,
    pub executor_handle: TaskExecutor,
    pub config: Arc<Config>,
}

impl WebsocketService {
    pub fn handle(
        &mut self,
        req: Request<Body>,
        client_addr: Option<SocketAddr>,
    ) -> Box<dyn Future<Item = Response<Body>, Error = saphir::error::ServerError> + Send> {
        if req.method() == Method::GET && req.uri().path().starts_with("/jet/accept") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_accept(
                req,
                client_addr,
                self.jet_associations.clone(),
                self.executor_handle.clone(),
            )
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jet/connect") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_connect(
                req,
                client_addr,
                self.jet_associations.clone(),
                self.executor_handle.clone(),
                self.config.clone(),
            )
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jet/test") {
            info!("{} {}", req.method(), req.uri().path());
            handle_jet_test(req, self.jet_associations.clone())
        } else {
            self.http_service.handle(req)
        }
    }
}

fn handle_jet_test(
    req: Request<Body>,
    jet_associations: JetAssociationsMap,
) -> Box<dyn Future<Item = Response<Body>, Error = saphir::error::ServerError> + Send> {
    match handle_jet_test_impl(req, jet_associations) {
        Ok(res) => Box::new(future::ok(res)),
        Err(status) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = status;
            Box::new(future::ok(res))
        }
    }
}

fn handle_jet_test_impl(
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

    let jet_assc = jet_associations.lock().unwrap();
    let assc = jet_assc.get(&association_id).ok_or(StatusCode::NOT_FOUND)?;
    if assc.get_candidate(candidate_id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(process_req(&req))
}

fn handle_jet_accept(
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
) -> Box<dyn Future<Item = Response<Body>, Error = saphir::error::ServerError> + Send> {
    match handle_jet_accept_impl(req, client_addr, jet_associations, executor_handle) {
        Ok(res) => Box::new(future::ok(res)),
        Err(()) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::FORBIDDEN;
            Box::new(future::ok(res))
        }
    }
}

fn handle_jet_accept_impl(
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
) -> Result<Response<Body>, ()> {
    let header = req.headers().get("upgrade").ok_or(())?;
    let header_str = header.to_str().map_err(|_| ())?;
    if header_str != "websocket" {
        return Err(());
    }

    let association_id = get_uuid_in_path(req.uri().path(), 2).ok_or(())?;
    let candidate_id = get_uuid_in_path(req.uri().path(), 3).ok_or(())?;

    let version = {
        let associations = jet_associations.lock().unwrap(); // TODO: replace by parking lot
        let association = associations.get(&association_id).ok_or(())?;
        association.version()
    };

    let res = process_req(&req);
    let on_upgrade = req.into_body().on_upgrade();

    match version {
        2 | 3 => {
            let fut = on_upgrade
                .map(move |upgraded| {
                    let mut jet_assc = jet_associations.lock().unwrap();
                    if let Some(assc) = jet_assc.get_mut(&association_id) {
                        if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                            candidate.set_state(CandidateState::Accepted);
                            candidate.set_transport(JetTransport::Ws(WsTransport::new_http(upgraded, client_addr)));
                        }
                    }
                })
                .map_err(|e| error!("upgrade error: {}", e));

            executor_handle.spawn(fut);

            Ok(res)
        }
        _ => Err(()),
    }
}

fn handle_jet_connect(
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
    config: Arc<Config>,
) -> Box<dyn Future<Item = Response<Body>, Error = saphir::error::ServerError> + Send> {
    match handle_jet_connect_impl(req, client_addr, jet_associations, executor_handle, config) {
        Ok(res) => Box::new(future::ok(res)),
        Err(()) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::BAD_REQUEST;
            Box::new(future::ok(res))
        }
    }
}

fn handle_jet_connect_impl(
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
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
        let associations = jet_associations.lock().unwrap(); // TODO: replace by parking lot
        let association = associations.get(&association_id).ok_or(())?;
        association.version()
    };

    let res = process_req(&req);
    let on_upgrade = req.into_body().on_upgrade();

    match version {
        2 | 3 => {
            let executor_handle_cloned = executor_handle.clone();

            let fut = on_upgrade
                .map(move |upgraded| {
                    let mut jet_assc = jet_associations.lock().unwrap();

                    let assc = if let Some(assc) = jet_assc.get_mut(&association_id) {
                        assc
                    } else {
                        return;
                    };

                    let candidate = if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                        candidate
                    } else {
                        return;
                    };

                    if (candidate.transport_type() == TransportType::Ws
                        || candidate.transport_type() == TransportType::Wss)
                        && candidate.state() == CandidateState::Accepted
                    {
                        let server_transport = candidate
                            .take_transport()
                            .expect("Candidate cannot be created without a transport");
                        let client_transport = JetTransport::Ws(WsTransport::new_http(upgraded, client_addr));
                        candidate.set_state(CandidateState::Connected);
                        candidate.set_client_nb_bytes_read(client_transport.clone_nb_bytes_read());
                        candidate.set_client_nb_bytes_written(client_transport.clone_nb_bytes_written());

                        // Start the proxy
                        let remove_association = RemoveAssociation::new(
                            jet_associations.clone(),
                            candidate.association_id(),
                            Some(candidate.id()),
                        );

                        let proxy = Proxy::new(config)
                            .build(server_transport, client_transport)
                            .then(move |_| remove_association)
                            .map(|_| ());

                        executor_handle_cloned.spawn(proxy);
                    }
                })
                .map_err(|e| error!("upgrade error: {}", e));

            executor_handle.spawn(fut);

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

    let mut builder = Response::builder();

    builder
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, key.as_str());

    // Add the SEC_WEBSOCKET_PROTOCOL header only if it was in the request, otherwise, IIS doesn't like it
    if let Some(websocket_protocol) = req.headers().get(header::SEC_WEBSOCKET_PROTOCOL) {
        builder.header(header::SEC_WEBSOCKET_PROTOCOL, websocket_protocol);
    }

    builder.body(Body::empty()).unwrap()
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
    _executor_handle: TaskExecutor,
}

impl WsClient {
    pub fn new(routing_url: Url, config: Arc<Config>, executor_handle: TaskExecutor) -> Self {
        WsClient {
            routing_url,
            config,
            _executor_handle: executor_handle,
        }
    }

    pub fn serve<T: 'static + Transport + Send>(
        self,
        client_transport: T,
    ) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let server_conn = WsTransport::connect(&self.routing_url);

        Box::new(server_conn.and_then(move |server_transport| {
            Proxy::new(self.config.clone()).build(server_transport, client_transport)
        }))
    }
}
