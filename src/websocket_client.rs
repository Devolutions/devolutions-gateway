use std::sync::Arc;
use crate::jet_client::JetAssociationsMap;
use hyper::{Request, Body, Response, Method, StatusCode, header, Version, http};
use futures::{Future, future};
use tokio::runtime::TaskExecutor;
use uuid::Uuid;
use crate::transport::{JetTransport, Transport};
use crate::transport::ws::WsTransport;
use std::net::SocketAddr;
use crate::config::Config;
use crate::Proxy;
use slog_scope::{info, error};
use url::Url;
use std::io;
use saphir::server::HttpService;
use crate::jet::TransportType;
use jet_proto::JET_VERSION_V2;
use crate::utils::association::RemoveAssociation;
use crate::jet::candidate::CandidateState;

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

            handle_jet_accept(req, client_addr, &mut self.jet_associations, &mut self.executor_handle)
        } else if req.method() == Method::GET && req.uri().path().starts_with("/jet/connect") {
            info!("{} {}", req.method(), req.uri().path());

            handle_jet_connect(
                req,
                client_addr,
                &mut self.jet_associations,
                &mut self.executor_handle,
                self.config.clone(),
            )
        } else {
            self.http_service.handle(req)
        }
    }
}

fn handle_jet_accept(
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
    jet_associations: &mut JetAssociationsMap,
    executor_handle: &mut TaskExecutor,
) -> Box<dyn Future<Item = Response<Body>, Error = saphir::error::ServerError> + Send> {
    if let Some(header) = req.headers().get("upgrade") {
        if header.to_str().ok().filter(|s| s == &"websocket").is_some() {
            if let (Some(association_id), Some(candidate_id)) = (
                get_uuid_in_path(req.uri().path(), 2),
                get_uuid_in_path(req.uri().path(), 3),
            ) {
                let jet_associations_clone = jet_associations.clone();
                if let Ok(jet_associations) = jet_associations.lock() {
                    if let Some(association) = jet_associations.get(&association_id) {
                        if association.version() == JET_VERSION_V2 {
                            let res = process_req(&req);

                            let fut = req
                                .into_body()
                                .on_upgrade()
                                .map(move |upgraded| {
                                    if let Ok(mut jet_assc) = jet_associations_clone.lock() {
                                        if let Some(assc) = jet_assc.get_mut(&association_id) {
                                            if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                                                candidate.set_state(CandidateState::Accepted);
                                                candidate.set_transport(JetTransport::Ws(WsTransport::new_http(
                                                    upgraded,
                                                    client_addr,
                                                )));
                                            }
                                        }
                                    }
                                })
                                .map_err(|e| error!("upgrade error: {}", e));

                            executor_handle.spawn(fut);

                            return Box::new(future::ok(res));
                        }
                    }
                }
            }
        }
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::FORBIDDEN;

    Box::new(future::ok(response))
}

fn handle_jet_connect(
    req: Request<Body>,
    client_addr: Option<SocketAddr>,
    jet_associations: &mut JetAssociationsMap,
    executor_handle: &mut TaskExecutor,
    config: Arc<Config>,
) -> Box<dyn Future<Item = Response<Body>, Error = saphir::error::ServerError> + Send> {
    if let Some(header) = req.headers().get("upgrade") {
        if header.to_str().ok().filter(|s| s == &"websocket").is_some() {
            let jet_associations_clone = jet_associations.clone();
            if let Ok(mut jet_associations) = jet_associations.lock() {
                if let (Some(association_id), Some(candidate_id)) = (
                    get_uuid_in_path(req.uri().path(), 2),
                    get_uuid_in_path(req.uri().path(), 3),
                ) {
                    if let Some(association) = jet_associations.get_mut(&association_id) {
                        if association.version() == JET_VERSION_V2 {
                            let res = process_req(&req);

                            let executor_handle_clone = executor_handle.clone();
                            let fut = req
                                .into_body()
                                .on_upgrade()
                                .map(move |upgraded| {
                                    if let Ok(mut jet_assc) = jet_associations_clone.lock() {
                                        if let Some(assc) = jet_assc.get_mut(&association_id) {
                                            if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                                                if (candidate.transport_type() == TransportType::Ws || candidate.transport_type() == TransportType::Wss)
                                                    && candidate.state() == CandidateState::Accepted {
                                                    {
                                                        let server_transport = candidate
                                                            .take_transport()
                                                            .expect("Candidate cannot be created without a transport");
                                                        let client_transport =
                                                            JetTransport::Ws(WsTransport::new_http(upgraded, client_addr));
                                                        candidate.set_state(CandidateState::Connected);
                                                        candidate.set_client_nb_bytes_read(
                                                            client_transport.clone_nb_bytes_read(),
                                                        );
                                                        candidate.set_client_nb_bytes_written(
                                                            client_transport.clone_nb_bytes_written(),
                                                        );

                                                        // Start the proxy
                                                        let remove_association = RemoveAssociation::new(
                                                            jet_associations_clone.clone(),
                                                            candidate.association_id(),
                                                            Some(candidate.id()),
                                                        );

                                                        let proxy = Proxy::new(config)
                                                            .build(server_transport, client_transport)
                                                            .then(move |_| remove_association)
                                                            .map(|_| ());

                                                        executor_handle_clone.spawn(proxy);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                })
                                .map_err(|e| error!("upgrade error: {}", e));

                            executor_handle.spawn(fut);

                            return Box::new(future::ok(res));
                        }
                    }
                }
            }
        }
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::BAD_REQUEST;

    Box::new(future::ok(response))
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
    let is_upgrade = req.headers()
        .get(header::CONNECTION)
        .map_or(false, |v| connection_has(v, "upgrade"));
    let is_websocket_upgrade = req.headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.eq_ignore_ascii_case("websocket"));

    let is_websocket_version_13_or_higher = req.headers()
        .get(header::SEC_WEBSOCKET_VERSION)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.parse::<u32>().unwrap_or_else(|_| 0) >= 13);

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
    if let Some(raw_uuid) = path.split("/").skip(index + 1).next() {
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
    ) -> Box<dyn Future<Item=(), Error=io::Error> + Send> {
        let server_conn = WsTransport::connect(&self.routing_url);

        Box::new(server_conn.and_then(move |server_transport| {
            Proxy::new(self.config.clone()).build(server_transport, client_transport)
        }))
    }
}
