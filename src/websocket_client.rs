use crate::jet_client::JetAssociationsMap;
use hyper::{Request, Body, Response, Method, StatusCode, header, Version, http};
use futures::Future;
use tokio::runtime::TaskExecutor;
use uuid::Uuid;
use crate::transport::{JetTransport, Transport};
use crate::transport::ws::WsTransport;
use std::net::SocketAddr;
use crate::config::Config;
use crate::Proxy;
use log::{info, error};
use url::Url;
use std::io;
use crate::jet::association::Association;
use jet_proto::{JET_VERSION_V2};
use crate::jet::candidate::{Candidate};
use crate::jet_client::JET_INSTANCE;

#[derive(Clone)]
pub struct WebsocketService {
    pub jet_associations: JetAssociationsMap,
    pub executor_handle: TaskExecutor,
    pub config: Config,
}

impl WebsocketService {
    pub fn handle(&mut self, req: Request<Body>, client_addr: Option<SocketAddr>) -> Box<dyn Future<Item=Response<Body>, Error=hyper::Error> + Send> {
        let mut response = Response::new(Body::empty());
        info!("HTTP request received: {} on path {}", req.method(), req.uri().path());
        match req.method() {
            &Method::GET => if req.uri().path().starts_with("/jet/accept") {
                if let Some(header) = req.headers().get("upgrade") {
                    if header.to_str().ok().filter(|s| s == &"websocket").is_some() {
                        if let (Some(association_id), Some(candidate_id)) = (get_uuid_in_path(req.uri().path(), 2), get_uuid_in_path(req.uri().path(), 3)) {
                            if let Ok(jet_associations) = self.jet_associations.lock() {
                                if let Some(_) = jet_associations.get(&association_id) {
                                    let res = process_req(&req);

                                    let jet_associations_clone = self.jet_associations.clone();
                                    let fut = req.into_body().on_upgrade().map(move |upgraded| {
                                        if let Ok(mut jet_assc) = jet_associations_clone.lock() {
                                            if let Some(assc) = jet_assc.get_mut(&association_id) {
                                                if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                                                    candidate.set_server_transport(JetTransport::Ws(WsTransport::new_http(upgraded, client_addr)));
                                                }
                                            }
                                        }
                                    }).map_err(|e| error!("upgrade error: {}", e));

                                    self.executor_handle.spawn(fut);

                                    return Box::new(futures::future::ok::<Response<Body>, hyper::Error>(res));
                                }
                            }
                        }
                    }
                }
                *response.status_mut() = StatusCode::FORBIDDEN;
            } else if req.uri().path().starts_with("/jet/connect") {
                if let Some(header) = req.headers().get("upgrade") {
                    if header.to_str().ok().filter(|s| s == &"websocket").is_some() {
                        if let Ok(mut jet_associations) = self.jet_associations.lock() {
                            if let (Some(association_id), Some(candidate_id)) = (get_uuid_in_path(req.uri().path(), 2), get_uuid_in_path(req.uri().path(), 3)) {
                                if let Some(_) = jet_associations.get_mut(&association_id) {
                                    let res = process_req(&req);

                                    let jet_associations_clone = self.jet_associations.clone();
                                    let self_clone = self.clone();
                                    let fut = req.into_body().on_upgrade().map(move |upgraded| {
                                        if let Ok(mut jet_assc) = jet_associations_clone.lock() {
                                            if let Some(assc) = jet_assc.get_mut(&association_id) {
                                                if let Some(candidate) = assc.get_candidate_mut(candidate_id) {
                                                    candidate.set_client_transport(JetTransport::Ws(WsTransport::new_http(upgraded, client_addr)));

                                                    // Start the proxy
                                                    if let (Some(server_transport), Some(client_transport)) = (candidate.server_transport(), candidate.client_transport()) {
                                                        let proxy = Proxy::new(self_clone.config.clone()).build(server_transport, client_transport).map_err(|_| ());
                                                        self_clone.executor_handle.spawn(proxy);
                                                    }
                                                }
                                            }
                                        }
                                    }).map_err(|e| error!("upgrade error: {}", e));

                                    self.executor_handle.spawn(fut);

                                    return Box::new(futures::future::ok::<Response<Body>, hyper::Error>(res));
                                }
                            }
                        }
                    }
                }
                *response.status_mut() = StatusCode::BAD_REQUEST;
            } else {
                *response.status_mut() = StatusCode::BAD_REQUEST;
            },

            &Method::POST => if req.uri().path().starts_with("/jet/create") {
                if let Some(uuid) = uuid_from_path(req.uri().path()) {
                    if let Ok(mut jet_associations) = self.jet_associations.lock() {
                        if !jet_associations.contains_key(&uuid) {
                            jet_associations.insert(uuid, Association::new(uuid, JET_VERSION_V2));
                            return Box::new(futures::future::ok::<Response<Body>, hyper::Error>(response));
                        }
                    }
                }
                *response.status_mut() = StatusCode::BAD_REQUEST;

            } else if req.uri().path().starts_with("/jet/gather") {
                *response.status_mut() = StatusCode::BAD_REQUEST;
                if let Some(association_id) = get_uuid_in_path(req.uri().path(), 2) {
                    if let Ok(mut jet_associations) = self.jet_associations.lock() {
                        if let Some(association) = jet_associations.get_mut(&association_id) {
                            for listener in self.config.listeners().expect("Should never happen") {
                                if let Some(candidate) = Candidate::new(&format!("{}://{}:{}", listener.scheme(), JET_INSTANCE.clone(), listener.port_or_known_default().unwrap_or(8080))) {
                                    association.add_candidate(candidate);
                                }
                            }

                            let body = association.gather_candidate();
                            *response.body_mut() = body.to_string().into();
                            *response.status_mut() = StatusCode::OK;
                        }
                    }
                }
            } else {
                *response.status_mut() = StatusCode::BAD_REQUEST;
            }

            _ => {
                *response.status_mut() = StatusCode::BAD_REQUEST;
            }
        }

        Box::new(futures::future::ok::<Response<Body>, hyper::Error>(response))
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

fn uuid_from_path(path: &str) -> Option<Uuid> {
    if let Some(raw_uuid) = path.split("/").skip(3).next() {
        Uuid::parse_str(raw_uuid).ok()
    } else {
        None
    }
}

pub struct WsClient {
    routing_url: Url,
    config: Config,
    _executor_handle: TaskExecutor,
}

impl WsClient {
    pub fn new(routing_url: Url, config: Config, executor_handle: TaskExecutor) -> Self {
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