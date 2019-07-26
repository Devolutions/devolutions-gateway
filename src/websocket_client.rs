use crate::jet_client::JetAssociationsMap;
use hyper::{Request, Body, Response, Method, StatusCode, header, Version, http};
use futures::Future;
use tokio::runtime::TaskExecutor;
use uuid::Uuid;
use crate::transport::JetTransport;
use crate::transport::ws::WsTransport;
use std::net::SocketAddr;
use crate::config::Config;
use crate::Proxy;
use log::error;

#[derive(Clone)]
pub struct WebsocketService {
    pub jet_associations: JetAssociationsMap,
    pub executor_handle: TaskExecutor,
    pub config: Config,
}

impl WebsocketService {
    pub fn handle(&mut self, req: Request<Body>, client_addr: Option<SocketAddr>) -> Box<dyn Future<Item=Response<Body>, Error=hyper::Error> + Send> {
        let mut response = Response::new(Body::empty());

        match req.method() {
            &Method::GET => if req.uri().path().starts_with("/jet/accept") {
                if let Some(header) = req.headers().get("upgrade") {
                    if header.to_str().unwrap_or("not a websocket") == "websocket" {
                        if let Some(uuid) = uuid_from_path(req.uri().path()) {
                            let res = process_req(&req);

                            let jet_associations_clone = self.jet_associations.clone();
                            let fut = req.into_body().on_upgrade().map(move |upgraded| {
                                if let Ok(mut jet_assc) = jet_associations_clone.try_lock() {
                                    jet_assc.insert(uuid, JetTransport::Ws(WsTransport::new_http(upgraded, client_addr)));
                                }
                            }).map_err(|e| error!("upgrade error: {}", e));

                            self.executor_handle.spawn(fut);

                            return Box::new(futures::future::ok::<Response<Body>, hyper::Error>(res));
                        }
                    }
                }
                *response.status_mut() = StatusCode::FORBIDDEN;
            } else if req.uri().path().starts_with("/jet/connect") {
                if let Some(header) = req.headers().get("upgrade") {
                    if header.to_str().unwrap_or("not a websocket") == "websocket" {
                        if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                            if let Some(uuid) = uuid_from_path(req.uri().path()) {
                                if let Some(assc) = jet_associations.remove(&uuid) {
                                    let res = process_req(&req);

                                    let self_clone = self.clone();
                                    let fut = req.into_body().on_upgrade().map(move |upgraded| {
                                        let proxy = Proxy::new(self_clone.config.clone()).build(WsTransport::new_http(upgraded, client_addr), assc).map_err(|_| ());
                                        self_clone.executor_handle.spawn(proxy);
                                    }).map_err(|e| error!("upgrade error: {}", e));

                                    self.executor_handle.spawn(fut);

                                    return Box::new(futures::future::ok::<Response<Body>, hyper::Error>(res));
                                }
                            }
                        }
                    }
                }
                *response.status_mut() = StatusCode::BAD_REQUEST;
            } else if req.uri().path().starts_with("/jet/create") {
                *response.body_mut() = Body::from(Uuid::new_v4().to_string())
            } else {
                *response.status_mut() = StatusCode::BAD_REQUEST;
            },

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
    let is_websocket_version_13 = req.headers()
        .get(header::SEC_WEBSOCKET_VERSION)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v == "13");
    if !is_http_11 || !is_upgrade || !is_websocket_upgrade || !is_websocket_version_13 {
        return Response::builder()
            .status(http::StatusCode::UPGRADE_REQUIRED)
            .header(http::header::SEC_WEBSOCKET_VERSION, "13")
            .body("Expected Upgrade to WebSocket version 13".into())
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


fn uuid_from_path(path: &str) -> Option<Uuid> {
    let path_split: Vec<&str> = path.split("/").skip(3).collect();
    if let Some(raw_uuid) = path_split.get(0) {
        if let Ok(uuid) = Uuid::parse_str(raw_uuid) {
            Some(uuid)
        } else {
            None
        }
    } else {
        None
    }
}