//! HTTPS server: one port, ALPN `h2` and `http/1.1`, REST (axum) and gRPC (tonic)
//! dispatched on the path after stripping the path prefix (CONTRACT.md §7.2, §11).

use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use agent_identity_channel_proto::agent_channel_server::AgentChannelServer;
use axum::body::Bytes;
use axum::response::IntoResponse as _;
use axum::{Json, Router, http};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt as _};

use crate::api_agent::{DROP_HEADER, INJECTED_HEADER};
use crate::app::App;
use crate::channel::ChannelService;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;
type OutResponse = http::Response<OutBody>;

/// Service error used to abort a connection without a response
/// (`faults.drop_next_response`, §11).
#[derive(Debug)]
pub struct ConnectionAborted;

impl fmt::Display for ConnectionAborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection aborted by mock fault")
    }
}

impl std::error::Error for ConnectionAborted {}

/// Top-level dispatcher: strips the path prefix, routes the gRPC path to the tonic
/// service and everything else to the axum router.
#[derive(Clone)]
pub struct Dispatcher {
    prefix: Arc<String>,
    app: Arc<App>,
    grpc: AgentChannelServer<ChannelService>,
    rest: Router,
}

impl Dispatcher {
    pub fn new(app: Arc<App>) -> Self {
        let app_for_404 = Arc::clone(&app);
        let rest = Router::new()
            .merge(crate::api_agent::router(Arc::clone(&app)))
            .merge(crate::api_admin::router(Arc::clone(&app)))
            .merge(crate::api_mock::router(Arc::clone(&app)))
            .fallback(move || {
                let app = Arc::clone(&app_for_404);
                async move {
                    // 404s inside the prefix carry the §5.4 body shape.
                    let body = json!({
                        "error": "not_found",
                        "message": "unknown path",
                        "server_time": crate::app::rfc3339(app.now()),
                    });
                    (http::StatusCode::NOT_FOUND, Json(body)).into_response()
                }
            });
        Self {
            prefix: Arc::new(app.prefix.clone()),
            app: Arc::clone(&app),
            grpc: AgentChannelServer::new(ChannelService { app }),
            rest,
        }
    }

    async fn handle(self, request: http::Request<Incoming>) -> Result<OutResponse, ConnectionAborted> {
        let path = request.uri().path().to_owned();
        let stripped = match strip_prefix(&self.prefix, &path) {
            Some(stripped) => stripped.to_owned(),
            None => return Ok(outside_prefix_response()),
        };

        // Rewrite the URI to the stripped path (query preserved).
        let (mut parts, body) = request.into_parts();
        let path_and_query = match parts.uri.query() {
            Some(query) => format!("{stripped}?{query}"),
            None => stripped.clone(),
        };
        parts.uri = http::Uri::builder()
            .path_and_query(path_and_query)
            .build()
            .map_err(|_| ConnectionAborted)?;
        let request = http::Request::from_parts(parts, body);

        let grpc_path = format!("/{}/Connect", agent_identity_channel_proto::SERVICE_NAME);
        if stripped == *grpc_path {
            let response = self
                .grpc
                .oneshot(request)
                .await
                .unwrap_or_else(|never: Infallible| match never {});
            return Ok(response.map(|body| body.map_err(|e| -> BoxError { Box::new(e) }).boxed_unsync()));
        }

        let mut response = self
            .rest
            .oneshot(request)
            .await
            .unwrap_or_else(|never: Infallible| match never {});
        if response.headers_mut().remove(DROP_HEADER).is_some() {
            // The fault fired: commit happened; abort without responding (§11).
            return Err(ConnectionAborted);
        }
        let injected = response.headers_mut().remove(INJECTED_HEADER).is_some();
        if !injected
            && (stripped == "/api/agent-identity/v1" || stripped.starts_with("/api/agent-identity/v1/"))
            && matches!(response.status().as_u16(), 400 | 404 | 405 | 413)
        {
            let status = response.status().as_u16();
            let message = match status {
                404 => "unknown agent-identity route",
                405 => "method not allowed",
                413 => "agent-identity request body is too large",
                _ => "invalid agent-identity request",
            };
            response = crate::api_agent::agent_error(&self.app, status, "invalid_request", message);
        }
        Ok(response.map(|body| body.map_err(|e| -> BoxError { Box::new(e) }).boxed_unsync()))
    }
}

impl Service<http::Request<Incoming>> for Dispatcher {
    type Response = OutResponse;
    type Error = ConnectionAborted;
    type Future = Pin<Box<dyn Future<Output = Result<OutResponse, ConnectionAborted>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(this.handle(request))
    }
}

/// Strips `prefix` from `path`: `/mock/api/...` → `/api/...`; `/mock` → `/`.
/// Returns `None` when the path is outside the prefix (§11: 404).
fn strip_prefix<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if path == prefix {
        return Some("/");
    }
    path.strip_prefix(prefix).filter(|rest| rest.starts_with('/'))
}

fn outside_prefix_response() -> OutResponse {
    map_response(http::StatusCode::NOT_FOUND.into_response())
}

fn map_response<B>(response: http::Response<B>) -> OutResponse
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    response.map(|body| body.map_err(Into::into).boxed_unsync())
}

/// Accept loop: TLS (ALPN h2 + http/1.1), then hyper's auto protocol detection.
pub async fn serve(listener: TcpListener, acceptor: TlsAcceptor, dispatcher: Dispatcher) -> anyhow::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                tracing::debug!("TLS handshake failed");
                return;
            };
            let io = TokioIo::new(tls);
            let service = hyper_util::service::TowerToHyperService::new(dispatcher);
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if let Err(error) = builder.serve_connection(io, service).await {
                tracing::debug!(%error, "Connection ended with an error");
            }
        });
    }
}
