//! Router and connection serving helpers.

use std::time::Duration;

use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

/// How long a client may take to send a complete request header before the connection is closed.
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve one HTTP connection (a named-pipe instance or a TCP stream) using the router.
pub async fn serve_connection<S>(stream: S, router: axum::Router)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_connection_with_header_timeout(stream, router, REQUEST_HEADER_TIMEOUT).await;
}

/// Serve one HTTP/1 connection, closing it when the request header is not received within `header_timeout`.
pub(crate) async fn serve_connection_with_header_timeout<S>(stream: S, router: axum::Router, header_timeout: Duration)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tower_service::Service as _;

    let socket = TokioIo::new(stream);

    let mut make_service = router.into_make_service();
    let tower_service = match make_service.call(()).await {
        Ok(service) => service,
        Err(infallible) => match infallible {},
    };
    let hyper_service = hyper_util::service::TowerToHyperService::new(tower_service);

    if let Err(error) = hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .serve_connection(socket, hyper_service)
        .with_upgrades()
        .await
    {
        warn!(error = %error, "Connection error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connections_without_a_request_header_are_closed_after_the_timeout() {
        let (server, _client) = tokio::io::duplex(1024);

        tokio::time::timeout(
            Duration::from_secs(5),
            serve_connection_with_header_timeout(server, axum::Router::new(), Duration::from_millis(100)),
        )
        .await
        .expect("an idle connection is closed after the header timeout");
    }
}
