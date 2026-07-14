//! Router and connection serving helpers.

use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

/// Serve one HTTP connection (a named-pipe instance or a TCP stream) using the router.
pub async fn serve_connection<S>(stream: S, router: axum::Router)
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

    if let Err(error) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .http1()
        .keep_alive(false)
        .serve_connection_with_upgrades(socket, hyper_service)
        .await
    {
        warn!(error = %error, "Connection error");
    }
}
