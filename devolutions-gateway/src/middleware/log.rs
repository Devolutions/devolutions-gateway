use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument as _;

use crate::http::HttpError;

pub async fn log_middleware(request: Request<Body>, next: Next) -> Result<Response, HttpError> {
    let uri_path = request.uri().path();
    let method = request.method();

    let is_health_check = uri_path.ends_with("health") || uri_path.ends_with("heartbeat");

    // Trim token from KdcProxy endpoint uri
    let uri_path = if uri_path.starts_with("/KdcProxy") {
        "/KdcProxy"
    } else if uri_path.starts_with("/jet/KdcProxy") {
        "/jet/KdcProxy"
    } else {
        uri_path
    };

    let span = if uri_path.len() > 512 {
        // Truncate long URI to keep log readable and prevent fast growing log file
        info_span!("request", %method, path = %&uri_path[..512])
    } else {
        info_span!("request", %method, path = %uri_path)
    };

    async move {
        let start_time = Instant::now();

        debug!("Received request");

        let response = next.run(request).await;

        let status = response.status();

        if is_health_check {
            debug!(duration = ?start_time.elapsed(), %status);
        } else {
            info!(duration = ?start_time.elapsed(), %status);
        }

        Ok(response)
    }
    .instrument(span)
    .await
}
