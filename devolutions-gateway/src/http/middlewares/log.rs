use saphir::error::SaphirError;
use saphir::http_context::HttpContext;
use saphir::middleware::MiddlewareChain;
use saphir::prelude::*;
use std::time::Instant;
use tracing::Instrument as _;

pub struct LogMiddleware;

#[middleware]
impl LogMiddleware {
    async fn next(&self, mut ctx: HttpContext, chain: &dyn MiddlewareChain) -> Result<HttpContext, SaphirError> {
        let request = ctx.state.request_unchecked();
        let operation_id = ctx.operation_id;
        let uri = request.uri().path().to_owned();
        let method = request.method().to_owned();
        let is_health_check = uri.ends_with("health");

        // Trim token from KdcProxy endpoint uri
        let uri = if uri.starts_with("KdcProxy") {
            String::from("/KdcProxy")
        } else if uri.starts_with("/jet/KdcProxy") {
            String::from("/jet/KdcProxy")
        } else {
            uri
        };

        async move {
            let start_time = Instant::now();

            debug!("received request");

            ctx = chain.next(ctx).await?;

            let status = ctx.state.response_unchecked().status();

            if is_health_check {
                debug!(duration = ?start_time.elapsed(), %status);
            } else {
                info!(duration = ?start_time.elapsed(), %status);
            }

            Ok(ctx)
        }
        .instrument(info_span!("request", request_id = %operation_id, %method, %uri))
        .await
    }
}
