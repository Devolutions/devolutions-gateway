use saphir::error::SaphirError;
use saphir::http_context::HttpContext;
use saphir::middleware::MiddlewareChain;
use saphir::prelude::*;
use slog::{o, slog_debug, slog_info};
use slog_scope_futures::future03::FutureExt as _;
use std::time::Instant;

pub struct LogMiddleware;

#[middleware]
impl LogMiddleware {
    async fn next(&self, mut ctx: HttpContext, chain: &dyn MiddlewareChain) -> Result<HttpContext, SaphirError> {
        let request = ctx.state.request_unchecked();
        let start_time = Instant::now();
        let operation_id = ctx.operation_id.to_string();

        let uri = request.uri().path().to_owned();
        let method = request.method().to_owned();

        let logger = slog_scope::logger().new(o!("request_id" => operation_id, "uri" => uri.clone()));

        slog_debug!(logger, "Request received: {} {}", method, uri);

        ctx = chain.next(ctx).with_logger(logger.clone()).await?;

        let status = ctx.state.response_unchecked().status();
        let duration = format!("Duration_ms={}", start_time.elapsed().as_millis());

        if uri.ends_with("health") {
            slog_debug!(logger, "{} {} {} ({})", method, uri, status, duration);
        } else {
            slog_info!(logger, "{} {} {} ({})", method, uri, status, duration);
        }

        Ok(ctx)
    }
}
