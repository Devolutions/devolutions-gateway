use saphir::error::SaphirError;
use saphir::http_context::HttpContext;
use saphir::middleware::MiddlewareChain;
use saphir::prelude::*;

pub struct CorsMiddleware;

#[middleware]
impl CorsMiddleware {
    async fn next(&self, mut ctx: HttpContext, chain: &dyn MiddlewareChain) -> Result<HttpContext, SaphirError> {
        let request = ctx.state.request_unchecked();

        if *request.method() == Method::OPTIONS {
            let cors_rsp = match Builder::new()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
                .header("Access-Control-Allow-Headers", "Authorization")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Max-Age", "7200")
                .status(StatusCode::NO_CONTENT)
                .build()
            {
                Err(e) => {
                    error!("Error building CORS OPTIONS request response: {:?}", e);
                    return Err(e);
                }
                Ok(res) => res,
            };

            ctx.after(cors_rsp);

            Ok(ctx)
        } else {
            let mut ctx = chain.next(ctx).await?;

            ctx.state
                .response_unchecked_mut()
                .headers_mut()
                .insert("Access-Control-Allow-Origin", "*".parse().unwrap());

            Ok(ctx)
        }
    }
}
