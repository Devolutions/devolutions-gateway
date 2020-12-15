use crate::config::Config;
use futures::future::{BoxFuture, FutureExt};
use saphir::{
    error::SaphirError,
    http::{self, StatusCode},
    http_context::{HttpContext, State},
    middleware::{Middleware, MiddlewareChain},
    response::Builder as ResponseBuilder,
};
use slog_scope::error;
use std::sync::Arc;

pub struct AuthMiddleware {
    config: Arc<Config>,
}

impl AuthMiddleware {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl Middleware for AuthMiddleware {
    fn next(
        &'static self,
        ctx: HttpContext,
        chain: &'static dyn MiddlewareChain,
    ) -> BoxFuture<'static, Result<HttpContext, SaphirError>> {
        auth_middleware(self.config.clone(), ctx, chain).boxed()
    }
}

async fn auth_middleware(
    config: Arc<Config>,
    ctx: HttpContext,
    chain: &'static dyn MiddlewareChain,
) -> Result<HttpContext, SaphirError> {
    if let Some(api_key) = &config.api_key {
        let auth_header = ctx
            .state
            .request()
            .expect("Invalid middleware state")
            .headers()
            .get(http::header::AUTHORIZATION);

        let auth_header = match auth_header {
            Some(header) => header.clone(),
            None => {
                error!("Authorization header not present in request.");
                let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;

                let mut ctx = ctx.clone_with_empty_state();
                ctx.state = State::After(Box::new(response));
                return Ok(ctx);
            }
        };

        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => {
                error!("Authorization header wrong format");
                let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;

                let mut ctx = ctx.clone_with_empty_state();
                ctx.state = State::After(Box::new(response));
                return Ok(ctx);
            }
        };

        if let Some((AuthHeaderType::Bearer, token)) = parse_auth_header(auth_str) {
            // API_KEY
            if api_key == &token {
                return chain.next(ctx).await;
            }
        }

        error!("Invalid authorization type");
        let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;

        let mut ctx = ctx.clone_with_empty_state();
        ctx.state = State::After(Box::new(response));
        return Ok(ctx);
    }

    Ok(chain.next(ctx).await?)
}

#[derive(PartialEq)]
pub enum AuthHeaderType {
    Basic,
    Bearer,
    Signature,
}

pub fn parse_auth_header(auth_header: &str) -> Option<(AuthHeaderType, String)> {
    let auth_vec = auth_header.trim().split(' ').collect::<Vec<&str>>();

    if auth_vec.len() == 2 {
        return match auth_vec[0].to_lowercase().as_ref() {
            "basic" => Some((AuthHeaderType::Basic, auth_vec[1].to_string())),
            "bearer" => Some((AuthHeaderType::Bearer, auth_vec[1].to_string())),
            "signature" => Some((AuthHeaderType::Signature, auth_vec[1].to_string())),
            _ => None,
        };
    }

    None
}
