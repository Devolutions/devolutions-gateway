use crate::config::Config;
use crate::token::JetAccessTokenClaims;
use chrono::Utc;
use futures::future::{BoxFuture, FutureExt};
use picky::jose::jwt::JwtDate;
use saphir::error::SaphirError;
use saphir::http::{self, StatusCode};
use saphir::http_context::{HttpContext, State};
use saphir::middleware::{Middleware, MiddlewareChain};
use saphir::response::Builder as ResponseBuilder;
use slog_scope::{error, warn};
use std::sync::Arc;

const GATEWAY_AUTHORIZATION_HDR_NAME: &str = "Gateway-Authorization";

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
    mut ctx: HttpContext,
    chain: &'static dyn MiddlewareChain,
) -> Result<HttpContext, SaphirError> {
    let request = ctx.state.request_unchecked_mut();
    let headers = request.headers_mut();

    // Authorization header used for authentication is removed from the request so that we don't
    // forward it mistakenly (currently only a concern for the HTTP bridge).
    let auth_value = headers
        .remove(GATEWAY_AUTHORIZATION_HDR_NAME)
        .or_else(|| headers.remove(http::header::AUTHORIZATION));

    // TODO: we could probably use an Error implementing the right saphir trait and `?` on error
    // (IRCC we did something similar in Bastion).
    let auth_value = match auth_value {
        Some(value) => value,
        None => {
            error!("Authorization header missing");
            let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;
            let mut ctx = ctx.clone_with_empty_state();
            ctx.state = State::After(Box::new(response));
            return Ok(ctx);
        }
    };

    let auth_value = match auth_value.to_str() {
        Ok(v) => v,
        Err(_) => {
            error!("non-ASCII value in Authorization header");
            let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;
            let mut ctx = ctx.clone_with_empty_state();
            ctx.state = State::After(Box::new(response));
            return Ok(ctx);
        }
    };

    if let Some((AuthHeaderType::Bearer, token)) = parse_auth_header(auth_value) {
        match validate_bearer_token(&config, &token) {
            Ok(jet_token) => {
                request.extensions_mut().insert(jet_token);
                return chain.next(ctx).await;
            }
            Err(e) => {
                error!("Invalid authorization token: {}", e);
            }
        }
    } else {
        error!("Invalid authorization type");
    }

    // At this point, authentication failed…

    let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;
    let mut ctx = ctx.clone_with_empty_state();
    ctx.state = State::After(Box::new(response));
    Ok(ctx)
}

#[derive(PartialEq)]
pub enum AuthHeaderType {
    Bearer,
    Signature,
}

pub fn parse_auth_header(auth_header: &str) -> Option<(AuthHeaderType, &str)> {
    let auth_vec = auth_header.trim().split(' ').collect::<Vec<&str>>();

    if auth_vec.len() >= 2 {
        match auth_vec[0].to_lowercase().as_ref() {
            "bearer" => Some((AuthHeaderType::Bearer, auth_vec[1])),
            "signature" => Some((AuthHeaderType::Signature, auth_header)),
            unexpected => {
                warn!("unexpected auth method: {}", unexpected);
                None
            }
        }
    } else {
        warn!("invalid auth header: {}", auth_header);
        None
    }
}

fn validate_bearer_token(config: &Config, token: &str) -> Result<JetAccessTokenClaims, String> {
    use picky::jose::jwt::{JwtSig, JwtValidator};

    let key = config
        .provisioner_public_key
        .as_ref()
        .ok_or_else(|| "Provisioner public key is missing".to_string())?;

    let now = JwtDate::new_with_leeway(Utc::now().timestamp(), 10 * 60);
    let validator = JwtValidator::strict(&now);

    let jwt = JwtSig::<JetAccessTokenClaims>::decode(&token, key, &validator)
        .map_err(|e| format!("Invalid jet token: {:?}", e))?;

    Ok(jwt.claims)
}
