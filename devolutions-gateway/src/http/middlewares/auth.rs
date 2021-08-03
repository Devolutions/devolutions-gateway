use crate::config::Config;
use chrono::Utc;
use futures::future::{BoxFuture, FutureExt};
use jet_proto::token::JetAccessTokenClaims;
use picky::jose::jwt::JwtDate;
use saphir::error::SaphirError;
use saphir::http::{self, StatusCode};
use saphir::http_context::{HttpContext, State};
use saphir::middleware::{Middleware, MiddlewareChain};
use saphir::response::Builder as ResponseBuilder;
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
    mut ctx: HttpContext,
    chain: &'static dyn MiddlewareChain,
) -> Result<HttpContext, SaphirError> {
    let request = ctx.state.request_unchecked_mut();

    let auth_header = request.headers().get(http::header::AUTHORIZATION);

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

    let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;

    let mut ctx = ctx.clone_with_empty_state();
    ctx.state = State::After(Box::new(response));
    return Ok(ctx);
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
