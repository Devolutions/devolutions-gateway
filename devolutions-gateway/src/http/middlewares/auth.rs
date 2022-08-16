use crate::config::Config;
use crate::http::HttpErrorStatus;
use crate::token::{AccessTokenClaims, CurrentJrl, RawToken, TokenCache, TokenValidator};
use futures::future::{BoxFuture, FutureExt};
use saphir::error::SaphirError;
use saphir::http::{self, StatusCode};
use saphir::http_context::{HttpContext, State};
use saphir::middleware::{Middleware, MiddlewareChain};
use saphir::responder::Responder;
use saphir::response::Builder as ResponseBuilder;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

const GATEWAY_AUTHORIZATION_HDR_NAME: &str = "Gateway-Authorization";

pub struct AuthMiddleware {
    config: Arc<Config>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
}

impl AuthMiddleware {
    pub fn new(config: Arc<Config>, token_cache: Arc<TokenCache>, jrl: Arc<CurrentJrl>) -> Self {
        Self {
            config,
            token_cache,
            jrl,
        }
    }
}

impl Middleware for AuthMiddleware {
    fn next(
        &'static self,
        ctx: HttpContext,
        chain: &'static dyn MiddlewareChain,
    ) -> BoxFuture<'static, Result<HttpContext, SaphirError>> {
        auth_middleware(
            self.config.clone(),
            self.token_cache.clone(),
            self.jrl.clone(),
            ctx,
            chain,
        )
        .boxed()
    }
}

async fn auth_middleware(
    config: Arc<Config>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
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

    let token = match &auth_value {
        // Extract token from header
        Some(auth_value) => match auth_value.to_str() {
            Ok(auth_value) => {
                if let Some((AuthHeaderType::Bearer, token)) = parse_auth_header(auth_value) {
                    token
                } else {
                    error!("Invalid authorization type");
                    let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;
                    let mut ctx = ctx.clone_with_empty_state();
                    ctx.state = State::After(Box::new(response));
                    return Ok(ctx);
                }
            }
            Err(_) => {
                error!("non-ASCII value in Authorization header");
                let response = ResponseBuilder::new().status(StatusCode::BAD_REQUEST).build()?;
                let mut ctx = ctx.clone_with_empty_state();
                ctx.state = State::After(Box::new(response));
                return Ok(ctx);
            }
        },

        // Try to extract token from query params
        None => {
            if let Some(token) = request.uri().query().and_then(|q| {
                q.split('&')
                    .filter_map(|segment| segment.split_once('='))
                    .find_map(|(key, val)| key.eq("token").then(|| val))
            }) {
                token
            } else {
                error!("Authorization header missing");
                let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;
                let mut ctx = ctx.clone_with_empty_state();
                ctx.state = State::After(Box::new(response));
                return Ok(ctx);
            }
        }
    };

    let source_addr = request
        .peer_addr()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "peer address missing"))?;

    match authenticate(*source_addr, token, &config, &token_cache, &jrl) {
        Ok(jet_token) => {
            let raw_token = RawToken(token.to_owned());
            let extensions = request.extensions_mut();
            extensions.insert(jet_token);
            extensions.insert(raw_token);
            chain.next(ctx).await
        }
        Err(e) => {
            let response = e.respond_with_builder(ResponseBuilder::new(), &ctx).build()?;
            let mut ctx = ctx.clone_with_empty_state();
            ctx.state = State::After(Box::new(response));
            Ok(ctx)
        }
    }
}

pub fn authenticate(
    source_addr: SocketAddr,
    token: &str,
    config: &Config,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> Result<AccessTokenClaims, HttpErrorStatus> {
    if config.debug.dump_tokens {
        debug!(token, "**DEBUG OPTION**");
    }

    let delegation_key = config.delegation_private_key.as_ref();

    if config.debug.disable_token_validation {
        #[allow(deprecated)]
        crate::token::unsafe_debug::dangerous_validate_token(token, delegation_key)
    } else {
        TokenValidator::builder()
            .source_ip(source_addr.ip())
            .provisioner_key(&config.provisioner_public_key)
            .delegation_key(delegation_key)
            .token_cache(token_cache)
            .revocation_list(jrl)
            .gw_id(config.id)
            .subkey(None)
            .build()
            .validate(token)
    }
    .map_err(HttpErrorStatus::unauthorized)
}

#[derive(PartialEq, Eq)]
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
