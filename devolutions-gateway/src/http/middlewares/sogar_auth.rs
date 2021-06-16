use crate::{
    config::{Config, SogarPermission, SogarUser},
    http::middlewares::auth::{parse_auth_header, AuthHeaderType},
};
use picky::jose::jwt::{JwtSig, JwtValidator};
use saphir::{http, http_context::State, prelude::*, response::Builder as ResponseBuilder};
use slog_scope::error;
use sogar_core::registry::{
    BLOB_DOWNLOAD_ENDPOINT, BLOB_EXIST_ENDPOINT, BLOB_GET_LOCATION_ENDPOINT, BLOB_UPLOAD_ENDPOINT,
    MANIFEST_DOWNLOAD_ENDPOINT, MANIFEST_EXIST_ENDPOINT, MANIFEST_UPLOAD_ENDPOINT,
};
use std::sync::Arc;

pub struct SogarAuthMiddleware {
    config: Arc<Config>,
}

impl SogarAuthMiddleware {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl Middleware for SogarAuthMiddleware {
    fn next(
        &'static self,
        ctx: HttpContext,
        chain: &'static dyn MiddlewareChain,
    ) -> BoxFuture<'static, Result<HttpContext, SaphirError>> {
        auth_middleware(ctx, chain, self.config.clone()).boxed()
    }
}

async fn auth_middleware(
    ctx: HttpContext,
    chain: &'static dyn MiddlewareChain,
    config: Arc<Config>,
) -> Result<HttpContext, SaphirError> {
    if let Some(metadata) = ctx.metadata.name {
        let auth_header = ctx
            .state
            .request()
            .expect("Invalid middleware state")
            .headers()
            .get(http::header::AUTHORIZATION);

        let auth_str = match auth_header.and_then(|header| header.to_str().ok()) {
            None => {
                error!("Authorization header is missing or wrong format.");
                //to be able to play video in the browser
                return if metadata == BLOB_DOWNLOAD_ENDPOINT || metadata == MANIFEST_DOWNLOAD_ENDPOINT {
                    chain.next(ctx).await
                } else {
                    let response = ResponseBuilder::new().status(StatusCode::UNAUTHORIZED).build()?;

                    let mut ctx = ctx.clone_with_empty_state();
                    ctx.state = State::After(Box::new(response));
                    Ok(ctx)
                };
            }
            Some(auth_str) => auth_str,
        };

        let private_key = config.delegation_private_key.clone();
        if let (Some((AuthHeaderType::Bearer, token)), Some(private_key)) = (parse_auth_header(auth_str), private_key) {
            let public_key = private_key.to_public_key();
            match JwtSig::<SogarUser>::decode(token.as_str(), &public_key, &JwtValidator::no_check()) {
                Ok(user) => {
                    if let Some(permission) = user.claims.permission {
                        if metadata == BLOB_EXIST_ENDPOINT || metadata == MANIFEST_EXIST_ENDPOINT {
                            return chain.next(ctx).await;
                        }

                        match permission {
                            SogarPermission::Push => {
                                if metadata == BLOB_GET_LOCATION_ENDPOINT
                                    || metadata == BLOB_UPLOAD_ENDPOINT
                                    || metadata == MANIFEST_UPLOAD_ENDPOINT
                                {
                                    return chain.next(ctx).await;
                                }
                            }
                            SogarPermission::Pull => {
                                if metadata == BLOB_DOWNLOAD_ENDPOINT || metadata == MANIFEST_DOWNLOAD_ENDPOINT {
                                    return chain.next(ctx).await;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to decode jwt token! Error is: {}", e);
                }
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
