use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::{Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::{RequestPartsExt as _, TypedHeader};

use crate::config::Conf;
use crate::http::HttpError;
use crate::token::{AccessTokenClaims, CurrentJrl, TokenCache, TokenValidator};
use crate::DgwState;

const AUTH_EXCEPTIONS: &[(&Method, &str)] = &[
    (&Method::GET, "/health"),
    (&Method::GET, "/jet/health"),
    (&Method::GET, "/jet/diagnostics/clock"),
    (&Method::GET, "/jet/rdp"),
];

pub async fn auth_middleware<B>(
    State(DgwState {
        conf_handle,
        token_cache,
        jrl,
        ..
    }): State<DgwState>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, HttpError>
where
    B: Send,
{
    #[derive(Deserialize)]
    struct TokenQueryParam<'a> {
        token: &'a str,
    }

    let method = request.method();
    let uri_path = request.uri().path();

    if AUTH_EXCEPTIONS.contains(&(method, uri_path)) {
        trace!("unauthenticated route");
        Ok(next.run(request).await)
    } else {
        let (mut parts, body) = request.into_parts();

        let extract_header = parts.extract::<TypedHeader<Authorization<Bearer>>>().await;

        let token = match &extract_header {
            Ok(auth) => auth.token(),
            Err(_) => {
                let query = parts.uri.query().unwrap_or_default();

                let Ok(query) = serde_urlencoded::from_str::<TokenQueryParam>(query) else {
                    return Err(HttpError::unauthorized().msg("both authorization header and token query param invalid or missing"));
                };

                query.token
            }
        };

        let conf = conf_handle.get_conf();

        let access_token_claims =
            authenticate(source_addr, token, &conf, &token_cache, &jrl).map_err(HttpError::unauthorized().err())?;

        let mut request = Request::from_parts(parts, body);

        request.extensions_mut().insert(access_token_claims);

        Ok(next.run(request).await)
    }
}

pub fn authenticate(
    source_addr: SocketAddr,
    token: &str,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> Result<AccessTokenClaims, crate::token::TokenError> {
    if conf.debug.dump_tokens {
        debug!(token, "**DEBUG OPTION**");
    }

    let delegation_key = conf.delegation_private_key.as_ref();

    if conf.debug.disable_token_validation {
        #[allow(deprecated)]
        crate::token::unsafe_debug::dangerous_validate_token(token, delegation_key)
    } else {
        TokenValidator::builder()
            .source_ip(source_addr.ip())
            .provisioner_key(&conf.provisioner_public_key)
            .delegation_key(delegation_key)
            .token_cache(token_cache)
            .revocation_list(jrl)
            .gw_id(conf.id)
            .subkey(conf.sub_provisioner_public_key.as_ref())
            .build()
            .validate(token)
    }
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
