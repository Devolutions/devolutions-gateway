use std::net::SocketAddr;

use axum::RequestPartsExt as _;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;

use crate::config::Conf;
use crate::http::HttpError;
use crate::recording::ActiveRecordings;
use crate::session::DisconnectedInfo;
use crate::token::{AccessTokenClaims, CurrentJrl, TokenCache, TokenValidator};
use crate::{DgwState, SYSTEM_LOGGER};

struct AuthException {
    method: Method,
    path: &'static str,
    exact_match: bool,
}

const AUTH_EXCEPTIONS: &[AuthException] = &[
    // -- Non sensitive information required for diagnostics -- //
    AuthException {
        method: Method::GET,
        path: "/health",
        exact_match: true,
    },
    AuthException {
        method: Method::GET,
        path: "/jet/health",
        exact_match: true,
    },
    AuthException {
        method: Method::GET,
        path: "/jet/diagnostics/clock",
        exact_match: true,
    },
    // -- Custom authentication via RDCleanPath PDU -- //
    AuthException {
        method: Method::GET,
        path: "/jet/rdp",
        exact_match: true,
    },
    // -- KDC proxy -- //
    AuthException {
        method: Method::POST,
        path: "/KdcProxy",
        exact_match: false,
    },
    AuthException {
        method: Method::POST,
        path: "/jet/KdcProxy",
        exact_match: false,
    },
    // -- Standalone web application -- //
    AuthException {
        method: Method::GET,
        path: "/jet/webapp/client",
        exact_match: false,
    },
    AuthException {
        method: Method::POST,
        path: "/jet/webapp/app-token",
        exact_match: true,
    },
    AuthException {
        method: Method::GET,
        path: "/",
        exact_match: true,
    },
    AuthException {
        method: Method::GET,
        path: "/jet/webapp",
        exact_match: true,
    },
    // -- Recording Player -- //
    AuthException {
        method: Method::GET,
        path: "/jet/jrec/play",
        exact_match: false,
    },
];

pub async fn auth_middleware(
    State(DgwState {
        conf_handle,
        token_cache,
        jrl,
        recordings,
        sessions,
        ..
    }): State<DgwState>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, HttpError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TokenQueryParam<'a> {
        token: &'a str,
    }

    let method = request.method();
    let uri_path = request.uri().path();

    let skip_authentication = AUTH_EXCEPTIONS.iter().any(|exception| {
        if method != exception.method {
            return false;
        }

        if exception.exact_match {
            uri_path == exception.path
        } else {
            uri_path.starts_with(exception.path)
        }
    });

    if skip_authentication {
        trace!("unauthenticated route");
        Ok(next.run(request).await)
    } else {
        let (mut parts, body) = request.into_parts();

        let extract_header = parts.extract::<TypedHeader<Authorization<Bearer>>>().await;

        let token = match &extract_header {
            Ok(auth) => auth.token(),
            Err(_) => {
                let query = parts.uri.query().unwrap_or_default();

                let Ok(query) = serde_urlencoded::from_str::<TokenQueryParam<'_>>(query) else {
                    return Err(HttpError::unauthorized()
                        .msg("both authorization header and token query param invalid or missing"));
                };

                query.token
            }
        };

        let disconnected_info = if let Ok(session_id) = crate::token::extract_session_id(token) {
            sessions.get_disconnected_info(session_id).await.ok().flatten()
        } else {
            None
        };

        let conf = conf_handle.get_conf();

        let result = authenticate(
            source_addr,
            token,
            &conf,
            &token_cache,
            &jrl,
            &recordings.active_recordings,
            disconnected_info,
        );

        let access_token_claims = match result {
            Ok(access_token_claims) => access_token_claims,
            Err(error) => {
                match &error {
                    crate::token::TokenError::SignatureVerification { source, key } => {
                        let _ = SYSTEM_LOGGER.emit(
                            sysevent_codes::jwt_rejected("bad_signature", format!("{source:#}")).field("key", key),
                        );
                    }
                    crate::token::TokenError::UnexpectedReplay { reason } => {
                        let _ = SYSTEM_LOGGER.emit(sysevent_codes::jwt_rejected("unexpected_replay", reason));
                    }
                    _ => {}
                }

                return Err(HttpError::unauthorized().err()(error));
            }
        };

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
    active_recordings: &ActiveRecordings,
    disconnected_info: Option<DisconnectedInfo>,
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
            .active_recordings(active_recordings)
            .gw_id(conf.id)
            .subkey(conf.sub_provisioner_public_key.as_ref())
            .disconnected_info(disconnected_info)
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
