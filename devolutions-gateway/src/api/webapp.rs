use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::extract::{self, ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::{http, response, Json, Router};
use axum_extra::headers::{self, HeaderMapExt as _};
use axum_extra::TypedHeader;
use picky::key::PrivateKey;
use tap::prelude::*;
use tower_http::services::ServeFile;
use uuid::Uuid;

use crate::config::{WebAppAuth, WebAppConf, WebAppUser};
use crate::extract::WebAppToken;
use crate::http::HttpError;
use crate::target_addr::TargetAddr;
use crate::token::ApplicationProtocol;
use crate::DgwState;

macro_rules! extract_conf {
    ($conf:expr) => {{
        $conf
            .webapp_conf_if_enabled()
            .ok_or_else(|| crate::http::HttpError::internal().msg("standalone web application not enabled"))?
    }};
}
use extract_conf as ensure_enabled;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    if state.conf_handle.get_conf().webapp_is_enabled() {
        Router::new()
            .route("/client", get(get_client))
            .route("/client/*path", get(get_client))
            .route("/app-token", post(sign_app_token))
            .route("/session-token", post(sign_session_token))
    } else {
        Router::new()
    }
    .with_state(state)
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum AppTokenContentType {
    WebApp,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AppTokenSignRequest {
    /// The content type for the web app token.
    content_type: AppTokenContentType,
    /// The username used to request the app token.
    subject: String,
    /// The validity duration in seconds for the app token.
    ///
    /// This value cannot exceed the configured maximum lifetime.
    /// If no value is provided, the configured maximum lifetime will be granted.
    lifetime: Option<u64>,
}

/// Requests a web application token using the configured authorization method
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SignAppToken",
    tag = "WebApp",
    path = "/jet/webapp/app-token",
    request_body(content = AppTokenSignRequest, description = "JSON-encoded payload specifying the desired claims", content_type = "application/json"),
    responses(
        (status = 200, description = "The application token has been granted", body = String),
        (status = 400, description = "Bad signature request"),
        (status = 401, description = "Invalid or missing authorization header"),
        (status = 403, description = "Insufficient permissions"),
        (status = 415, description = "Unsupported content type in request body"),
    ),
    security(
        (),
        ("web_app_custom_auth" = []),
    ),
))]
pub(crate) async fn sign_app_token(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    headers: HeaderMap,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    Json(req): Json<AppTokenSignRequest>,
) -> Result<Response, HttpError> {
    let conf = conf_handle.get_conf();

    let provisioner_key = conf
        .provisioner_private_key
        .as_ref()
        .ok_or_else(|| HttpError::internal().msg("provisioner private key is missing"))?;

    let conf = extract_conf!(conf);

    trace!(request = ?req, "Received sign app token request");

    match login_rate_limit::check(req.subject.clone(), source_addr.ip(), conf.login_limit_rate) {
        Ok(()) => {}
        Err(()) => {
            warn!(user = req.subject, "Detected too many login attempts");
            return Err(HttpError::unauthorized().msg("too many login attempts"));
        }
    }

    match &conf.authentication {
        WebAppAuth::Custom(users) => match do_custom_auth(&headers, users, &req)? {
            CustomAuthResult::Authenticated => {}
            CustomAuthResult::SendChallenge(response) => return Ok(response),
        },
        WebAppAuth::None => {}
    };

    let token = generate_web_app_token(conf, provisioner_key, req)?;

    let cache_control = TypedHeader(headers::CacheControl::new().with_no_cache().with_no_store());

    let response = (cache_control, token).into_response();

    return Ok(response);

    // -- local helpers -- //

    enum CustomAuthResult {
        Authenticated,
        SendChallenge(response::Response),
    }

    fn do_custom_auth(
        headers: &HeaderMap,
        users: &HashMap<String, WebAppUser>,
        req: &AppTokenSignRequest,
    ) -> Result<CustomAuthResult, HttpError> {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};

        let Some(authorization) = headers.typed_get::<headers::Authorization<headers::authorization::Basic>>() else {
            trace!(covmark = "custom_auth_challenge");

            let auth_header_key = headers
                .get("x-requested-with")
                .filter(|&header_value| header_value == "XMLHttpRequest")
                .map(|_| "x-www-authenticate")
                .unwrap_or(http::header::WWW_AUTHENTICATE.as_str());

            // If the Authorization header is missing, send a challenge to request it.
            return Ok(CustomAuthResult::SendChallenge(
                (
                    http::StatusCode::UNAUTHORIZED,
                    [(auth_header_key, "Basic realm=\"DGW Custom Auth\", charset=\"UTF-8\"")],
                )
                    .into_response(),
            ));
        };

        if authorization.username() != req.subject {
            trace!(covmark = "custom_auth_username_mismatch");
            return Err(HttpError::unauthorized().msg("username mismatch"));
        }

        let user = users
            .get(authorization.username())
            .ok_or_else(|| HttpError::unauthorized().msg("user not found"))?;

        let password_hash = PasswordHash::new(user.password_hash.get())
            .map_err(HttpError::internal().with_msg("invalid password hash").err())?;

        argon2::Argon2::default()
            .verify_password(authorization.password().as_bytes(), &password_hash)
            .map_err(|e| {
                trace!(covmark = "custom_auth_bad_password");
                HttpError::unauthorized().with_msg("invalid password").build(e)
            })?;

        Ok(CustomAuthResult::Authenticated)
    }

    fn generate_web_app_token(
        conf: &WebAppConf,
        key: &PrivateKey,
        req: AppTokenSignRequest,
    ) -> Result<String, HttpError> {
        use crate::token::WebAppTokenClaims;
        use picky::jose::jws::JwsAlg;
        use picky::jose::jwt::CheckedJwtSig;

        let lifetime = req
            .lifetime
            .map(Duration::from_secs)
            .map(|lifetime| {
                if lifetime < conf.app_token_maximum_lifetime {
                    lifetime
                } else {
                    conf.app_token_maximum_lifetime
                }
            })
            .unwrap_or(conf.app_token_maximum_lifetime);

        let jti = Uuid::new_v4();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let exp = now + i64::try_from(lifetime.as_secs()).map_err(HttpError::internal().err())?;

        let claims = WebAppTokenClaims {
            jti,
            iat: now,
            nbf: now,
            exp,
            sub: req.subject.clone(),
        };

        let jwt_sig = CheckedJwtSig::new_with_cty(JwsAlg::RS256, "WEBAPP", claims);

        let token = jwt_sig
            .encode(key)
            .map_err(HttpError::internal().with_msg("sign WEBAPP token").err())?;

        info!(
            user = req.subject,
            lifetime = lifetime.as_secs(),
            "Granted a WEBAPP token"
        );

        Ok(token)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(tag = "content_type")]
pub(crate) enum SessionTokenContentType {
    Association {
        /// Protocol for the session (e.g.: "rdp")
        protocol: ApplicationProtocol,
        /// Destination host
        destination: TargetAddr,
        /// Unique ID for this session
        session_id: Uuid,
    },
    Jmux {
        /// Protocol for the session (e.g.: "tunnel")
        protocol: ApplicationProtocol,
        /// Destination host
        destination: TargetAddr,
        /// Unique ID for this session
        session_id: Uuid,
    },
    Kdc {
        /// Kerberos realm.
        ///
        /// E.g.: `ad.it-help.ninja`
        /// Should be lowercased (actual validation is case-insensitive though).
        krb_realm: String,

        /// Kerberos KDC address.
        ///
        /// E.g.: `tcp://IT-HELP-DC.ad.it-help.ninja:88`
        /// Default scheme is `tcp`.
        /// Default port is `88`.
        krb_kdc: TargetAddr,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SessionTokenSignRequest {
    /// The content type for the session token
    #[serde(flatten)]
    content_type: SessionTokenContentType,
    /// The validity duration in seconds for the session token
    ///
    /// This value cannot exceed 2 hours.
    lifetime: u64,
}

/// Requests a session token using a web application token
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SignSessionToken",
    tag = "WebApp",
    path = "/jet/webapp/session-token",
    request_body(content = SessionTokenSignRequest, description = "JSON-encoded payload specifying the desired claims", content_type = "application/json"),
    responses(
        (status = 200, description = "The application token has been granted", body = String),
        (status = 400, description = "Bad signature request"),
        (status = 401, description = "Invalid or missing authorization header"),
        (status = 403, description = "Insufficient permissions"),
        (status = 415, description = "Unsupported content type in request body"),
    ),
    security(
        ("web_app_token" = []),
    ),
))]
pub(crate) async fn sign_session_token(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    WebAppToken(web_app_token): WebAppToken,
    Json(req): Json<SessionTokenSignRequest>,
) -> Result<Response, HttpError> {
    use crate::token::{AssociationTokenClaims, ConnectionMode, ContentType, JmuxTokenClaims, KdcTokenClaims};

    use picky::jose::jws::JwsAlg;
    use picky::jose::jwt::CheckedJwtSig;

    const MAXIMUM_LIFETIME_SECS: u64 = 60 * 60 * 2; // 2 hours

    trace!(request = ?req, "Received sign session token request");

    let conf = conf_handle.get_conf();

    let provisioner_key = conf
        .provisioner_private_key
        .as_ref()
        .ok_or_else(|| HttpError::internal().msg("provisioner private key is missing"))?;

    // Also perform a sanity check, ensuring the standalone web application is enabled.
    ensure_enabled!(conf);

    let lifetime = if req.lifetime < MAXIMUM_LIFETIME_SECS {
        req.lifetime
    } else {
        MAXIMUM_LIFETIME_SECS
    };

    let jti = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + i64::try_from(lifetime).map_err(HttpError::internal().err())?;

    let (claims, content_type, destination) = match req.content_type {
        SessionTokenContentType::Association {
            protocol,
            destination,
            session_id,
        } => (
            AssociationTokenClaims {
                jet_aid: session_id,
                jet_ap: protocol,
                jet_cm: ConnectionMode::Fwd {
                    targets: nonempty::NonEmpty::new(destination.clone()),
                    creds: None,
                },
                jet_rec: false,
                jet_flt: false,
                jet_ttl: crate::token::SessionTtl::Unlimited,
                exp,
                jti: Some(jti),
            }
            .pipe(serde_json::to_value)
            .map(|mut claims| {
                if let Some(claims) = claims.as_object_mut() {
                    claims.insert("iat".to_owned(), serde_json::json!(now));
                    claims.insert("nbf".to_owned(), serde_json::json!(now));
                }
                claims
            })
            .map_err(HttpError::internal().with_msg("ASSOCIATION claims").err())?,
            ContentType::Association,
            destination,
        ),

        SessionTokenContentType::Jmux {
            protocol,
            destination,
            session_id,
        } => (
            JmuxTokenClaims {
                jet_aid: session_id,
                jet_ap: protocol,
                hosts: nonempty::NonEmpty::new(destination.clone()),
                jet_ttl: crate::token::SessionTtl::Unlimited,
                exp,
                jti,
            }
            .pipe(serde_json::to_value)
            .map(|mut claims| {
                if let Some(claims) = claims.as_object_mut() {
                    claims.insert("iat".to_owned(), serde_json::json!(now));
                    claims.insert("nbf".to_owned(), serde_json::json!(now));
                }
                claims
            })
            .map_err(HttpError::internal().with_msg("JMUX claims").err())?,
            ContentType::Jmux,
            destination,
        ),

        SessionTokenContentType::Kdc { krb_realm, krb_kdc } => (
            KdcTokenClaims {
                krb_realm: krb_realm.into(),
                krb_kdc: krb_kdc.clone(),
            }
            .pipe(serde_json::to_value)
            .map(|mut claims| {
                if let Some(claims) = claims.as_object_mut() {
                    claims.insert("iat".to_owned(), serde_json::json!(now));
                    claims.insert("nbf".to_owned(), serde_json::json!(now));
                    claims.insert("exp".to_owned(), serde_json::json!(exp));
                }
                claims
            })
            .map_err(HttpError::internal().with_msg("KDC claims").err())?,
            ContentType::Kdc,
            krb_kdc,
        ),
    };

    let jwt_sig = CheckedJwtSig::new_with_cty(JwsAlg::RS256, content_type.to_string(), claims);

    let token = jwt_sig
        .encode(provisioner_key)
        .map_err(HttpError::internal().with_msg("sign session token").err())?;

    info!(
        user = web_app_token.sub,
        %destination,
        lifetime,
        %content_type,
        "Granted a session token"
    );

    let cache_control = TypedHeader(headers::CacheControl::new().with_no_cache().with_no_store());

    let response = (cache_control, token).into_response();

    Ok(response)
}

async fn get_client<ReqBody>(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    path: Option<extract::Path<String>>,
    mut request: axum::http::Request<ReqBody>,
) -> Result<Response<tower_http::services::fs::ServeFileSystemResponseBody>, HttpError>
where
    ReqBody: Send + 'static,
{
    use tower::ServiceExt as _;
    use tower_http::services::ServeDir;

    let conf = conf_handle.get_conf();
    ensure_enabled!(conf);

    let path = path.map(|path| path.0).unwrap_or_else(|| "/".to_owned());

    debug!(path, "Requested client ressource");

    *request.uri_mut() = http::Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(HttpError::internal().with_msg("invalid ressource path").err())?;

    let webapp_root_path = find_webapp_root().map_err(HttpError::internal().err())?;
    let client_root = webapp_root_path.join("client/");
    let client_index = webapp_root_path.join("client/index.html");

    match ServeDir::new(client_root)
        .fallback(ServeFile::new(client_index))
        .append_index_html_on_directories(true)
        .oneshot(request)
        .await
    {
        Ok(response) => Ok(response),
        Err(never) => match never {},
    }
}

fn find_webapp_root() -> anyhow::Result<PathBuf> {
    if let Ok(path) = env::var("DGATEWAY_WEBAPP_PATH") {
        Ok(PathBuf::from(path))
    } else {
        let mut exe_path = std::env::current_exe()?;
        exe_path.pop();
        exe_path.push("webapp");
        Ok(exe_path)
    }
}

mod login_rate_limit {
    use std::{collections::HashMap, net::IpAddr, time::Duration};

    use lazy_static::lazy_static;
    use parking_lot::Mutex;
    use time::Instant;

    type LoginAttempts = Mutex<HashMap<(String, IpAddr), u8>>;

    lazy_static! {
        static ref LOGIN_ATTEMPTS: LoginAttempts = Mutex::new(HashMap::new());
        static ref LAST_RESET: Mutex<Instant> = Mutex::new(Instant::now());
    }

    const PERIOD: Duration = Duration::from_secs(60);

    pub fn check(username: String, address: IpAddr, rate_limit: u8) -> Result<(), ()> {
        {
            // Reset if necessary.

            let now = Instant::now();
            let mut last_reset = LAST_RESET.lock();

            if now - *last_reset > PERIOD {
                *last_reset = now;
                LOGIN_ATTEMPTS.lock().clear();
            }
        }

        {
            // Check for the number of attempts within the period.

            let mut attempts = LOGIN_ATTEMPTS.lock();

            let num_attempts = attempts.entry((username, address)).or_insert(0);
            *num_attempts = num_attempts.checked_add(1).ok_or(())?;

            if *num_attempts > rate_limit {
                Err(())
            } else {
                Ok(())
            }
        }
    }
}
