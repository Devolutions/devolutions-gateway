use core::fmt;
use core::panic::Location;
use std::error::Error as StdError;

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::error_code::ErrorCode;

pub struct HttpErrorBuilder {
    pub code: StatusCode,
    pub loc: &'static Location<'static>,
    pub msg: Option<&'static str>,
    pub error_code: Option<ErrorCode>,
}

impl HttpErrorBuilder {
    #[inline]
    #[track_caller]
    pub fn new(code: StatusCode) -> Self {
        Self {
            code,
            loc: Location::caller(),
            msg: None,
            error_code: None,
        }
    }

    #[inline]
    pub fn build<T: Into<Box<dyn StdError + Sync + Send + 'static>>>(self, source: T) -> HttpError {
        HttpError {
            code: self.code,
            loc: self.loc,
            msg: self.msg,
            error_code: self.error_code,
            source: Some(source.into()),
        }
    }

    #[inline]
    pub fn err<T: Into<Box<dyn StdError + Sync + Send + 'static>>>(self) -> impl FnOnce(T) -> HttpError {
        move |source| HttpError {
            code: self.code,
            loc: self.loc,
            msg: self.msg,
            error_code: self.error_code,
            source: Some(source.into()),
        }
    }

    #[inline]
    #[must_use]
    pub fn with_msg(mut self, msg: &'static str) -> HttpErrorBuilder {
        self.msg = Some(msg);
        self
    }

    /// Sets the machine-readable code sent to the client.
    ///
    /// Without one, the response carries the generic code matching the HTTP status.
    #[inline]
    #[must_use]
    pub fn with_error_code(mut self, error_code: ErrorCode) -> HttpErrorBuilder {
        self.error_code = Some(error_code);
        self
    }

    #[inline]
    pub fn msg(self, msg: &'static str) -> HttpError {
        HttpError {
            code: self.code,
            loc: self.loc,
            msg: Some(msg),
            error_code: self.error_code,
            source: None,
        }
    }
}

pub struct HttpError {
    pub code: StatusCode,
    pub loc: &'static Location<'static>,
    /// Internal context, logged but never sent to the client.
    pub msg: Option<&'static str>,
    /// Machine-readable code sent to the client.
    pub error_code: Option<ErrorCode>,
    /// Internal error, logged but never sent to the client.
    pub source: Option<Box<dyn StdError + Sync + Send + 'static>>,
}

impl HttpError {
    #[inline]
    #[track_caller]
    pub fn forbidden() -> HttpErrorBuilder {
        HttpErrorBuilder::new(StatusCode::FORBIDDEN)
    }

    #[inline]
    #[track_caller]
    pub fn not_found() -> HttpErrorBuilder {
        HttpErrorBuilder::new(StatusCode::NOT_FOUND)
    }

    #[inline]
    #[track_caller]
    pub fn unauthorized() -> HttpErrorBuilder {
        HttpErrorBuilder::new(StatusCode::UNAUTHORIZED)
    }

    #[inline]
    #[track_caller]
    pub fn internal() -> HttpErrorBuilder {
        HttpErrorBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
    }

    #[inline]
    #[track_caller]
    pub fn bad_request() -> HttpErrorBuilder {
        HttpErrorBuilder::new(StatusCode::BAD_REQUEST)
    }

    #[inline]
    #[track_caller]
    pub fn bad_gateway() -> HttpErrorBuilder {
        HttpErrorBuilder::new(StatusCode::BAD_GATEWAY)
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.code, self.loc)?;

        if let Some(msg) = self.msg {
            write!(f, ": {msg}")?;
        }

        if let Some(source) = self.source.as_deref() {
            write!(f, " [source: {source}")?;
            for cause in anyhow::Chain::new(source).skip(1) {
                write!(f, ", because {cause}")?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let error_code = self.error_code.unwrap_or_else(|| generic_error_code(self.code));
        error!(error = %self, %error_code);
        ApiError::new(self.code, error_code).into_response()
    }
}

/// Returns the code describing an HTTP status, for errors without a more specific code.
fn generic_error_code(status: StatusCode) -> ErrorCode {
    match status {
        StatusCode::BAD_REQUEST => ErrorCode::BadRequest,
        StatusCode::UNAUTHORIZED => ErrorCode::Unauthorized,
        StatusCode::FORBIDDEN => ErrorCode::Forbidden,
        StatusCode::NOT_FOUND => ErrorCode::NotFound,
        StatusCode::REQUEST_TIMEOUT => ErrorCode::RequestTimeout,
        StatusCode::CONFLICT => ErrorCode::Conflict,
        StatusCode::PAYLOAD_TOO_LARGE => ErrorCode::PayloadTooLarge,
        StatusCode::INTERNAL_SERVER_ERROR => ErrorCode::InternalError,
        StatusCode::BAD_GATEWAY => ErrorCode::BadGateway,
        StatusCode::SERVICE_UNAVAILABLE => ErrorCode::ServiceUnavailable,
        StatusCode::GATEWAY_TIMEOUT => ErrorCode::GatewayTimeout,
        StatusCode::INSUFFICIENT_STORAGE => ErrorCode::InsufficientStorage,
        _ if status.is_client_error() => ErrorCode::BadRequest,
        _ => ErrorCode::InternalError,
    }
}

// Only the code is sent to the client: never add internal details, such as error sources or claim values.
// The `utoipa::path` annotations of the API handlers refer to this schema by name, without importing it.

/// Body of an API error response, as defined by RFC 9457 (problem details for HTTP APIs).
///
/// The Gateway logs the details of the error, along with its code.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(
    example = json!({ "type": "about:blank", "title": "Unauthorized", "status": 401, "error": "gateway_id_mismatch" })
))]
pub struct ApiError {
    /// Problem type, always `about:blank`: the HTTP status and the error code describe the problem.
    #[serde(rename = "type")]
    problem_type: &'static str,
    /// Reason phrase of the HTTP status.
    title: &'static str,
    /// HTTP status code.
    #[serde(serialize_with = "serialize_status")]
    #[cfg_attr(feature = "openapi", schema(value_type = u16))]
    status: StatusCode,
    /// Machine-readable error code; the `ErrorCode` schema lists the known values.
    ///
    /// New codes can be added: treat unknown values as generic failures.
    // Typed as a string in the OpenAPI document, so that generated clients keep parsing the body when they get an unknown code.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    error: ErrorCode,
}

impl ApiError {
    pub const CONTENT_TYPE: &'static str = "application/problem+json";

    pub fn new(status: StatusCode, error: ErrorCode) -> Self {
        Self {
            problem_type: "about:blank",
            title: status.canonical_reason().unwrap_or("Unknown"),
            status,
            error,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let challenge = bearer_challenge(self.error);

        let mut response = (status, Json(self)).into_response();

        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(Self::CONTENT_TYPE));
        if let Some(challenge) = challenge {
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }

        response
    }
}

fn serialize_status<S: serde::Serializer>(status: &StatusCode, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u16(status.as_u16())
}

/// Returns the `WWW-Authenticate` challenge for a rejected bearer token, as described by RFC 6750.
fn bearer_challenge(error_code: ErrorCode) -> Option<&'static str> {
    match error_code {
        ErrorCode::MissingToken => Some("Bearer"),
        ErrorCode::MalformedToken
        | ErrorCode::BadSignature
        | ErrorCode::UnknownSubkey
        | ErrorCode::Expired
        | ErrorCode::NotYetValid
        | ErrorCode::GatewayIdMismatch
        | ErrorCode::Revoked
        | ErrorCode::UnexpectedReplay
        | ErrorCode::InvalidToken => Some(r#"Bearer error="invalid_token""#),
        ErrorCode::InsufficientScope => Some(r#"Bearer error="insufficient_scope""#),
        ErrorCode::BadRequest
        | ErrorCode::Unauthorized
        | ErrorCode::Forbidden
        | ErrorCode::NotFound
        | ErrorCode::RequestTimeout
        | ErrorCode::Conflict
        | ErrorCode::PayloadTooLarge
        | ErrorCode::InternalError
        | ErrorCode::BadGateway
        | ErrorCode::ServiceUnavailable
        | ErrorCode::GatewayTimeout
        | ErrorCode::InsufficientStorage
        | ErrorCode::WrongTokenType => None,
    }
}

/// Serves a static directory for a request whose sub-path was captured by a `{*path}` wildcard.
pub(crate) async fn serve_dir<ReqBody>(
    mut request: axum::http::Request<ReqBody>,
    captured_path: Option<axum::extract::Path<String>>,
    root: std::path::PathBuf,
    index: std::path::PathBuf,
) -> Result<Response<tower_http::services::fs::ServeFileSystemResponseBody>, HttpError>
where
    ReqBody: Send + 'static,
{
    use tower::ServiceExt as _;
    use tower_http::services::{ServeDir, ServeFile};

    // The captured wildcard ({*path}) does not include the leading slash,
    // but `path_and_query` requires the path to start with a slash.
    let path = format!("/{}", captured_path.map(|path| path.0).unwrap_or_default());

    debug!(path, "Requested static resource");

    *request.uri_mut() = axum::http::Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(HttpError::internal().with_msg("invalid resource path").err())?;

    match ServeDir::new(root)
        .fallback(ServeFile::new(index))
        .append_index_html_on_directories(true)
        .oneshot(request)
        .await
    {
        Ok(response) => Ok(response),
        Err(never) => match never {},
    }
}
