use core::fmt;
use core::panic::Location;
use std::error::Error as StdError;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub struct HttpErrorBuilder {
    pub code: StatusCode,
    pub loc: &'static Location<'static>,
    pub msg: Option<&'static str>,
}

impl HttpErrorBuilder {
    #[inline]
    #[track_caller]
    pub fn new(code: StatusCode) -> Self {
        Self {
            code,
            loc: Location::caller(),
            msg: None,
        }
    }

    #[inline]
    pub fn build<T: Into<Box<dyn StdError + Sync + Send + 'static>>>(self, source: T) -> HttpError {
        HttpError {
            code: self.code,
            loc: self.loc,
            msg: self.msg,
            source: Some(source.into()),
        }
    }

    #[inline]
    pub fn err<T: Into<Box<dyn StdError + Sync + Send + 'static>>>(self) -> impl FnOnce(T) -> HttpError {
        move |source| HttpError {
            code: self.code,
            loc: self.loc,
            msg: self.msg,
            source: Some(source.into()),
        }
    }

    #[inline]
    #[must_use]
    pub fn with_msg(mut self, msg: &'static str) -> HttpErrorBuilder {
        self.msg = Some(msg);
        self
    }

    #[inline]
    pub fn msg(self, msg: &'static str) -> HttpError {
        HttpError {
            code: self.code,
            loc: self.loc,
            msg: Some(msg),
            source: None,
        }
    }
}

pub struct HttpError {
    pub code: StatusCode,
    pub loc: &'static Location<'static>,
    pub msg: Option<&'static str>,
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
        error!(error = %self);
        self.code.into_response()
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

    debug!(path, "Requested static ressource");

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
