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
    pub fn err<T: Into<Box<dyn StdError + Sync + Send + 'static>>>(self) -> impl FnOnce(T) -> HttpError {
        move |source| HttpError {
            code: self.code,
            loc: self.loc,
            msg: self.msg,
            source: Some(source.into()),
        }
    }

    #[inline]
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
