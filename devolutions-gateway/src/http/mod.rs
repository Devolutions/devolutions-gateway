pub mod controllers;
pub mod guards;
pub mod http_server;
pub mod middlewares;

use core::fmt::Display;
use core::panic::Location;
use saphir::http::StatusCode;
use saphir::http_context::HttpContext;
use saphir::responder::Responder;
use saphir::response::Builder;

pub struct HttpErrorStatus {
    pub code: StatusCode,
    pub loc: &'static Location<'static>,
    pub source: Box<dyn Display + Send + Sync + 'static>, // TODO: use anyhow::Error
}

impl<T: Display + Send + Sync + 'static> From<(StatusCode, T)> for HttpErrorStatus {
    #[track_caller]
    fn from((code, source): (StatusCode, T)) -> Self {
        Self::new(code, source)
    }
}

impl HttpErrorStatus {
    #[track_caller]
    fn new<T: Display + Send + Sync + 'static>(code: StatusCode, source: T) -> Self {
        Self {
            code,
            loc: Location::caller(),
            source: Box::new(source),
        }
    }

    #[track_caller]
    fn forbidden<T: Display + Send + Sync + 'static>(source: T) -> Self {
        Self::new(StatusCode::FORBIDDEN, source)
    }

    #[track_caller]
    fn not_found<T: Display + Send + Sync + 'static>(source: T) -> Self {
        Self::new(StatusCode::NOT_FOUND, source)
    }

    #[track_caller]
    fn unauthorized<T: Display + Send + Sync + 'static>(source: T) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, source)
    }

    #[track_caller]
    fn internal<T: Display + Send + Sync + 'static>(source: T) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, source)
    }

    #[track_caller]
    fn bad_request<T: Display + Send + Sync + 'static>(source: T) -> Self {
        Self::new(StatusCode::BAD_REQUEST, source)
    }

    #[track_caller]
    fn bad_gateway<T: Display + Send + Sync + 'static>(source: T) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, source)
    }
}

impl Responder for HttpErrorStatus {
    fn respond_with_builder(self, builder: Builder, _: &HttpContext) -> Builder {
        error!("{} at {} [{:#}]", self.code, self.loc, self.source);
        builder.status(self.code)
    }
}
