pub mod controllers;
pub mod http_server;
pub mod middlewares;

use core::fmt::Display;
use core::panic::Location;
use saphir::http::StatusCode;
use saphir::http_context::HttpContext;
use saphir::responder::Responder;
use saphir::response::Builder;

pub struct HttpErrorStatus {
    code: StatusCode,
    loc: &'static Location<'static>,
    source: Box<dyn Display + Send + 'static>,
}

impl<T: Display + Send + 'static> From<(StatusCode, T)> for HttpErrorStatus {
    #[track_caller]
    fn from((code, source): (StatusCode, T)) -> Self {
        Self::new(code, source)
    }
}

impl HttpErrorStatus {
    #[track_caller]
    fn new<T: Display + Send + 'static>(code: StatusCode, source: T) -> Self {
        Self {
            code,
            loc: Location::caller(),
            source: Box::new(source),
        }
    }
}

impl Responder for HttpErrorStatus {
    fn respond_with_builder(self, builder: Builder, _: &HttpContext) -> Builder {
        slog_scope::error!("status {} at {} [source: {}]", self.code, self.loc, self.source);
        builder.status(self.code)
    }
}
