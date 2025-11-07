use aide::OperationOutput;
use axum::Json;
use axum::response::{IntoResponse, Response};
use hyper::StatusCode;

use crate::db::DbError;

/// An error type for route handlers.
///
/// The error contains a status code and an optional error message.
#[derive(Debug)]
pub(crate) struct HandlerError(StatusCode, Option<String>);

impl HandlerError {
    /// Creates a handler error.
    ///
    /// The input message should start with a lowercase letter.
    /// It will be capitalized in the response.
    #[allow(dead_code, reason = "reserved for future use")]
    pub(crate) fn new(status_code: StatusCode, msg: Option<&str>) -> Self {
        Self(
            status_code,
            msg.map(|s| {
                // capitalize first letter
                let mut t = s
                    .chars()
                    .next()
                    .expect("handler error messaged contained empty string")
                    .to_uppercase()
                    .to_string();
                t.push_str(&s[1..]);
                t
            }),
        )
    }
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        (self.0, self.1.unwrap_or_default()).into_response()
    }
}

// for Aide
impl OperationOutput for HandlerError {
    type Inner = (StatusCode, Json<HandlerError>);
}

impl From<DbError> for HandlerError {
    fn from(e: DbError) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, Some(e.to_string()))
    }
}

impl From<anyhow::Error> for HandlerError {
    fn from(e: anyhow::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, Some(e.to_string()))
    }
}

#[cfg(feature = "postgres")]
impl From<tokio_postgres::Error> for HandlerError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, Some(e.to_string()))
    }
}
