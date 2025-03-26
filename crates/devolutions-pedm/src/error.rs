use std::fmt::Debug;

use aide::OperationOutput;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hyper::StatusCode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::error;
use win_api_wrappers::raw::Win32::Foundation::{
    ERROR_ACCESS_DISABLED_BY_POLICY, ERROR_CANCELLED, ERROR_INVALID_PARAMETER, E_UNEXPECTED,
};

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum Error {
    AccessDenied,
    NotFound,
    InvalidParameter,
    Internal,
    Cancelled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl<E> From<E> for Error
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        let error = error.into();

        match error.downcast::<Error>() {
            Ok(error) => error,
            Err(error) => {
                error!(%error, "Error handling request");

                Error::Internal
            }
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        ErrorResponse::from(self).into_response()
    }
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub struct ErrorResponse {
    kind: Error,
    win32_error: u32,
}

impl From<Error> for ErrorResponse {
    fn from(kind: Error) -> Self {
        let win32_error = match kind {
            Error::AccessDenied => ERROR_ACCESS_DISABLED_BY_POLICY.0,
            Error::InvalidParameter | Error::NotFound => ERROR_INVALID_PARAMETER.0,
            #[expect(clippy::cast_sign_loss)] // E_UNEXPECTED fits in a u32.
            Error::Internal => E_UNEXPECTED.0 as u32,
            Error::Cancelled => ERROR_CANCELLED.0,
        };

        Self { kind, win32_error }
    }
}

impl OperationOutput for Error {
    type Inner = (StatusCode, Json<ErrorResponse>);
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (
            match self.kind {
                Error::AccessDenied => StatusCode::FORBIDDEN,
                Error::NotFound => StatusCode::NOT_FOUND,
                Error::InvalidParameter => StatusCode::BAD_REQUEST,
                Error::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Cancelled => StatusCode::REQUEST_TIMEOUT,
            },
            Json(self),
        )
            .into_response()
    }
}
