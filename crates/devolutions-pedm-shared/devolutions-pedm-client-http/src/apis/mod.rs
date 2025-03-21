use http;
use hyper;
use serde_json;

#[derive(Debug)]
pub enum Error {
    Api(ApiError),
    Header(hyper::http::header::InvalidHeaderValue),
    Http(http::Error),
    Hyper(hyper::Error),
    Serde(serde_json::Error),
    UriError(http::uri::InvalidUri),
}

#[derive(Debug)]
pub struct ApiError {
    pub code: hyper::StatusCode,
    pub body: hyper::body::Body,
}

impl From<(hyper::StatusCode, hyper::body::Body)> for Error {
    fn from(e: (hyper::StatusCode, hyper::body::Body)) -> Self {
        Error::Api(ApiError { code: e.0, body: e.1 })
    }
}

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Self {
        Error::Http(e)
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Error::Hyper(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

mod request;

mod default_api;
pub use self::default_api::{DefaultApi, DefaultApiClient};

pub mod client;
pub mod configuration;
