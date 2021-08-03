use crate::http::guards::access::{AccessGuard, JetTokenType};
use crate::http::HttpErrorStatus;
use jet_proto::token::JetAccessTokenClaims;
use saphir::macros::controller;
use saphir::request::Request;
use saphir::response::Builder;

pub const REQUEST_AUTHORIZATION_TOKEN_HDR_NAME: &str = "Request-Authorization-Token";

pub struct HttpBridgeController {
    client: reqwest::Client,
}

impl HttpBridgeController {
    pub fn new() -> Self {
        let client = reqwest::Client::new();
        Self { client }
    }
}

#[controller(name = "bridge")]
impl HttpBridgeController {
    #[post("/message")]
    #[guard(AccessGuard, init_expr = r#"JetTokenType::Bridge"#)]
    async fn message(&self, req: Request) -> Result<Builder, HttpErrorStatus> {
        use core::convert::TryFrom;

        if let Some(JetAccessTokenClaims::Bridge(claims)) = req
            .extensions()
            .get::<JetAccessTokenClaims>()
            .map(|claim| claim.clone())
        {
            // FIXME: when updating reqwest 0.10 → 0.11 and hyper 0.13 → 0.14:
            // Use https://docs.rs/reqwest/0.11.4/reqwest/struct.Body.html#impl-From%3CBody%3E
            // to get a streaming reqwest Request instead of loading the whole body in memory.
            let req = req.load_body().await.map_err(HttpErrorStatus::internal)?;
            let req: saphir::request::Request<reqwest::Body> = req.map(reqwest::Body::from);
            let mut req: http::Request<reqwest::Body> = http::Request::from(req);

            // === Replace Authorization header (used to be authorized on the gateway) with the request authorization token === //

            let mut rsp = {
                let headers = req.headers_mut();
                headers.remove(http::header::AUTHORIZATION);
                if let Some(auth_token) = headers.remove(REQUEST_AUTHORIZATION_TOKEN_HDR_NAME) {
                    headers.insert(http::header::AUTHORIZATION, auth_token);
                }

                // Update request destination
                let uri = http::Uri::try_from(claims.target.as_str()).map_err(HttpErrorStatus::bad_request)?;
                *req.uri_mut() = uri;

                // Forward
                slog_scope::debug!("Forward HTTP request to {}", req.uri());
                let req = reqwest::Request::try_from(req).map_err(HttpErrorStatus::internal)?;
                self.client.execute(req).await.map_err(HttpErrorStatus::bad_gateway)?
            };

            // === Create HTTP response using target response === //

            let mut rsp_builder = Builder::new();

            {
                // Status code
                rsp_builder = rsp_builder.status(rsp.status());

                // Headers
                let headers = rsp_builder.headers_mut().unwrap();
                rsp.headers_mut().drain().for_each(|(name, value)| {
                    if let Some(name) = name {
                        headers.insert(name, value);
                    }
                });

                // Body
                match rsp.bytes().await {
                    Ok(body) => rsp_builder = rsp_builder.body(body),
                    Err(e) => slog_scope::warn!("Couldn’t get bytes from response body: {}", e),
                }
            }

            Ok(rsp_builder)
        } else {
            Err(HttpErrorStatus::unauthorized("Bridge token is mandatory"))
        }
    }
}
