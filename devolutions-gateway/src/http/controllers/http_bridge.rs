use crate::http::guards::access::{AccessGuard, JetTokenType};
use crate::http::HttpErrorStatus;
use crate::token::JetAccessTokenClaims;
use saphir::macros::controller;
use saphir::request::Request;
use saphir::response::Builder;

pub struct HttpBridgeController {
    client: reqwest::Client,
}

impl HttpBridgeController {
    pub fn new() -> Self {
        let client = reqwest::Client::new();
        Self { client }
    }
}

impl Default for HttpBridgeController {
    fn default() -> Self {
        Self::new()
    }
}

#[controller(name = "jet/bridge")]
impl HttpBridgeController {
    #[get("/message")]
    #[post("/message")]
    #[put("/message")]
    #[patch("/message")]
    #[delete("/message")]
    #[guard(AccessGuard, init_expr = r#"JetTokenType::Bridge"#)]
    async fn message(&self, mut req: Request) -> Result<Builder, HttpErrorStatus> {
        use core::convert::TryFrom;

        let claims = req
            .extensions_mut()
            .remove::<JetAccessTokenClaims>()
            .ok_or_else(|| HttpErrorStatus::unauthorized("identity is missing (token)"))?;

        // FIXME: when updating reqwest 0.10 → 0.11 and hyper 0.13 → 0.14:
        // Use https://docs.rs/reqwest/0.11.4/reqwest/struct.Body.html#impl-From%3CBody%3E
        // to get a streaming reqwest Request instead of loading the whole body in memory.
        let req = req.load_body().await.map_err(HttpErrorStatus::internal)?;
        let req: saphir::request::Request<reqwest::Body> = req.map(reqwest::Body::from);
        let mut req: http::Request<reqwest::Body> = http::Request::from(req);

        // Update request destination based on the token claims
        let uri: http::Uri = if let JetAccessTokenClaims::Bridge(claims) = claims {
            // <METHOD> <TARGET>
            let request_target = req
                .headers()
                .get("Request-Target")
                .ok_or_else(|| HttpErrorStatus::bad_request("Request-Target header is missing"))?
                .to_str()
                .map_err(|_| HttpErrorStatus::bad_request("Request-Target header has an invalid value"))?;
            // <TARGET>
            let request_target = request_target
                .split(' ')
                .rev()
                .next()
                .expect("Split always returns at least one element");

            claims
                .target_host
                .to_uri_with_path_and_query(request_target)
                .map_err(|e| {
                    HttpErrorStatus::bad_request(format!("Request-Target header has an invalid value: {}", e))
                })?
        } else {
            return Err(HttpErrorStatus::forbidden("token not allowed"));
        };
        *req.uri_mut() = uri;

        // Forward
        slog_scope::debug!("Forward HTTP request to {}", req.uri());
        let req = reqwest::Request::try_from(req).map_err(HttpErrorStatus::internal)?;
        let mut rsp = self.client.execute(req).await.map_err(HttpErrorStatus::bad_gateway)?;

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
    }
}
