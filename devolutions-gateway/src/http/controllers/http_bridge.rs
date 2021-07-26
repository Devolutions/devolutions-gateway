use crate::config::Config;
use crate::http::HttpErrorStatus;
use saphir::http::StatusCode;
use saphir::macros::controller;
use saphir::request::Request;
use saphir::response::Builder;
use std::sync::Arc;

pub const GATEWAY_BRIDGE_TOKEN_HDR_NAME: &str = "Gateway-Bridge-Token";

#[derive(Deserialize)]
struct HttpBridgeClaims {
    target: url::Url,
}

pub struct HttpBridgeController {
    config: Arc<Config>,
    client: reqwest::Client,
}

impl HttpBridgeController {
    pub fn new(config: Arc<Config>) -> Self {
        let client = reqwest::Client::new();
        Self { config, client }
    }
}

impl HttpBridgeController {
    fn h_decode_claims(&self, token_str: &str) -> Result<HttpBridgeClaims, HttpErrorStatus> {
        use core::convert::TryFrom;
        use picky::jose::jwt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let key = self
            .config
            .provisioner_public_key
            .as_ref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "provisioner public key is missing"))?;

        let numeric_date = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("UNIX EPOCH is in the past")
            .as_secs();
        let date = jwt::JwtDate::new(i64::try_from(numeric_date).unwrap());
        let validator = jwt::JwtValidator::strict(&date);

        let jws = jwt::JwtSig::decode(token_str, key, &validator).map_err(|e| (StatusCode::FORBIDDEN, e))?;

        Ok(jws.claims)
    }
}

#[controller(name = "bridge")]
impl HttpBridgeController {
    #[post("/message")]
    async fn message(&self, req: Request) -> Result<Builder, HttpErrorStatus> {
        use core::convert::TryFrom;

        // FIXME: when updating reqwest 0.10 → 0.11 and hyper 0.13 → 0.14:
        // Use https://docs.rs/reqwest/0.11.4/reqwest/struct.Body.html#impl-From%3CBody%3E
        // to get a streaming reqwest Request instead of loading the whole body in memory.
        let req: saphir::request::Request<saphir::body::Bytes> = req
            .load_body()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let req: saphir::request::Request<reqwest::Body> = req.map(reqwest::Body::from);
        let mut req: http::Request<reqwest::Body> = http::Request::from(req);

        // === Filter and validate request to forward === //

        let headers = req.headers_mut();

        // Gateway Bridge Claims
        let token_hdr = headers
            .remove(GATEWAY_BRIDGE_TOKEN_HDR_NAME)
            .ok_or((StatusCode::BAD_REQUEST, "Gateway-Bridge-Token header is missing"))?;
        let token_str = token_hdr.to_str().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let claims = self.h_decode_claims(token_str)?;

        // Update request destination
        let uri = http::Uri::try_from(claims.target.as_str()).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        *req.uri_mut() = uri;

        // Forward
        slog_scope::debug!("Forward HTTP request to {}", req.uri());
        let req = reqwest::Request::try_from(req).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let mut rsp = self
            .client
            .execute(req)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;

        // === Create HTTP response using target response === //

        let mut rsp_builder = Builder::new();

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

        Ok(rsp_builder)
    }
}
