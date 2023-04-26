use crate::config::ConfHandle;
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpError;
use crate::token::{AccessScope, AccessTokenClaims, CurrentJrl};
use saphir::prelude::*;
use std::sync::Arc;
use tap::Pipe as _;
use tokio::io::{AsyncWriteExt, BufWriter};
use uuid::Uuid;

pub struct JrlController {
    conf_handle: ConfHandle,
    revocation_list: Arc<CurrentJrl>,
}

impl JrlController {
    pub fn new(config: ConfHandle, revocation_list: Arc<CurrentJrl>) -> Self {
        Self {
            conf_handle: config,
            revocation_list,
        }
    }
}

#[controller(name = "jet/jrl")]
impl JrlController {
    #[post("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Jrl"#)]
    async fn update_jrl(&self, req: Request) -> Result<(), HttpError> {
        update_jrl(&self.conf_handle, &self.revocation_list, req).await
    }

    #[get("/info")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::JrlRead)"#)]
    async fn get_jrl_info(&self) -> Json<JrlInfo> {
        get_jrl_info(&self.revocation_list).await
    }
}

/// Updates JRL (Json Revocation List) using a JRL token
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "UpdateJrl",
    tag = "Jrl",
    path = "/jet/jrl",
    responses(
        (status = 200, description = "JRL updated successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to update the JRL"),
    ),
    security(("jrl_token" = [])),
))]
async fn update_jrl(conf_handle: &ConfHandle, revocation_list: &CurrentJrl, mut req: Request) -> Result<(), HttpError> {
    let claims = req
        .extensions_mut()
        .remove::<AccessTokenClaims>()
        .ok_or_else(|| HttpError::unauthorized().msg("identity is missing (token)"))?;

    if let AccessTokenClaims::Jrl(claims) = claims {
        let conf = conf_handle.get_conf();

        let jrl_json = serde_json::to_string_pretty(&claims)
            .map_err(HttpError::internal().with_msg("failed to serialize JRL").err())?;

        let jrl_file = conf.jrl_file.as_path();

        info!(path = %jrl_file, "Writing JRL file to disk");

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(jrl_file)
            .await
            .map_err(HttpError::internal().err())?
            .pipe(BufWriter::new);

        file.write_all(jrl_json.as_bytes())
            .await
            .map_err(HttpError::internal().err())?;

        file.flush().await.map_err(HttpError::internal().err())?;

        *revocation_list.lock() = claims;

        info!("Current JRL updated!");

        Ok(())
    } else {
        Err(HttpError::forbidden().msg("token not allowed"))
    }
}

/// Retrieves current JRL (Json Revocation List) info
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetJrlInfo",
    tag = "Jrl",
    path = "/jet/jrl/info",
    responses(
        (status = 200, description = "Current JRL Info", body = JrlInfo),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to update the JRL"),
    ),
    security(("scope_token" = ["gateway.jrl.read"])),
))]
async fn get_jrl_info(revocation_list: &CurrentJrl) -> Json<JrlInfo> {
    let revocation_list = revocation_list.lock();
    Json(JrlInfo {
        jti: revocation_list.jti,
        iat: revocation_list.iat,
    })
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct JrlInfo {
    /// Unique ID for current JRL
    pub jti: Uuid,
    /// JWT "Issued At" claim of JRL
    pub iat: i64,
}
