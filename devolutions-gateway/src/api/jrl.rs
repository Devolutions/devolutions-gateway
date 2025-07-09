use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use tap::Pipe as _;
use tokio::io::{AsyncWriteExt, BufWriter};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{JrlReadScope, JrlToken};
use crate::http::HttpError;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/", post(update_jrl))
        .route("/info", get(get_jrl_info))
        .with_state(state)
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
async fn update_jrl(
    State(DgwState { conf_handle, jrl, .. }): State<DgwState>,
    JrlToken(claims): JrlToken,
) -> Result<(), HttpError> {
    let conf = conf_handle.get_conf();

    let jrl_json = serde_json::to_string_pretty(&claims)
        .map_err(HttpError::internal().with_msg("failed to serialize JRL").err())?;

    let jrl_tmp_path = conf.jrl_file.with_extension("tmp");

    debug!(path = %jrl_tmp_path, "Writing JRL file to disk");

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&jrl_tmp_path)
        .await
        .map_err(HttpError::internal().err())?
        .pipe(BufWriter::new);

    file.write_all(jrl_json.as_bytes())
        .await
        .map_err(HttpError::internal().err())?;

    file.flush().await.map_err(HttpError::internal().err())?;

    let jrl_path = conf.jrl_file.as_path();

    debug!(tmp_path = %jrl_tmp_path, path = %jrl_path, "Swapping temporary JRL file");

    tokio::fs::rename(jrl_tmp_path, jrl_path)
        .await
        .map_err(HttpError::internal().err())?;

    *jrl.lock() = claims;

    info!("Current JRL updated!");

    Ok(())
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct JrlInfo {
    /// Unique ID for current JRL
    jti: Uuid,
    /// JWT "Issued At" claim of JRL
    iat: i64,
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
async fn get_jrl_info(State(DgwState { jrl, .. }): State<DgwState>, _scope: JrlReadScope) -> Json<JrlInfo> {
    let revocation_list = jrl.lock();
    Json(JrlInfo {
        jti: revocation_list.jti,
        iat: revocation_list.iat,
    })
}
