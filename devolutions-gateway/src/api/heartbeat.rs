use axum::extract::State;
use axum::Json;
use uuid::Uuid;

use crate::extract::HeartbeatReadScope;
use crate::http::HttpError;
use crate::DgwState;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct Heartbeat {
    /// This Gateway's unique ID
    id: Option<Uuid>,
    /// This Gateway's hostname
    hostname: String,
    /// Gateway service version
    version: &'static str,
    /// Number of running sessions
    running_session_count: usize,
}

/// Performs a heartbeat check
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetHeartbeat",
    tag = "Heartbeat",
    path = "/jet/heartbeat",
    responses(
        (status = 200, description = "Heartbeat for this Gateway", body = Heartbeat),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.heartbeat.read"])),
))]
pub(super) async fn get_heartbeat(
    State(DgwState {
        conf_handle, sessions, ..
    }): State<DgwState>,
    _scope: HeartbeatReadScope,
) -> Result<Json<Heartbeat>, HttpError> {
    let conf = conf_handle.get_conf();

    let running_session_count = sessions
        .get_running_session_count()
        .await
        .map_err(HttpError::internal().err())?;

    Ok(Json(Heartbeat {
        id: conf.id,
        hostname: conf.hostname.clone(),
        version: env!("CARGO_PKG_VERSION"),
        running_session_count,
    }))
}
