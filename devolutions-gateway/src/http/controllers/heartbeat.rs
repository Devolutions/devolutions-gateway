use crate::config::ConfHandle;
use crate::http::guards::access::AccessGuard;
use crate::http::guards::access::TokenType;
use crate::http::HttpErrorStatus;
use crate::session::SessionManagerHandle;
use crate::token::AccessScope;
use saphir::body::json::Json;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::request::Request;
use uuid::Uuid;

pub struct HeartbeatController {
    pub conf_handle: ConfHandle,
    pub sessions: SessionManagerHandle,
}

#[controller(name = "jet/heartbeat")]
impl HeartbeatController {
    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::HeartbeatRead)"#)]
    async fn get_heartbeat(&self) -> Result<Json<Heartbeat>, HttpErrorStatus> {
        get_heartbeat(&self.conf_handle, &self.sessions).await
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct Heartbeat {
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
pub(crate) async fn get_heartbeat(
    conf_handle: &ConfHandle,
    sessions: &SessionManagerHandle,
) -> Result<Json<Heartbeat>, HttpErrorStatus> {
    let conf = conf_handle.get_conf();

    let running_session_count = sessions
        .get_running_session_count()
        .await
        .map_err(HttpErrorStatus::internal)?;

    Ok(Json(Heartbeat {
        id: conf.id,
        hostname: conf.hostname.clone(),
        version: env!("CARGO_PKG_VERSION"),
        running_session_count,
    }))
}
