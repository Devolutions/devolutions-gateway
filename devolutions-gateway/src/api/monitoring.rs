use axum::debug_handler;
use axum::Json;
use axum::Router;
use axum::extract;
use axum::routing;
use axum::http;
use network_monitor::MonitorResult;
use crate::DgwState;
use network_monitor;
use network_monitor::SetConfigError;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    let router = Router::new()
        .route("/config", routing::post(handle_set_monitoring_config))
        .route("/log/drain", routing::post(handle_drain_log));

    router.with_state(state)
}

#[debug_handler]
async fn handle_set_monitoring_config(
    extract::State(DgwState { monitoring_state, .. }): extract::State<DgwState>,
    Json(config): Json<network_monitor::MonitorsConfig>,
) -> Result<(), http::StatusCode> {
    network_monitor::set_config(config, monitoring_state).await.map_err (| err |  {
        // TODO: no side effects in a map please. move the match to a From impl?
        error!(error = format!("{err:#}"), "Failed to set up network monitoring");
        match err {
            SetConfigError::Io(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            SetConfigError::Serde(_) => http::StatusCode::INTERNAL_SERVER_ERROR
        }
    })
}

#[debug_handler]
async fn handle_drain_log(
    extract::State(DgwState { monitoring_state, .. }): extract::State<DgwState>
) -> Result<Json<MonitoringLogResponse>, http::StatusCode> {
    Ok(Json(
        MonitoringLogResponse {
            entries: network_monitor::drain_log(monitoring_state).into()
        }
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct MonitoringLogResponse {
    entries: Vec<MonitorResult>
}
