use axum::debug_handler;
use axum::Router;
use axum::extract;
use axum::routing;
use axum::http;
use crate::DgwState;
use network_monitor;
use network_monitor::SetConfigError;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    let router = Router::new().route("/config", routing::post(handle_set_monitoring_config));

    router.with_state(state)
}

#[debug_handler]
async fn handle_set_monitoring_config(
    extract::Json(config): extract::Json<network_monitor::MonitorsConfig>,
) -> Result<(), http::StatusCode> {
    network_monitor::set_config(config).await.map_err (| err |  {
        match err {
            SetConfigError::Io(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            SetConfigError::Serde(_) => http::StatusCode::INTERNAL_SERVER_ERROR
        }
    })
}
