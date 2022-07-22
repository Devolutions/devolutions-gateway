#![allow(non_camel_case_types)]

use chrono::{DateTime, Utc};
use utoipa::OpenApi;
use uuid::Uuid;

#[derive(OpenApi)]
#[openapi(
    handlers(
        crate::http::controllers::health::get_health,
        crate::http::controllers::sessions::get_sessions,
        crate::http::controllers::diagnostics::get_logs,
        crate::http::controllers::diagnostics::get_configuration,
        crate::http::controllers::diagnostics::get_clock,
    ),
    components(SessionInfo)
)]
pub struct ApiDoc;

#[allow(dead_code)]
#[derive(utoipa::Component)]
pub struct SessionInfo {
    association_id: Uuid,
    application_protocol: String,
    recording_policy: bool,
    filtering_policy: bool,
    start_timestamp: DateTime<Utc>,
    #[component(inline)]
    connection_mode: ConnectionMode,
    destination_host: Option<String>,
}

#[derive(utoipa::Component)]
pub enum ConnectionMode {
    rdv,
    fwd,
}
