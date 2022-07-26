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
    components(
        SessionInfo,
        ConnectionMode,
        crate::http::controllers::diagnostics::GatewayConfiguration,
        crate::config::ListenerConfig,
        crate::http::controllers::diagnostics::GatewayClock,
    )
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
    connection_mode: ConnectionMode,
    destination_host: Option<String>,
}

#[derive(Serialize, utoipa::Component)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionMode {
    Rdv,
    Fwd,
}
