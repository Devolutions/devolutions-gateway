use chrono::{DateTime, Utc};
use utoipa::OpenApi;
use uuid::Uuid;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::http::controllers::health::get_health,
        crate::http::controllers::sessions::get_sessions,
        crate::http::controllers::diagnostics::get_logs,
        crate::http::controllers::diagnostics::get_configuration,
        crate::http::controllers::diagnostics::get_clock,
        crate::http::controllers::config::patch_config,
    ),
    components(schemas(
        SessionInfo,
        ConnectionMode,
        crate::listener::ListenerUrls,
        crate::config::DataEncoding,
        crate::config::PubKeyFormat,
        crate::http::controllers::config::SubProvisionerKey,
        crate::http::controllers::config::ConfigPatch,
        crate::http::controllers::diagnostics::ConfigDiagnostic,
        crate::http::controllers::diagnostics::ClockDiagnostic,
    ))
)]
pub struct ApiDoc;

#[allow(dead_code)]
#[derive(utoipa::ToSchema)]
pub struct SessionInfo {
    association_id: Uuid,
    application_protocol: String,
    recording_policy: bool,
    filtering_policy: bool,
    start_timestamp: DateTime<Utc>,
    connection_mode: ConnectionMode,
    destination_host: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionMode {
    Rdv,
    Fwd,
}
