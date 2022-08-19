use chrono::{DateTime, Utc};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
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
        crate::http::controllers::jrl::update_jrl,
        crate::http::controllers::jrl::get_jrl_info,
    ),
    components(schemas(
        SessionInfo,
        ConnectionMode,
        crate::listener::ListenerUrls,
        crate::config::dto::DataEncoding,
        crate::config::dto::PubKeyFormat,
        crate::config::dto::Subscriber,
        crate::http::controllers::diagnostics::ConfigDiagnostic,
        crate::http::controllers::diagnostics::ClockDiagnostic,
        crate::http::controllers::config::SubProvisionerKey,
        crate::http::controllers::config::ConfigPatch,
        crate::http::controllers::jrl::JrlInfo,
    )),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

#[allow(dead_code)]
#[derive(utoipa::ToSchema)]
struct SessionInfo {
    association_id: Uuid,
    application_protocol: String,
    recording_policy: bool,
    filtering_policy: bool,
    start_timestamp: DateTime<Utc>,
    connection_mode: ConnectionMode,
    destination_host: Option<String>,
}

#[allow(unused)]
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "kebab-case")]
enum ConnectionMode {
    Rdv,
    Fwd,
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // we can unwrap safely since there already is components registered.
        let components = openapi.components.as_mut().unwrap();

        components.add_security_scheme(
            "scope_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Token allowing a single HTTP request for a specific scope".to_owned(),
                    ))
                    .build(),
            ),
        );

        components.add_security_scheme(
            "jrl_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("Contains the JRL to apply if newer".to_owned()))
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(crate::subscriber::post_subscriber_message),
    components(schemas(SubscriberMessage, SubscriberSessionInfo, SubscriberMessageKind)),
    modifiers(&SubscriberSecurityAddon),
)]
pub struct SubscriberApiDoc;

#[derive(utoipa::ToSchema, Serialize)]
struct SubscriberSessionInfo {
    association_id: Uuid,
    start_timestamp: DateTime<Utc>,
}

#[allow(unused)]
#[derive(utoipa::ToSchema, Serialize)]
enum SubscriberMessageKind {
    #[serde(rename = "session.started")]
    SessionStarted,
    #[serde(rename = "session.ended")]
    SessionEnded,
    #[serde(rename = "session.list")]
    SessionList,
}

#[derive(utoipa::ToSchema, Serialize)]
#[serde(tag = "kind")]
struct SubscriberMessage {
    kind: SubscriberMessageKind,
    session: Option<SubscriberSessionInfo>,
    session_list: Option<Vec<SubscriberSessionInfo>>,
}

struct SubscriberSecurityAddon;

impl Modify for SubscriberSecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // we can unwrap safely since there already is components registered.
        openapi.components.as_mut().unwrap().add_security_scheme(
            "subscriber_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("Token allowing to push messages".to_owned()))
                    .build(),
            ),
        );
    }
}
