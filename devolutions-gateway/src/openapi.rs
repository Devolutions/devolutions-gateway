use chrono::{DateTime, Utc};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use uuid::Uuid;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::http::controllers::health::get_health,
        crate::http::controllers::heartbeat::get_heartbeat,
        crate::http::controllers::sessions::get_sessions,
        crate::http::controllers::session::terminate_session,
        crate::http::controllers::diagnostics::get_logs,
        crate::http::controllers::diagnostics::get_configuration,
        crate::http::controllers::diagnostics::get_clock,
        crate::http::controllers::config::patch_config,
        crate::http::controllers::jrl::update_jrl,
        crate::http::controllers::jrl::get_jrl_info,
        crate::http::controllers::jrec::list_recordings,
        crate::http::controllers::jrec::pull_recording_file,
    ),
    components(schemas(
        crate::http::controllers::health::Identity,
        crate::http::controllers::heartbeat::Heartbeat,
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
        crate::token::AccessScope,
    )),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

/// Information about an ongoing Gateway session
#[allow(dead_code)]
#[derive(utoipa::ToSchema)]
struct SessionInfo {
    /// Unique ID for this session
    association_id: Uuid,
    /// Protocol used during this session
    application_protocol: String,
    /// Recording Policy
    recording_policy: bool,
    /// Filtering Policy
    filtering_policy: bool,
    /// Date this session was started
    start_timestamp: DateTime<Utc>,
    /// Maximum session duration in minutes (0 is used for the infinite duration)
    // NOTE: Optional purely for client code generation (this field didn't always exist)
    time_to_live: Option<u64>,
    /// Jet Connection Mode
    connection_mode: ConnectionMode,
    /// Destination Host
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
    paths(post_subscriber_message),
    components(schemas(SubscriberMessage, SubscriberSessionInfo, SubscriberMessageKind)),
    modifiers(&SubscriberSecurityAddon),
)]
pub struct SubscriberApiDoc;

#[derive(utoipa::ToSchema, Serialize)]
struct SubscriberSessionInfo {
    association_id: Uuid,
    start_timestamp: DateTime<Utc>,
}

/// Event type for messages
#[allow(unused)]
#[derive(utoipa::ToSchema, Serialize)]
#[allow(clippy::enum_variant_names)]
enum SubscriberMessageKind {
    /// A new session started
    #[serde(rename = "session.started")]
    SessionStarted,
    /// A session terminated
    #[serde(rename = "session.ended")]
    SessionEnded,
    /// Periodic running session listing
    #[serde(rename = "session.list")]
    SessionList,
}

/// Message produced on various Gateway events
#[derive(utoipa::ToSchema, Serialize)]
#[serde(tag = "kind")]
struct SubscriberMessage {
    /// Name of the event type associated to this message
    ///
    /// Presence or absence of additionnal fields depends on the value of this field.
    kind: SubscriberMessageKind,
    /// Date and time this message was produced
    timestamp: DateTime<Utc>,
    /// Session information associated to this event
    session: Option<SubscriberSessionInfo>,
    /// Session list associated to this event
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

/// Process a message originating from a Devolutions Gateway instance
#[allow(unused)]
#[utoipa::path(
    post,
    operation_id = "PostMessage",
    tag = "Subscriber",
    path = "/dgw/subscriber",
    request_body(content = SubscriberMessage, description = "Message", content_type = "application/json"),
    responses(
        (status = 200, description = "Message received and processed successfully"),
        (status = 400, description = "Bad message"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Gateway Subscriber not found"),
    ),
    security(("subscriber_token" = [])),
)]
fn post_subscriber_message() {}
