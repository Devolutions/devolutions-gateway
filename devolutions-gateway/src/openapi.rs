use time::OffsetDateTime;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use uuid::Uuid;

use crate::api::preflight::PreflightAlertStatus;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::health::get_health,
        crate::api::heartbeat::get_heartbeat,
        crate::api::sessions::get_sessions,
        crate::api::session::terminate_session,
        crate::api::diagnostics::get_logs,
        crate::api::diagnostics::get_configuration,
        crate::api::diagnostics::get_clock,
        crate::api::config::patch_config,
        crate::api::jrl::update_jrl,
        crate::api::jrl::get_jrl_info,
        crate::api::jrec::jrec_delete,
        crate::api::jrec::jrec_delete_many,
        crate::api::jrec::list_recordings,
        crate::api::jrec::pull_recording_file,
        crate::api::webapp::sign_app_token,
        crate::api::webapp::sign_session_token,
        crate::api::update::trigger_update_check,
        crate::api::preflight::post_preflight,
        crate::api::net::get_net_config,
        crate::api::monitoring::handle_set_monitoring_config,
        crate::api::monitoring::handle_drain_log,
        crate::api::traffic::post_traffic_claim,
        crate::api::traffic::post_traffic_ack,
    ),
    components(schemas(
        crate::api::health::Identity,
        crate::api::heartbeat::Heartbeat,
        SessionInfo,
        ConnectionMode,
        crate::listener::ListenerUrls,
        crate::config::dto::DataEncoding,
        crate::config::dto::PubKeyFormat,
        crate::config::dto::Subscriber,
        crate::api::diagnostics::ConfigDiagnostic,
        crate::api::diagnostics::ClockDiagnostic,
        SubProvisionerKey,
        ConfigPatch,
        crate::api::jrl::JrlInfo,
        crate::api::jrec::DeleteManyResult,
        crate::token::AccessScope,
        crate::api::webapp::AppTokenSignRequest,
        crate::api::webapp::AppTokenContentType,
        crate::api::update::UpdateResponse,
        PreflightOperation,
        PreflightOperationKind,
        AppCredential,
        AppCredentialKind,
        PreflightOutput,
        PreflightOutputKind,
        PreflightAlertStatus,
        SessionTokenContentType,
        SessionTokenSignRequest,
        InterfaceInfo,
        AddressFamily,
        crate::api::monitoring::MonitoringLogResponse,
        crate::api::monitoring::MonitorResult,
        crate::api::monitoring::MonitorsConfig,
        crate::api::monitoring::MonitorDefinition,
        crate::api::monitoring::MonitoringProbeType,
        crate::api::monitoring::MonitorDefinitionProbeTypeError,
        crate::api::traffic::ClaimedTrafficEvent,
        crate::api::traffic::AckRequest,
        crate::api::traffic::AckResponse,
        crate::api::traffic::TrafficEventResponse,
        crate::api::traffic::EventOutcomeResponse,
        crate::api::traffic::TransportProtocolResponse,
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
    start_timestamp: OffsetDateTime,
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
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);

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

        components.add_security_scheme(
            "jrec_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Token allowing recording retrieval for a specific session ID".to_owned(),
                    ))
                    .build(),
            ),
        );

        components.add_security_scheme(
            "web_app_custom_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Basic)
                    .description(Some(
                        "Custom authentication method for the standalone web application".to_owned(),
                    ))
                    .build(),
            ),
        );

        components.add_security_scheme(
            "web_app_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Token allowing usage of the standalone web application".to_owned(),
                    ))
                    .build(),
            ),
        );

        components.add_security_scheme(
            "netscan_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Token allowing usage of the network exploration endpoints".to_owned(),
                    ))
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
    #[serde(with = "time::serde::rfc3339")]
    start_timestamp: OffsetDateTime,
}

/// Event type for messages.
#[allow(unused)]
#[derive(utoipa::ToSchema, Serialize)]
#[allow(clippy::enum_variant_names)]
enum SubscriberMessageKind {
    /// A new session started.
    #[serde(rename = "session.started")]
    SessionStarted,
    /// A session terminated.
    #[serde(rename = "session.ended")]
    SessionEnded,
    /// Periodic running session listing.
    #[serde(rename = "session.list")]
    SessionList,
}

/// Message produced on various Gateway events.
#[derive(utoipa::ToSchema, Serialize)]
struct SubscriberMessage {
    /// Name of the event type associated to this message.
    ///
    /// Presence or absence of additionnal fields depends on the value of this field.
    kind: SubscriberMessageKind,
    /// Date and time this message was produced.
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    /// Session information associated to this event.
    session: Option<SubscriberSessionInfo>,
    /// Session list associated to this event.
    session_list: Option<Vec<SubscriberSessionInfo>>,
}

#[allow(unused)]
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "UPPERCASE")]
enum SessionTokenContentType {
    Association,
    Jmux,
    Kdc,
}

#[derive(Serialize, utoipa::ToSchema)]
struct SessionTokenSignRequest {
    /// The content type for the session token.
    content_type: SessionTokenContentType,
    /// Protocol for the session (e.g.: "rdp").
    protocol: Option<String>,
    /// Destination host.
    destination: Option<String>,
    /// Unique ID for this session.
    session_id: Option<Uuid>,
    /// Kerberos realm.
    ///
    /// E.g.: `ad.it-help.ninja`.
    /// Should be lowercased (actual validation is case-insensitive though).
    krb_realm: Option<String>,
    /// Kerberos KDC address.
    ///
    /// E.g.: `tcp://IT-HELP-DC.ad.it-help.ninja:88`.
    /// Default scheme is `tcp`.
    /// Default port is `88`.
    krb_kdc: Option<String>,
    /// The validity duration in seconds for the session token.
    ///
    /// This value cannot exceed 2 hours.
    lifetime: u64,
}

struct SubscriberSecurityAddon;

impl Modify for SubscriberSecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default)
            .add_security_scheme(
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

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "PascalCase")]
struct ConfigPatch {
    /// This Gateway's unique ID
    id: Option<Uuid>,
    /// The sub provisioner public key (may only be used to verify tokens when establishing a session)
    sub_provisioner_public_key: Option<SubProvisionerKey>,
    /// Subscriber configuration
    subscriber: Option<crate::config::dto::Subscriber>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SubProvisionerKey {
    /// The key ID for this subkey
    id: String,
    /// The binary-to-text-encoded key data
    value: String,
    /// The format used for the key data
    format: Option<crate::config::dto::PubKeyFormat>,
    /// The binary-to-text encoding used for the key data
    encoding: Option<crate::config::dto::DataEncoding>,
}

#[allow(unused)]
#[derive(Deserialize, utoipa::ToSchema)]
struct PreflightOperation {
    /// Unique ID identifying the preflight operation.
    id: Uuid,
    /// The type of preflight operation to perform.
    kind: PreflightOperationKind,
    /// The token to be stored on the proxy-side.
    ///
    /// Required for "provision-token" and "provision-credentials" kinds.
    token: Option<String>,
    /// The credential to use to authorize the client at the proxy-level.
    ///
    /// Required for "provision-credentials" kind.
    proxy_credential: Option<AppCredential>,
    /// The credential to use against the target server.
    ///
    /// Required for "provision-credentials" kind.
    target_credential: Option<AppCredential>,
    /// The hostname to perform DNS resolution on.
    ///
    /// Required for "resolve-host" kind.
    host_to_resolve: Option<String>,
    /// Minimum persistance duration in seconds for the data provisioned via this operation.
    ///
    /// Optional parameter for "provision-token" and "provision-credentials" kinds.
    time_to_live: Option<u32>,
}

#[derive(Deserialize, utoipa::ToSchema)]
enum PreflightOperationKind {
    #[serde(rename = "get-version")]
    GetVersion,
    #[serde(rename = "get-agent-version")]
    GetAgentVersion,
    #[serde(rename = "get-running-session-count")]
    GetRunningSessionCount,
    #[serde(rename = "get-recording-storage-health")]
    GetRecordingStorageHealth,
    #[serde(rename = "provision-token")]
    ProvisionToken,
    #[serde(rename = "provision-credentials")]
    ProvisionCredentials,
    #[serde(rename = "resolve-host")]
    ResolveHost,
}

#[allow(unused)]
#[derive(Deserialize, utoipa::ToSchema)]
struct AppCredential {
    /// The kind of credentials.
    kind: AppCredentialKind,
    /// Username for the credential.
    ///
    /// Required for "username-password" kind.
    username: Option<String>,
    /// Password for the credential.
    ///
    /// Required for "username-password" kind.
    password: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
enum AppCredentialKind {
    #[serde(rename = "username-password")]
    UsernamePassword,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PreflightOutput {
    /// The ID of the preflight operation associated to this result.
    operation_id: Uuid,
    /// The type of preflight result.
    kind: PreflightOutputKind,
    /// Service version.
    ///
    /// Set for "version" kind.
    version: Option<String>,
    /// Agent service version, if installed.
    ///
    /// Set for "agent-version" kind.
    agent_version: Option<String>,
    /// Number of running sessions.
    ///
    /// Set for "running-session-count" kind.
    running_session_count: Option<usize>,
    /// Whether the recording storage is writeable or not.
    ///
    /// Set for "recording-storage-health" kind.
    recording_storage_is_writeable: Option<bool>,
    /// The total space of the disk used to store recordings, in bytes.
    ///
    /// Set for "recording-storage-health" kind.
    recording_storage_total_space: Option<u64>,
    /// The remaining available space to store recordings, in bytes.
    ///
    /// set for "recording-storage-health" kind.
    recording_storage_available_space: Option<u64>,
    /// Hostname that was resolved.
    ///
    /// Set for "resolved-host" kind.
    resolved_host: Option<String>,
    /// Resolved IP addresses.
    ///
    /// Set for "resolved-host" kind.
    resolved_addresses: Option<Vec<String>>,
    /// Alert status.
    ///
    /// Set for "alert" kind.
    alert_status: Option<PreflightAlertStatus>,
    /// Message describing the problem.
    ///
    /// Set for "alert" kind.
    alert_message: Option<String>,
}

#[allow(unused)]
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum PreflightOutputKind {
    #[serde(rename = "version")]
    Version,
    #[serde(rename = "agent-version")]
    AgentVersion,
    #[serde(rename = "running-session-count")]
    RunningSessionCount,
    #[serde(rename = "recording-storage-health")]
    RecordingStorageHealth,
    #[serde(rename = "resolved-host")]
    ResolvedHost,
    #[serde(rename = "alert")]
    Alert,
}

#[derive(Serialize, utoipa::ToSchema)]
struct InterfaceInfo {
    family: AddressFamily,
    address: String,
    broadcast: Option<String>,
    netmask: Option<String>,
    mac: Option<String>,
}

#[allow(unused)]
#[derive(Serialize, utoipa::ToSchema)]
enum AddressFamily {
    #[serde(rename = "IPv4")]
    V4,
    #[serde(rename = "IPv6")]
    V6,
}
