use time::OffsetDateTime;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use uuid::Uuid;

use crate::api::preflight::PreflightAlertStatus;
use crate::config::dto::{DataEncoding, PubKeyFormat, Subscriber};
use crate::provisioner_tasks::Permanent;
use crate::provisioner_tasks::ai::AiProvider;
use crate::provisioner_tasks::recording_ai_analysis::{BadAnswer, Failure, Recoverable};

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
        crate::api::jrec::pull_recording_session,
        crate::api::jrec::pull_recording_file,
        crate::api::jrec::search::search_recordings,
        crate::api::tasks::recording_ai_analysis::start_ai_analysis,
        crate::api::tasks::recording_ai_analysis::get_ai_analysis,
        crate::api::webapp::sign_app_token,
        crate::api::webapp::sign_session_token,
        crate::api::update::get_update_products,
        crate::api::update::trigger_update_check,
        crate::api::update::get_update_schedule,
        crate::api::update::set_update_schedule,
        crate::api::preflight::post_preflight,
        crate::api::net::get_net_config,
        crate::api::net::get_net_interfaces,
        crate::api::net::handle_network_scan,
        crate::api::monitoring::handle_set_monitoring_config,
        crate::api::monitoring::handle_drain_log,
        crate::api::traffic::post_traffic_claim,
        crate::api::traffic::post_traffic_ack,
        crate::api::tunnel::enroll_agent,
        crate::api::tunnel::list_agents,
        crate::api::tunnel::get_agent,
        crate::api::tunnel::delete_agent,
    ),
    components(schemas(
        crate::api::health::Identity,
        crate::api::heartbeat::Heartbeat,
        SessionInfo,
        ConnectionMode,
        crate::listener::ListenerUrls,
        DataEncoding,
        PubKeyFormat,
        Subscriber,
        crate::api::diagnostics::ConfigDiagnostic,
        crate::api::diagnostics::ClockDiagnostic,
        SubProvisionerKey,
        ConfigPatch,
        crate::api::jrl::JrlInfo,
        crate::api::jrec::DeleteManyResult,
        crate::api::jrec::search::RecordingSearchRequest,
        crate::api::jrec::search::RecordingSelection,
        crate::api::jrec::search::StartTimeRange,
        crate::api::jrec::search::RecordingSearchResponse,
        crate::api::jrec::search::RecordingSearchHit,
        crate::api::tasks::recording_ai_analysis::AiAnalysisRequest,
        crate::api::tasks::recording_ai_analysis::AiAnalysisConflict,
        crate::api::tasks::recording_ai_analysis::AiAnalysisConflictCode,
        AiProvider,
        crate::api::tasks::recording_ai_analysis::AiAnalysisTask,
        crate::api::tasks::TaskState,
        AiAnalysisParams,
        AiAnalysisPayload,
        AiAnalysisRunningPayload,
        AiAnalysisSucceededPayload,
        AiAnalysisUsage,
        AiAnalysisFailedPayload,
        AiAnalysisError,
        AiAnalysisErrorKind,
        AiAnalysisBadAnswer,
        AiAnalysisRecoverableError,
        AiAnalysisRecoverableErrorKind,
        crate::token::AccessScope,
        crate::api::webapp::AppTokenSignRequest,
        crate::api::webapp::AppTokenContentType,
        crate::api::update::GetUpdateProductsResponse,
        crate::api::update::UpdateRequestSchema,
        crate::api::update::UpdateProduct,
        crate::api::update::UpdateProductInfo,
        crate::api::update::UpdateResponse,
        crate::api::update::GetUpdateScheduleResponse,
        crate::api::update::SetUpdateScheduleRequest,
        crate::api::update::SetUpdateScheduleResponse,
        PreflightOperation,
        PreflightOperationKind,
        AppCredential,
        AppCredentialKind,
        TargetConnectionOptions,
        PreflightOutput,
        PreflightOutputKind,
        PreflightAlertStatus,
        SessionTokenContentType,
        SessionTokenSignRequest,
        InterfaceInfo,
        AddressFamily,
        crate::api::net::NetworkInterfacesResponse,
        crate::api::net::NetworkScanSourceDto,
        crate::api::net::NetworkInterfaceDto,
        crate::api::net::NetworkScanSourceCapabilitiesDto,
        crate::api::net::NetworkScanResultEventDto,
        crate::api::net::NetworkScanResultKindDto,
        crate::api::net::ScanResultSourceDto,
        crate::api::net::ScanOriginDto,
        crate::api::net::HostScanStateDto,
        crate::api::monitoring::MonitoringLogResponse,
        crate::api::monitoring::MonitorResult,
        crate::api::monitoring::MonitorsConfig,
        crate::api::monitoring::MonitorDefinition,
        crate::api::monitoring::MonitoringProbeType,
        crate::api::monitoring::SetConfigResponse,
        crate::api::monitoring::MonitorDefinitionProbeTypeError,
        crate::api::traffic::ClaimedTrafficEvent,
        crate::api::traffic::AckRequest,
        crate::api::traffic::AckResponse,
        crate::api::traffic::TrafficEventResponse,
        crate::api::traffic::EventOutcomeResponse,
        crate::api::traffic::TransportProtocolResponse,
        crate::api::tunnel::EnrollRequest,
        crate::api::tunnel::EnrollResponse,
        crate::api::tunnel::AgentDomainAdvertisement,
        crate::api::tunnel::AgentStatus,
        crate::api::tunnel::AgentInfo,
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

/// Params of an AI analysis Task: what was asked, without the API key and the base URL
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisParams {
    provider: AiProvider,
    /// Model identifier, passed to the provider as is.
    model: String,
    /// Upper bound of tokens in each AI answer; null when not asked.
    #[schema(value_type = Option<i64>, minimum = 0, maximum = 4_294_967_295_u64)]
    max_output_tokens: Option<u32>,
    /// Language the AI writes in; absent when not asked, so the AI writes in English.
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<String>,
}

/// Details of the state of an AI analysis Task: `running`, `succeeded` and `failed` each have their own
#[derive(Serialize, utoipa::ToSchema)]
#[serde(untagged)]
#[expect(dead_code, reason = "it only describes the payload, which the Task keeps as JSON")]
enum AiAnalysisPayload {
    Running(AiAnalysisRunningPayload),
    Succeeded(AiAnalysisSucceededPayload),
    Failed(AiAnalysisFailedPayload),
}

/// Payload of a `running` AI analysis Task: its progress, and the tokens it used so far
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisRunningPayload {
    /// Current step: `preparing` (the attempt starts), `reading` (the recordings are read), `describing` (the AI is
    /// asked about the recording, part by part), then `writing` (the log is written).
    step: String,
    /// Work done in the step: bytes read while `reading`, parts described while `describing`; absent in the other steps.
    done: Option<u64>,
    /// Work the step has in all, in the same unit as `done`; absent in the other steps.
    total: Option<u64>,
    usage: AiAnalysisUsage,
}

/// Payload of a `succeeded` AI analysis Task: the log it put in the session
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisSucceededPayload {
    /// Name of the log in the session manifest, such as `ai-analysis-0.slog`.
    file_name: String,
    /// Model that wrote the log, as reported by the AI provider; the requested model when it reports none.
    model: String,
    usage: AiAnalysisUsage,
    /// Versions of the prompts that wrote the log, such as
    /// `session-actions-3f9a1c2b7e4d0a51+session-summary-8b20e9a4c1f70d36`.
    prompt_version: String,
}

/// Tokens the AI provider counted for an AI analysis Task, over all its attempts
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisUsage {
    input_tokens: u64,
    output_tokens: u64,
    /// Requests that may have cost tokens the provider did not report, such as a request that got no answer, or one
    /// still waiting for it; while it is not 0, `inputTokens` and `outputTokens` are short of what the provider billed.
    unreported_requests: u64,
}

/// Payload of a `failed` AI analysis Task: why it failed, and the tokens it used
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisFailedPayload {
    error: AiAnalysisError,
    /// Absent only for a Task that never ran before its deadline passed, since it used no token.
    usage: Option<AiAnalysisUsage>,
}

/// Why an AI analysis Task failed: a kind, with the fields of that kind; there is no text for people, so the caller
/// words it
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisError {
    kind: AiAnalysisErrorKind,
    /// HTTP status the AI provider answered, for `aiRejected`.
    status: Option<u16>,
    /// What was wrong with the answer, for `aiBadAnswer`.
    why: Option<AiAnalysisBadAnswer>,
    /// Recording file that cannot be read, for `unreadableRecording`.
    file: Option<String>,
    /// Failure of the last attempt, for `attemptsExhausted`.
    last: Option<AiAnalysisRecoverableError>,
}

/// Kind of failure of an AI analysis Task
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
enum AiAnalysisErrorKind {
    /// The AI provider refused the request for good, such as for a wrong API key (401) or a spent quota.
    AiRejected,
    /// The AI provider answered, but not with something usable.
    AiBadAnswer,
    /// The API key is gone, such as after a Gateway restart.
    KeyLost,
    /// The session has no recording, or it was deleted.
    NoRecording,
    /// The session mixes terminal and video recordings.
    MixedRecording,
    /// A recording file of the session cannot be read.
    UnreadableRecording,
    /// The Task itself is not valid, such as with parameters this Gateway cannot read.
    InvalidTask,
    /// The attempt panicked.
    Panicked,
    /// Something went wrong inside Gateway, such as a file it could not write.
    Internal,
    /// Every attempt failed with a failure worth another attempt.
    AttemptsExhausted,
    /// The Task did not start in time, or went too long without progress.
    DeadlinePassed,
    /// The job of the Task could not be queued.
    NotQueued,
}

/// What was wrong with an answer of the AI provider
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
enum AiAnalysisBadAnswer {
    /// The answer is not in the format of the provider API.
    Invalid,
    /// The answer was cut short by the output token limit or the context window.
    Truncated,
    /// The provider refused to answer, such as when its content filter blocked the request.
    Refused,
    /// The model did not answer in the format it was asked for.
    NotExpectedJson,
}

/// A failure of an attempt that was worth another attempt
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisRecoverableError {
    kind: AiAnalysisRecoverableErrorKind,
    /// HTTP status the AI provider answered, for `aiBusy`.
    status: Option<u16>,
}

/// Kind of a failure worth another attempt
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
enum AiAnalysisRecoverableErrorKind {
    /// The AI provider could not be reached, or did not answer in time.
    AiUnreachable,
    /// The AI provider is busy or failing for now, such as with a rate limit (429) or a server error (5xx).
    AiBusy,
    /// Gateway could not read its own storage, such as the folder of the session.
    Storage,
}

// The error kinds are written out above for their descriptions, which utoipa drops from the variants without fields, so
// these matches stop the build until a new kind or field is written out too.
const _: fn(&Permanent<Failure, Recoverable>) -> AiAnalysisErrorKind = |error| match error {
    Permanent::Kind(Failure::AiRejected { status: _ }) => AiAnalysisErrorKind::AiRejected,
    Permanent::Kind(Failure::AiBadAnswer { why: _ }) => AiAnalysisErrorKind::AiBadAnswer,
    Permanent::Kind(Failure::KeyLost) => AiAnalysisErrorKind::KeyLost,
    Permanent::Kind(Failure::NoRecording) => AiAnalysisErrorKind::NoRecording,
    Permanent::Kind(Failure::MixedRecording) => AiAnalysisErrorKind::MixedRecording,
    Permanent::Kind(Failure::UnreadableRecording { file: _ }) => AiAnalysisErrorKind::UnreadableRecording,
    Permanent::InvalidTask => AiAnalysisErrorKind::InvalidTask,
    Permanent::Panicked => AiAnalysisErrorKind::Panicked,
    Permanent::Internal => AiAnalysisErrorKind::Internal,
    Permanent::AttemptsExhausted { last: _ } => AiAnalysisErrorKind::AttemptsExhausted,
    Permanent::DeadlinePassed => AiAnalysisErrorKind::DeadlinePassed,
    Permanent::NotQueued => AiAnalysisErrorKind::NotQueued,
};

const _: fn(&Recoverable) -> AiAnalysisRecoverableErrorKind = |error| match error {
    Recoverable::AiUnreachable => AiAnalysisRecoverableErrorKind::AiUnreachable,
    Recoverable::AiBusy { status: _ } => AiAnalysisRecoverableErrorKind::AiBusy,
    Recoverable::Storage => AiAnalysisRecoverableErrorKind::Storage,
};

const _: fn(&BadAnswer) -> AiAnalysisBadAnswer = |why| match why {
    BadAnswer::Invalid => AiAnalysisBadAnswer::Invalid,
    BadAnswer::Truncated => AiAnalysisBadAnswer::Truncated,
    BadAnswer::Refused => AiAnalysisBadAnswer::Refused,
    BadAnswer::NotExpectedJson => AiAnalysisBadAnswer::NotExpectedJson,
};

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

        components.add_security_scheme(
            "enrollment_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("Single-use token authorizing Agent Tunnel enrollment".to_owned()))
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
    /// Presence or absence of additional fields depends on the value of this field.
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
    subscriber: Option<Subscriber>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SubProvisionerKey {
    /// The key ID for this subkey
    id: String,
    /// The binary-to-text-encoded key data
    value: String,
    /// The format used for the key data
    format: Option<PubKeyFormat>,
    /// The binary-to-text encoding used for the key data
    encoding: Option<DataEncoding>,
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
    /// Required for "provision-token", "provision-credentials", and
    /// "provision-connection-options" kinds.
    token: Option<String>,
    /// The credential to use to authorize the client at the proxy-level.
    ///
    /// Required for "provision-credentials" kind.
    proxy_credential: Option<AppCredential>,
    /// The credential to use against the target server.
    ///
    /// Required for "provision-credentials" kind.
    target_credential: Option<AppCredential>,
    /// Options used by the Gateway when connecting to the target.
    ///
    /// Required for "provision-connection-options" kind.
    connection_options: Option<TargetConnectionOptions>,
    /// The hostname to perform DNS resolution on.
    ///
    /// Required for "resolve-host" kind.
    host_to_resolve: Option<String>,
    /// Retention duration in seconds for data provisioned by this operation.
    ///
    /// For "provision-credentials", this is the maximum staging time before the first credential
    /// checkout. After checkout, Gateway retains the credentials for later connections authorized
    /// for the same association.
    ///
    /// Optional parameter for "provision-token", "provision-credentials", and
    /// "provision-connection-options" kinds.
    time_to_live: Option<u32>,
}

#[allow(unused)]
#[derive(Deserialize, utoipa::ToSchema)]
struct TargetConnectionOptions {
    /// Kerberos KDC address for the target-side CredSSP connection.
    ///
    /// Format: `<scheme>://<host>:<port>` (port is required). Supported schemes are `tcp` and `udp`.
    krb_kdc: Option<String>,
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
    // Append-only: keep after ResolveHost so generated C# numeric values for existing variants stay stable.
    #[serde(rename = "provision-connection-options")]
    ProvisionConnectionOptions,
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
