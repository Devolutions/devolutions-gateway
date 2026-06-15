//! HTTP server for the UniGetUI package broker.
//!
//! Built on `axum` + `aide`, served over a Windows named pipe (or TCP in dev).
//! The same router drives both request handling and OpenAPI generation.
//!
//! Routes:
//! - `GET /v1/health` — readiness check
//! - `GET /v1/capabilities` — supported features
//! - `POST /v1/package-operations/evaluate` — evaluate policy (dry-run)
//! - `POST /v1/package-operations/execute` — evaluate and execute
//! - `POST /v1/package-operations/status` — query an operation's status

use std::sync::{Arc, RwLock};

use aide::axum::ApiRouter;
use aide::axum::routing::{get_with, post_with};
use aide::openapi::OpenApi;
use aide::transform::TransformOperation;
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, Utc};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::command_builder::build_command;
use crate::evaluator;
use crate::executor::CommandExecutor;
use crate::model::{
    BrokerInfo, BrokerResponse, CapabilitiesResponse, Decision, ErrorResponse, ExecutionInfo, ExecutionMode,
    HealthResponse, HealthStatus, ManagerName, Operation, OperationStatus, PackageRequest, PolicyDocument,
    ProtocolVersion, ResourceId, ResponsePolicyInfo, RuleId, StatusRequest, StatusResponse, Transport,
};
use crate::operation_tracker::OperationTracker;

const PROTOCOL_VERSION_STR: &str = "1.0";

const RESPONSE_MEDIA_TYPE: &str = "application/vnd.unigetui.package-broker-response+json; version=1.0";

const STATUS_RESPONSE_MEDIA_TYPE: &str = "application/vnd.unigetui.package-operation-status-response+json; version=1.0";

const MAX_REQUEST_BODY_BYTES: usize = 256 * 1024; // 256 KiB per spec.

const ACCEPTED_CONTENT_TYPES: &[&str] = &[
    "application/vnd.unigetui.package-request+json; version=1.0",
    "application/json",
];

const BROKER_NAME: &str = "Devolutions Agent UniGetUI Broker";

/// Shared server state.
pub struct BrokerState {
    /// Current policy. `None` means the broker is paused (policy file missing or corrupted).
    pub policy: RwLock<Option<Arc<PolicyDocument>>>,
    pub executor: Box<dyn CommandExecutor>,
    pub pipe_name: String,
    pub tracker: OperationTracker,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Router and transport
// ═══════════════════════════════════════════════════════════════════════════════

/// Build the broker's API router (state not yet applied).
///
/// Used both to serve requests (via [`build_router`]) and to generate the OpenAPI
/// document (via [`openapi`]).
pub fn api_router() -> ApiRouter<Arc<BrokerState>> {
    ApiRouter::new()
        .api_route("/v1/health", get_with(handle_health, health_docs))
        .api_route("/v1/capabilities", get_with(handle_capabilities, capabilities_docs))
        .api_route(
            "/v1/package-operations/evaluate",
            post_with(handle_evaluate_dryrun, evaluate_docs),
        )
        .api_route(
            "/v1/package-operations/execute",
            post_with(handle_execute, execute_docs),
        )
        .api_route("/v1/package-operations/status", post_with(handle_status, status_docs))
}

/// Build the axum router to serve, with state applied.
pub fn build_router(state: Arc<BrokerState>) -> axum::Router {
    axum::Router::from(api_router().with_state(state))
}

/// Serve one HTTP connection (a named-pipe instance or a TCP stream) using the router.
pub async fn serve_connection<S>(stream: S, router: axum::Router)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tower_service::Service as _;

    let socket = TokioIo::new(stream);

    // Obtain a per-connection service from the router.
    let mut make_service = router.into_make_service();
    let tower_service = match make_service.call(()).await {
        Ok(service) => service,
        Err(infallible) => match infallible {},
    };
    let hyper_service = hyper_util::service::TowerToHyperService::new(tower_service);

    if let Err(error) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .http1()
        .keep_alive(false)
        .serve_connection_with_upgrades(socket, hyper_service)
        .await
    {
        tracing::warn!(error = %error, "Connection error");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// OpenAPI document
// ═══════════════════════════════════════════════════════════════════════════════

/// Build the OpenAPI 3 document for the broker API from the router and schemas.
pub fn openapi() -> OpenApi {
    use aide::openapi::Info;

    let mut api = OpenApi {
        info: Info {
            title: "UniGetUI Package Broker API".to_owned(),
            version: "1.0".to_owned(),
            description: Some(
                "HTTP API exposed by the Devolutions Agent UniGetUI package broker over a Windows named pipe."
                    .to_owned(),
            ),
            ..Info::default()
        },
        ..OpenApi::default()
    };

    aide::generate::in_context(|ctx| {
        ctx.schema = schemars::r#gen::SchemaGenerator::new(schemars::r#gen::SchemaSettings::openapi3());
    });

    let _ = api_router().finish_api(&mut api);

    // The policy document is admin-authored config, not an API payload, so it is not
    // referenced by any route. Register it (and its dependencies) as components anyway
    // so the generated C# client also gets strongly-typed policy models.
    register_policy_schema(&mut api);

    api
}

/// Add `PolicyDocument` and its dependency schemas to the OpenAPI components.
///
/// Uses the same openapi3 schemars settings as the route schemas, so shared
/// definitions (e.g. `ResourceId`, `Decision`) are byte-identical and de-duplicated.
fn register_policy_schema(api: &mut OpenApi) {
    use aide::openapi::{Components, SchemaObject};
    use schemars::schema::Schema;

    let generator = schemars::r#gen::SchemaGenerator::new(schemars::r#gen::SchemaSettings::openapi3());
    let root = generator.into_root_schema_for::<PolicyDocument>();

    let components = api.components.get_or_insert_with(Components::default);

    components
        .schemas
        .entry("PolicyDocument".to_owned())
        .or_insert_with(|| SchemaObject {
            json_schema: Schema::Object(root.schema),
            external_docs: None,
            example: None,
        });

    for (name, schema) in root.definitions {
        components.schemas.entry(name).or_insert_with(|| SchemaObject {
            json_schema: schema,
            external_docs: None,
            example: None,
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════════════════════

async fn handle_health(State(state): State<Arc<BrokerState>>) -> Json<HealthResponse> {
    let policy_guard = state.policy.read().expect("policy lock poisoned");
    let status = if policy_guard.is_some() {
        HealthStatus::Ready
    } else {
        HealthStatus::Paused
    };
    let policy_id = policy_guard
        .as_ref()
        .map(|p| p.metadata.id.to_string())
        .unwrap_or_default();

    Json(HealthResponse {
        status,
        protocol_version: ProtocolVersion::from(PROTOCOL_VERSION_STR),
        elevated_simulation: false,
        policy_id,
        endpoints: vec![
            "GET /v1/health".to_owned(),
            "GET /v1/capabilities".to_owned(),
            "POST /v1/package-operations/evaluate".to_owned(),
            "POST /v1/package-operations/execute".to_owned(),
            "POST /v1/package-operations/status".to_owned(),
        ],
    })
}

async fn handle_capabilities(State(state): State<Arc<BrokerState>>) -> Json<CapabilitiesResponse> {
    Json(CapabilitiesResponse {
        protocol_version: ProtocolVersion::from(PROTOCOL_VERSION_STR),
        transports: vec![Transport::HttpNamedPipe],
        request_media_types: ACCEPTED_CONTENT_TYPES.iter().map(|&s| s.to_owned()).collect(),
        response_media_types: vec![RESPONSE_MEDIA_TYPE.to_owned()],
        supported_managers: vec![ManagerName::Winget, ManagerName::PowerShell, ManagerName::PowerShell7],
        supported_operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
        max_request_body_bytes: MAX_REQUEST_BODY_BYTES as u64,
        pipe_name: state.pipe_name.clone(),
    })
}

async fn handle_evaluate_dryrun(State(state): State<Arc<BrokerState>>, headers: HeaderMap, body: Bytes) -> Response {
    evaluate(state, &headers, &body, false)
}

async fn handle_execute(State(state): State<Arc<BrokerState>>, headers: HeaderMap, body: Bytes) -> Response {
    evaluate(state, &headers, &body, true)
}

/// Shared evaluate/execute logic for both package-operation endpoints.
fn evaluate(state: Arc<BrokerState>, headers: &HeaderMap, body_bytes: &Bytes, execute: bool) -> Response {
    let audit_id = generate_audit_id();
    let received_at = Utc::now();

    // Acquire policy; return 503 if broker is paused.
    let policy = {
        let guard = state.policy.read().expect("policy lock poisoned");
        match guard.as_ref() {
            Some(p) => Arc::clone(p),
            None => return service_unavailable(&audit_id),
        }
    };

    // Fail closed if the policy is outside its validity window (not yet active or expired).
    if let Some(reason) = policy_validity_failure(&policy, received_at) {
        tracing::warn!(%audit_id, %reason, "Rejecting request: policy outside validity window");
        return make_error_response(
            &policy,
            &audit_id,
            received_at,
            &reason,
            StatusCode::FORBIDDEN,
            &state.pipe_name,
        );
    }

    // Validate required protocol headers per wire protocol spec.
    if let Some(err_response) = validate_request_headers(headers, &policy, &audit_id, received_at, &state.pipe_name) {
        return err_response;
    }

    // Extract header request-id for cross-check with the body.
    let header_request_id = headers
        .get("UniGetUI-Request-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    if body_bytes.is_empty() {
        return make_error_response(
            &policy,
            &audit_id,
            received_at,
            "request body is required",
            StatusCode::BAD_REQUEST,
            &state.pipe_name,
        );
    }

    if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
        return make_error_response(
            &policy,
            &audit_id,
            received_at,
            &format!(
                "request body exceeds maximum size ({} bytes > {} bytes)",
                body_bytes.len(),
                MAX_REQUEST_BODY_BYTES
            ),
            StatusCode::BAD_REQUEST,
            &state.pipe_name,
        );
    }

    // Deserialize and validate the request (validation happens in custom Deserialize impls).
    let request: PackageRequest = match serde_json::from_slice(body_bytes) {
        Ok(req) => req,
        Err(error) => {
            return make_error_response(
                &policy,
                &audit_id,
                received_at,
                &format!("invalid request: {error}"),
                StatusCode::UNPROCESSABLE_ENTITY,
                &state.pipe_name,
            );
        }
    };

    // Validate UniGetUI-Request-Id header matches body requestId (spec requirement).
    if let Some(header_val) = &header_request_id
        && header_val != &*request.request_id
    {
        return make_error_response(
            &policy,
            &audit_id,
            received_at,
            &format!(
                "UniGetUI-Request-Id header '{}' does not match body requestId '{}'",
                header_val, &*request.request_id
            ),
            StatusCode::BAD_REQUEST,
            &state.pipe_name,
        );
    }

    tracing::trace!(
        %audit_id,
        operation = %request.operation,
        manager = %request.manager.name,
        package_id = %*request.package.id,
        request_id = %*request.request_id,
        "Evaluating policy for request",
    );

    // Evaluate policy.
    let decision = evaluator::evaluate(&policy, &request);

    // Audit mode observes but does not enforce: the broker logs the real decision
    // and reports `Allow` so the client proceeds.
    let audit_mode = policy.enforcement.audit_mode == Some(true);
    if audit_mode {
        tracing::info!(
            %audit_id,
            real_decision = %decision.decision,
            rule_id = %decision.rule_id,
            "Audit mode enabled; decision is not enforced",
        );
    }

    let effective_decision = if audit_mode { Decision::Allow } else { decision.decision };

    let reason = if audit_mode && decision.decision != Decision::Allow {
        format!(
            "[Audit mode] Not enforced. Policy decision was {} (rule '{}'): {}",
            decision.decision, decision.rule_id, decision.reason
        )
    } else {
        decision.reason.clone()
    };

    let (command, would_execute) = if effective_decision == Decision::Allow {
        let cmd = build_command(&request);
        (cmd, true)
    } else {
        (vec![], false)
    };

    // If execute mode and decision is allow, spawn background execution.
    let (execution_mode, note) = if execute && would_execute {
        let ctx = crate::executor::ExecutionContext {
            kill_processes: request
                .options
                .kill_before_operation
                .iter()
                .map(|p| p.0.clone())
                .collect(),
            pre_command: request.options.pre_operation_command.clone(),
            command: command.clone(),
            post_command: request.options.post_operation_command.clone(),
            effective_user: request.broker.effective_user.clone(),
            elevation: request.broker.requested_elevation,
            scope: request.options.scope,
            capture_output: request.capture_output,
        };

        // Register the operation and spawn execution in background.
        let request_id_str = request.request_id.to_string();
        state.tracker.register(&request.request_id);
        state.tracker.mark_running(&request_id_str);

        // Spawn background task to wait for process completion.
        // The response is returned immediately; clients poll /status for result.
        let bg_state = Arc::clone(&state);
        let exe_name = ctx.command.first().cloned().unwrap_or_else(|| "process".to_owned());
        tokio::spawn(async move {
            let timeout = OperationTracker::operation_timeout();
            match tokio::time::timeout(timeout, bg_state.executor.execute(&ctx)).await {
                Ok(Ok(output)) => {
                    let stdout = (!output.stdout.is_empty()).then(|| output.stdout.clone());
                    // For non-zero exits, the note is a short error summary (e.g. winget HRESULT
                    // codes); for success it is a plain confirmation.
                    let note = if output.exit_code == 0 {
                        "Process exited successfully.".to_owned()
                    } else {
                        #[allow(clippy::cast_sign_loss)]
                        let unsigned = output.exit_code as u32;
                        match crate::executor::describe_exit_code(output.exit_code) {
                            Some(description) => format!(
                                "{exe_name} exited with code {} (0x{unsigned:08X}): {description}",
                                output.exit_code
                            ),
                            None => format!("{exe_name} exited with code {} (0x{unsigned:08X})", output.exit_code),
                        }
                    };
                    tracing::info!(
                        request_id = %request_id_str,
                        exit_code = output.exit_code,
                        "Background execution completed"
                    );
                    bg_state
                        .tracker
                        .mark_completed(&request_id_str, output.exit_code, note, stdout);
                }
                Ok(Err(error)) => {
                    // Launch failures carry the underlying WinAPI error description.
                    let note = format!("{error:#}");
                    tracing::error!(request_id = %request_id_str, %error, "Background execution failed");
                    bg_state.tracker.mark_failed(&request_id_str, note, None);
                }
                Err(_elapsed) => {
                    let note = format!("Operation timed out after {} seconds.", timeout.as_secs());
                    tracing::error!(
                        request_id = %request_id_str,
                        timeout_secs = timeout.as_secs(),
                        "Background execution timed out"
                    );
                    bg_state.tracker.mark_failed(&request_id_str, note, None);
                }
            }
        });

        (
            ExecutionMode::Elevated,
            "Operation submitted for execution. Poll /v1/package-operations/status for result.".to_owned(),
        )
    } else if execute {
        (ExecutionMode::Elevated, "Denied by policy.".to_owned())
    } else {
        (
            ExecutionMode::SimulatedElevated,
            "Dry-run: command not executed.".to_owned(),
        )
    };

    let completed_at = Utc::now();

    let response = BrokerResponse {
        broker: BrokerInfo {
            name: BROKER_NAME.to_owned(),
            protocol_version: ProtocolVersion::from(PROTOCOL_VERSION_STR),
            transport: Transport::HttpNamedPipe,
            pipe_name: Some(state.pipe_name.clone()),
            elevated_simulation: !execute,
        },
        audit_id: ResourceId::from(audit_id.clone()),
        request_id: request.request_id.clone(),
        received_at,
        completed_at,
        manager: Some(request.manager.name.to_string()),
        source: Some(request.source.name.clone()),
        package_id: Some(request.package.id.clone()),
        operation: Some(request.operation),
        decision: effective_decision,
        rule_id: RuleId::from(decision.rule_id),
        reason,
        would_execute,
        policy: ResponsePolicyInfo {
            id: policy.metadata.id.clone(),
            revision: policy.metadata.revision,
            policy_version: policy.policy_version.clone(),
        },
        execution: ExecutionInfo {
            mode: execution_mode,
            command: command.into_iter().map(crate::model::CommandString).collect(),
            note,
        },
    };

    let status = if effective_decision == Decision::Allow {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };

    let body = serde_json::to_vec_pretty(&response).expect("BUG: BrokerResponse serialization");
    Response::builder()
        .status(status)
        .header("Content-Type", RESPONSE_MEDIA_TYPE)
        .header("UniGetUI-Protocol-Version", PROTOCOL_VERSION_STR)
        .header("UniGetUI-Audit-Id", &audit_id)
        .header("UniGetUI-Policy-Id", &*policy.metadata.id)
        .header("UniGetUI-Policy-Revision", policy.metadata.revision.to_string())
        .body(Body::from(body))
        .expect("BUG: response builder with valid status and ASCII headers")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Status endpoint
// ═══════════════════════════════════════════════════════════════════════════════

async fn handle_status(State(state): State<Arc<BrokerState>>, body: Bytes) -> Response {
    if body.is_empty() {
        return json_error_response(StatusCode::BAD_REQUEST, "request body is required");
    }

    // Deserialize the status request.
    let status_req: StatusRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(error) => {
            return json_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("invalid status request: {error}"),
            );
        }
    };

    // Look up the tracked operation.
    let tracked = state.tracker.get(&status_req.request_id);

    let broker_info = || BrokerInfo {
        name: BROKER_NAME.to_owned(),
        protocol_version: ProtocolVersion::from(PROTOCOL_VERSION_STR),
        transport: Transport::HttpNamedPipe,
        pipe_name: Some(state.pipe_name.clone()),
        elevated_simulation: false,
    };

    let (status_code, response) = match tracked {
        Some(op) => (
            StatusCode::OK,
            StatusResponse {
                broker: broker_info(),
                request_id: status_req.request_id,
                status: op.status,
                started_at: op.started_at,
                completed_at: op.completed_at,
                exit_code: op.exit_code,
                note: op.note,
                stdout: op.stdout,
            },
        ),
        None => (
            // Operation not found — either it never existed or it was evicted.
            StatusCode::NOT_FOUND,
            StatusResponse {
                broker: broker_info(),
                request_id: status_req.request_id,
                status: OperationStatus::Failed,
                started_at: None,
                completed_at: None,
                exit_code: None,
                note: Some("Operation not found (never submitted or already evicted).".to_owned()),
                stdout: None,
            },
        ),
    };

    let body = serde_json::to_vec_pretty(&response).expect("BUG: StatusResponse serialization");
    Response::builder()
        .status(status_code)
        .header("Content-Type", STATUS_RESPONSE_MEDIA_TYPE)
        .header("UniGetUI-Protocol-Version", PROTOCOL_VERSION_STR)
        .body(Body::from(body))
        .expect("BUG: response builder with valid status and ASCII headers")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn json_error_response(status: StatusCode, message: &str) -> Response {
    let body = ErrorResponse {
        error: message.to_owned(),
        reason: None,
        audit_id: None,
    };
    let bytes = serde_json::to_vec_pretty(&body).expect("BUG: ErrorResponse serialization");
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(bytes))
        .expect("BUG: response builder with valid status")
}

/// Validate required request headers per the wire protocol specification.
///
/// Returns `Some(response)` if validation fails, `None` if all checks pass.
fn validate_request_headers(
    headers: &HeaderMap,
    policy: &PolicyDocument,
    audit_id: &str,
    received_at: DateTime<Utc>,
    pipe_name: &str,
) -> Option<Response> {
    // UniGetUI-Protocol-Version header is required.
    let proto_version = headers.get("UniGetUI-Protocol-Version");
    match proto_version.and_then(|v| v.to_str().ok()) {
        Some("1.0") => {}
        Some(other) => {
            return Some(make_error_response(
                policy,
                audit_id,
                received_at,
                &format!("unsupported protocol version '{other}', expected '1.0'"),
                StatusCode::BAD_REQUEST,
                pipe_name,
            ));
        }
        None => {
            return Some(make_error_response(
                policy,
                audit_id,
                received_at,
                "missing required header: UniGetUI-Protocol-Version",
                StatusCode::BAD_REQUEST,
                pipe_name,
            ));
        }
    }

    // UniGetUI-Request-Id header is required.
    if headers.get("UniGetUI-Request-Id").is_none() {
        return Some(make_error_response(
            policy,
            audit_id,
            received_at,
            "missing required header: UniGetUI-Request-Id",
            StatusCode::BAD_REQUEST,
            pipe_name,
        ));
    }

    // Content-Type must be an accepted type.
    let content_type = headers.get(axum::http::header::CONTENT_TYPE);
    match content_type.and_then(|v| v.to_str().ok()) {
        Some(ct) => {
            let ct_lower = ct.to_lowercase();
            if !ACCEPTED_CONTENT_TYPES
                .iter()
                .any(|accepted| ct_lower.starts_with(accepted))
            {
                return Some(make_error_response(
                    policy,
                    audit_id,
                    received_at,
                    &format!("unsupported Content-Type: '{ct}'"),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    pipe_name,
                ));
            }
        }
        None => {
            return Some(make_error_response(
                policy,
                audit_id,
                received_at,
                "missing required header: Content-Type",
                StatusCode::BAD_REQUEST,
                pipe_name,
            ));
        }
    }

    None
}

/// Return a deny reason if the policy is outside its validity window at `now`,
/// or `None` if the policy is currently active. Brokers fail closed: a policy that
/// is not yet active or has expired denies all requests.
fn policy_validity_failure(policy: &PolicyDocument, now: DateTime<Utc>) -> Option<String> {
    if let Some(valid_from) = policy.metadata.valid_from
        && now < valid_from
    {
        return Some(format!("policy is not active until {valid_from} (current time {now})"));
    }
    if let Some(valid_until) = policy.metadata.valid_until
        && now > valid_until
    {
        return Some(format!("policy expired at {valid_until} (current time {now})"));
    }
    None
}

fn make_error_response(
    policy: &PolicyDocument,
    audit_id: &str,
    received_at: DateTime<Utc>,
    reason: &str,
    status: StatusCode,
    pipe_name: &str,
) -> Response {
    let completed_at = Utc::now();
    let response = BrokerResponse {
        broker: BrokerInfo {
            name: BROKER_NAME.to_owned(),
            protocol_version: ProtocolVersion::from(PROTOCOL_VERSION_STR),
            transport: Transport::HttpNamedPipe,
            pipe_name: Some(pipe_name.to_owned()),
            elevated_simulation: false,
        },
        audit_id: ResourceId::from(audit_id),
        request_id: ResourceId::from("unknown"),
        received_at,
        completed_at,
        manager: None,
        source: None,
        package_id: None,
        operation: None,
        decision: Decision::Deny,
        rule_id: RuleId::from("<validation-failure>"),
        reason: reason.to_owned(),
        would_execute: false,
        policy: ResponsePolicyInfo {
            id: policy.metadata.id.clone(),
            revision: policy.metadata.revision,
            policy_version: policy.policy_version.clone(),
        },
        execution: ExecutionInfo {
            mode: ExecutionMode::SimulatedElevated,
            command: vec![],
            note: "Validation failed; no command built.".to_owned(),
        },
    };

    let body = serde_json::to_vec_pretty(&response).expect("BUG: BrokerResponse serialization");
    Response::builder()
        .status(status)
        .header("Content-Type", RESPONSE_MEDIA_TYPE)
        .header("UniGetUI-Protocol-Version", PROTOCOL_VERSION_STR)
        .header("UniGetUI-Audit-Id", audit_id)
        .header("UniGetUI-Policy-Id", &*policy.metadata.id)
        .header("UniGetUI-Policy-Revision", policy.metadata.revision.to_string())
        .body(Body::from(body))
        .expect("BUG: response builder with valid status and ASCII headers")
}

fn service_unavailable(audit_id: &str) -> Response {
    let body = ErrorResponse {
        error: "broker paused".to_owned(),
        reason: Some("policy file is unavailable or corrupted; waiting for a valid policy".to_owned()),
        audit_id: Some(audit_id.to_owned()),
    };
    let bytes = serde_json::to_vec_pretty(&body).expect("BUG: ErrorResponse serialization");
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "application/json")
        .header("Retry-After", "5")
        .body(Body::from(bytes))
        .expect("BUG: static response builder")
}

fn generate_audit_id() -> String {
    format!("audit-{}", uuid::Uuid::new_v4())
}

// ═══════════════════════════════════════════════════════════════════════════════
// OpenAPI operation docs
// ═══════════════════════════════════════════════════════════════════════════════

fn health_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.summary("Health check")
        .description("Reports whether the broker is ready or paused (policy unavailable).")
        .response::<200, Json<HealthResponse>>()
}

fn capabilities_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.summary("Broker capabilities")
        .description("Lists supported transports, media types, managers, and operations.")
        .response::<200, Json<CapabilitiesResponse>>()
}

fn evaluate_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.summary("Evaluate a package operation (dry-run)")
        .description("Evaluates a package request against the active policy without executing anything.")
        .input::<Json<PackageRequest>>()
        .response::<200, Json<BrokerResponse>>()
        .response::<400, Json<BrokerResponse>>()
        .response::<403, Json<BrokerResponse>>()
        .response::<415, Json<BrokerResponse>>()
        .response::<422, Json<BrokerResponse>>()
        .response::<503, Json<ErrorResponse>>()
}

fn execute_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.summary("Evaluate and execute a package operation")
        .description(
            "Evaluates a package request and, if allowed, submits it for elevated background execution. \
             Poll the status endpoint for the result.",
        )
        .input::<Json<PackageRequest>>()
        .response::<200, Json<BrokerResponse>>()
        .response::<400, Json<BrokerResponse>>()
        .response::<403, Json<BrokerResponse>>()
        .response::<415, Json<BrokerResponse>>()
        .response::<422, Json<BrokerResponse>>()
        .response::<503, Json<ErrorResponse>>()
}

fn status_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    op.summary("Query operation status")
        .description("Returns the current status of a previously submitted package operation.")
        .input::<Json<StatusRequest>>()
        .response::<200, Json<StatusResponse>>()
        .response::<400, Json<ErrorResponse>>()
        .response::<404, Json<StatusResponse>>()
        .response::<422, Json<ErrorResponse>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_has_expected_paths_and_components() {
        let api = openapi();

        let paths = api.paths.expect("OpenAPI should have paths");
        for expected in [
            "/v1/health",
            "/v1/capabilities",
            "/v1/package-operations/evaluate",
            "/v1/package-operations/execute",
            "/v1/package-operations/status",
        ] {
            assert!(paths.paths.contains_key(expected), "missing OpenAPI path: {expected}");
        }

        let components = api.components.expect("OpenAPI should have components");
        for expected in [
            "PackageRequest",
            "BrokerResponse",
            "StatusRequest",
            "StatusResponse",
            "PolicyDocument",
            "HealthResponse",
            "CapabilitiesResponse",
            "ErrorResponse",
        ] {
            assert!(
                components.schemas.contains_key(expected),
                "missing OpenAPI component schema: {expected}"
            );
        }
    }
}
