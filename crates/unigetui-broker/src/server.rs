//! HTTP server for the UniGetUI package broker.
//!
//! Implements the HTTP-over-named-pipe protocol described in the spec.
//! Routes:
//! - `GET /v1/health` — readiness check
//! - `GET /v1/capabilities` — supported features
//! - `POST /v1/package-operations/evaluate` — evaluate policy (dry-run)
//! - `POST /v1/package-operations` — evaluate and execute

use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::command_builder::winget::build_winget_command;
use crate::evaluator;
use crate::executor::CommandExecutor;
use crate::model::{
    BrokerInfo, BrokerResponse, Decision, ExecutionInfo, ExecutionMode, OperationStatus, PackageBrokerResponse,
    PackageOperationStatusResponse, PackageRequest, PolicyDocument, ProtocolVersion, ResourceId, ResponsePolicyInfo,
    ResponseSchemaUri, RuleId, SemanticVersion, StatusRequest, StatusResponse, StatusResponseSchemaUri, Transport,
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

/// Shared server state.
pub struct BrokerState {
    /// Current policy. `None` means the broker is paused (policy file missing or corrupted).
    pub policy: RwLock<Option<Arc<PolicyDocument>>>,
    pub executor: Box<dyn CommandExecutor>,
    pub pipe_name: String,
    pub tracker: OperationTracker,
}

/// Serve one HTTP connection over an arbitrary async stream.
pub async fn serve_connection<S>(stream: S, state: Arc<BrokerState>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = Arc::clone(&state);
        async move { handle_request(req, state).await }
    });

    let io = hyper_util::rt::TokioIo::new(stream);
    if let Err(error) = http1::Builder::new()
        .max_buf_size(32 * 1024) // 32 KiB max header size per wire protocol spec.
        .serve_connection(io, service)
        .await
    {
        tracing::warn!(%error, "Connection error");
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<BrokerState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/v1/health") => handle_health(&state),
        (&Method::GET, "/v1/capabilities") => handle_capabilities(&state),
        (&Method::POST, "/v1/package-operations/evaluate") => handle_evaluate(req, Arc::clone(&state), false).await,
        (&Method::POST, "/v1/package-operations") => handle_evaluate(req, Arc::clone(&state), true).await,
        (&Method::POST, "/v1/package-operations/status") => handle_status(req, &state).await,
        _ => not_found(),
    };
    Ok(response)
}

fn handle_health(state: &BrokerState) -> Response<Full<Bytes>> {
    let policy_guard = state.policy.read().expect("policy lock poisoned");
    let status = if policy_guard.is_some() { "ready" } else { "paused" };
    let policy_id = policy_guard
        .as_ref()
        .map(|p| p.metadata.id.to_string())
        .unwrap_or_default();

    let body = serde_json::json!({
        "status": status,
        "protocolVersion": PROTOCOL_VERSION_STR,
        "elevatedSimulation": false,
        "policyId": policy_id,
        "endpoints": [
            "GET /v1/health",
            "GET /v1/capabilities",
            "POST /v1/package-operations/evaluate",
            "POST /v1/package-operations",
            "POST /v1/package-operations/status"
        ]
    });
    json_response(StatusCode::OK, &body)
}

fn handle_capabilities(state: &BrokerState) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION_STR,
        "transports": ["http-named-pipe"],
        "requestMediaTypes": [
            "application/vnd.unigetui.package-request+json; version=1.0",
            "application/json"
        ],
        "responseMediaTypes": [RESPONSE_MEDIA_TYPE],
        "requestSchema": "https://aka.ms/unigetui/package-request.schema.1.0.json",
        "responseSchema": "https://aka.ms/unigetui/package-broker-response.schema.1.0.json",
        "supportedManagers": ["Winget"],
        "supportedOperations": ["install", "update", "uninstall"],
        "maxRequestBodyBytes": 262144,
        "pipeName": &state.pipe_name
    });
    json_response(StatusCode::OK, &body)
}

async fn handle_evaluate(req: Request<Incoming>, state: Arc<BrokerState>, execute: bool) -> Response<Full<Bytes>> {
    let audit_id = generate_audit_id();
    let received_at = Utc::now();

    tracing::trace!(%audit_id, method = %req.method(), path = %req.uri().path(), "Received request");

    // Acquire policy; return 503 if broker is paused.
    let policy = {
        let guard = state.policy.read().expect("policy lock poisoned");
        match guard.as_ref() {
            Some(p) => Arc::clone(p),
            None => return service_unavailable(&audit_id),
        }
    };

    // Validate required protocol headers per wire protocol spec.
    if let Some(err_response) = validate_request_headers(&req, &policy, &audit_id, received_at, &state.pipe_name) {
        return err_response;
    }

    // Extract header request-id before consuming the body.
    let header_request_id = req
        .headers()
        .get("UniGetUI-Request-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Read body.
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return make_error_response(
                &policy,
                &audit_id,
                received_at,
                "failed to read request body",
                StatusCode::BAD_REQUEST,
                &state.pipe_name,
            );
        }
    };

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
    let request: PackageRequest = match serde_json::from_slice(&body_bytes) {
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

    let (command, would_execute) = if decision.decision == Decision::Allow {
        if request.manager.name != crate::model::ManagerName::Winget {
            return make_error_response(
                &policy,
                &audit_id,
                received_at,
                &format!(
                    "manager '{}' is not supported for command execution",
                    request.manager.name
                ),
                StatusCode::UNPROCESSABLE_ENTITY,
                &state.pipe_name,
            );
        }
        let cmd = build_winget_command(&request);
        (cmd, true)
    } else {
        (vec![], false)
    };

    // If execute mode and decision is allow, spawn background execution.
    let (execution_mode, note) = if execute && would_execute {
        let ctx = crate::executor::ExecutionContext {
            command: command.clone(),
            effective_user: request.broker.effective_user.clone(),
            elevation: request.broker.requested_elevation,
            run_as_administrator: request.options.run_as_administrator,
        };

        // Register the operation and spawn execution in background.
        let request_id_str = request.request_id.to_string();
        state.tracker.register(&request.request_id);
        state.tracker.mark_running(&request_id_str);

        // Spawn background task to wait for process completion.
        // The response is returned immediately; clients poll /status for result.
        let bg_state = Arc::clone(&state);
        tokio::spawn(async move {
            match bg_state.executor.execute(&ctx).await {
                Ok(exit_code) => {
                    bg_state.tracker.mark_completed(&request_id_str, exit_code);
                    tracing::info!(
                        request_id = %request_id_str,
                        exit_code,
                        "Background execution completed"
                    );
                }
                Err(error) => {
                    tracing::error!(request_id = %request_id_str, %error, "Background execution failed");
                    bg_state
                        .tracker
                        .mark_failed(&request_id_str, format!("Execution failed: {error}"));
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
        _schema: ResponseSchemaUri,
        response_version: SemanticVersion::from("1.0.0"),
        response_type: PackageBrokerResponse,
        broker: BrokerInfo {
            name: "Devolutions Agent UniGetUI Broker".to_owned(),
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
        decision: decision.decision,
        rule_id: RuleId::from(decision.rule_id),
        reason: decision.reason,
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

    tracing::trace!(
        %audit_id,
        decision = %response.decision,
        rule_id = %*response.rule_id,
        reason = %response.reason,
        would_execute = response.would_execute,
        "Sending response",
    );

    let status = if decision.decision == Decision::Allow {
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
        .body(Full::new(Bytes::from(body)))
        .expect("BUG: response builder with valid status and ASCII headers")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Status endpoint
// ═══════════════════════════════════════════════════════════════════════════════

async fn handle_status(req: Request<Incoming>, state: &BrokerState) -> Response<Full<Bytes>> {
    // Read body.
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return json_error_response(StatusCode::BAD_REQUEST, "failed to read request body");
        }
    };

    if body_bytes.is_empty() {
        return json_error_response(StatusCode::BAD_REQUEST, "request body is required");
    }

    // Deserialize the status request.
    let status_req: StatusRequest = match serde_json::from_slice(&body_bytes) {
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

    match tracked {
        Some(op) => {
            let response = StatusResponse {
                _schema: StatusResponseSchemaUri,
                response_version: SemanticVersion::from("1.0.0"),
                response_type: PackageOperationStatusResponse,
                broker: BrokerInfo {
                    name: "Devolutions Agent UniGetUI Broker".to_owned(),
                    protocol_version: ProtocolVersion::from(PROTOCOL_VERSION_STR),
                    transport: Transport::HttpNamedPipe,
                    pipe_name: Some(state.pipe_name.clone()),
                    elevated_simulation: false,
                },
                request_id: status_req.request_id,
                status: op.status,
                started_at: op.started_at,
                completed_at: op.completed_at,
                exit_code: op.exit_code,
                note: op.note,
            };

            let body = serde_json::to_vec_pretty(&response).expect("BUG: StatusResponse serialization");
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", STATUS_RESPONSE_MEDIA_TYPE)
                .header("UniGetUI-Protocol-Version", PROTOCOL_VERSION_STR)
                .body(Full::new(Bytes::from(body)))
                .expect("BUG: response builder with valid status and ASCII headers")
        }
        None => {
            // Operation not found — either it never existed or it was evicted.
            let response = StatusResponse {
                _schema: StatusResponseSchemaUri,
                response_version: SemanticVersion::from("1.0.0"),
                response_type: PackageOperationStatusResponse,
                broker: BrokerInfo {
                    name: "Devolutions Agent UniGetUI Broker".to_owned(),
                    protocol_version: ProtocolVersion::from(PROTOCOL_VERSION_STR),
                    transport: Transport::HttpNamedPipe,
                    pipe_name: Some(state.pipe_name.clone()),
                    elevated_simulation: false,
                },
                request_id: status_req.request_id,
                status: OperationStatus::Failed,
                started_at: None,
                completed_at: None,
                exit_code: None,
                note: Some("Operation not found (never submitted or already evicted).".to_owned()),
            };

            let body = serde_json::to_vec_pretty(&response).expect("BUG: StatusResponse serialization");
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", STATUS_RESPONSE_MEDIA_TYPE)
                .header("UniGetUI-Protocol-Version", PROTOCOL_VERSION_STR)
                .body(Full::new(Bytes::from(body)))
                .expect("BUG: response builder with valid status and ASCII headers")
        }
    }
}

fn json_error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": message });
    let bytes = serde_json::to_vec_pretty(&body).expect("BUG: JSON value serialization");
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("BUG: static response builder")
}

/// Validate required request headers per the wire protocol specification.
///
/// Returns `Some(response)` if validation fails, `None` if all checks pass.
fn validate_request_headers(
    req: &Request<Incoming>,
    policy: &PolicyDocument,
    audit_id: &str,
    received_at: DateTime<Utc>,
    pipe_name: &str,
) -> Option<Response<Full<Bytes>>> {
    // UniGetUI-Protocol-Version header is required.
    let proto_version = req.headers().get("UniGetUI-Protocol-Version");
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
    if req.headers().get("UniGetUI-Request-Id").is_none() {
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
    let content_type = req.headers().get(hyper::header::CONTENT_TYPE);
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

fn make_error_response(
    policy: &PolicyDocument,
    audit_id: &str,
    received_at: DateTime<Utc>,
    reason: &str,
    status: StatusCode,
    pipe_name: &str,
) -> Response<Full<Bytes>> {
    let completed_at = Utc::now();
    let response = BrokerResponse {
        _schema: ResponseSchemaUri,
        response_version: SemanticVersion::from("1.0.0"),
        response_type: PackageBrokerResponse,
        broker: BrokerInfo {
            name: "Devolutions Agent UniGetUI Broker".to_owned(),
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
        .body(Full::new(Bytes::from(body)))
        .expect("BUG: response builder with valid status and ASCII headers")
}

fn service_unavailable(audit_id: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": "broker paused",
        "reason": "policy file is unavailable or corrupted; waiting for a valid policy",
        "auditId": audit_id,
    });
    let bytes = serde_json::to_vec_pretty(&body).expect("BUG: JSON value serialization");
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "application/json")
        .header("Retry-After", "5")
        .body(Full::new(Bytes::from(bytes)))
        .expect("BUG: static response builder")
}

fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(r#"{"error":"not found"}"#.as_bytes().to_vec())))
        .expect("BUG: static response builder")
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec_pretty(body).expect("BUG: JSON value serialization");
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("BUG: response builder with valid status")
}

fn generate_audit_id() -> String {
    format!("audit-{}", uuid::Uuid::new_v4())
}
