//! HTTP server for the UniGetUI package broker.
//!
//! Implements the HTTP-over-named-pipe protocol described in the spec.
//! Routes:
//! - `GET /v1/health` — readiness check
//! - `GET /v1/capabilities` — supported features
//! - `POST /v1/package-operations/evaluate` — evaluate policy (dry-run)
//! - `POST /v1/package-operations` — evaluate and execute

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::command_builder::build_winget_command;
use crate::evaluator;
use crate::executor::CommandExecutor;
use crate::models::{
    BrokerInfo, BrokerResponse, Decision, ExecutionInfo, ExecutionMode, PackageRequest, PolicyDocument,
    ResponsePolicyInfo, Transport,
};
use crate::schema::SchemaValidators;

const PROTOCOL_VERSION: &str = "1.0";

const RESPONSE_MEDIA_TYPE: &str = "application/vnd.unigetui.package-broker-response+json; version=1.0";

/// Shared server state.
pub struct BrokerState {
    pub policy: PolicyDocument,
    pub executor: Box<dyn CommandExecutor>,
    pub pipe_name: String,
    pub validators: SchemaValidators,
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
    if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
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
        (&Method::POST, "/v1/package-operations/evaluate") => handle_evaluate(req, &state, false).await,
        (&Method::POST, "/v1/package-operations") => handle_evaluate(req, &state, true).await,
        _ => not_found(),
    };
    Ok(response)
}

fn handle_health(state: &BrokerState) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "status": "ready",
        "protocolVersion": PROTOCOL_VERSION,
        "elevatedSimulation": false,
        "policyId": state.policy.metadata.id,
        "endpoints": [
            "GET /v1/health",
            "GET /v1/capabilities",
            "POST /v1/package-operations/evaluate",
            "POST /v1/package-operations"
        ]
    });
    json_response(StatusCode::OK, &body)
}

fn handle_capabilities(state: &BrokerState) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
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
        "pipeName": state.pipe_name
    });
    json_response(StatusCode::OK, &body)
}

async fn handle_evaluate(req: Request<Incoming>, state: &BrokerState, execute: bool) -> Response<Full<Bytes>> {
    let audit_id = generate_audit_id();
    let received_at = chrono::Utc::now().to_rfc3339();

    // Read body.
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return make_error_response(
                &state.policy,
                &audit_id,
                &received_at,
                "failed to read request body",
                StatusCode::BAD_REQUEST,
                &state.pipe_name,
            );
        }
    };

    if body_bytes.is_empty() {
        return make_error_response(
            &state.policy,
            &audit_id,
            &received_at,
            "request body is required",
            StatusCode::BAD_REQUEST,
            &state.pipe_name,
        );
    }

    // Parse as generic JSON first for schema validation.
    let request_value: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(error) => {
            return make_error_response(
                &state.policy,
                &audit_id,
                &received_at,
                &format!("invalid JSON: {error}"),
                StatusCode::BAD_REQUEST,
                &state.pipe_name,
            );
        }
    };

    // Validate request against schema.
    if let Err(error) = evaluator::validate_request(&state.validators, &request_value) {
        return make_error_response(
            &state.policy,
            &audit_id,
            &received_at,
            &error.to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
            &state.pipe_name,
        );
    }

    // Deserialize into typed request.
    let request: PackageRequest = match serde_json::from_value(request_value) {
        Ok(req) => req,
        Err(error) => {
            return make_error_response(
                &state.policy,
                &audit_id,
                &received_at,
                &format!("request deserialization failed: {error}"),
                StatusCode::UNPROCESSABLE_ENTITY,
                &state.pipe_name,
            );
        }
    };

    // Evaluate policy.
    let decision = match evaluator::evaluate(&state.policy, &request) {
        Ok(d) => d,
        Err(error) => {
            return make_error_response(
                &state.policy,
                &audit_id,
                &received_at,
                &error.to_string(),
                StatusCode::UNPROCESSABLE_ENTITY,
                &state.pipe_name,
            );
        }
    };

    let (command, would_execute) = if decision.decision == Decision::Allow {
        if request.manager.name != crate::models::ManagerName::Winget {
            return make_error_response(
                &state.policy,
                &audit_id,
                &received_at,
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

    // If execute mode and decision is allow, run the command.
    let (execution_mode, note) = if execute && would_execute {
        match state.executor.execute(&command, &request.broker.effective_user).await {
            Ok(()) => (ExecutionMode::Elevated, "Command executed successfully.".to_owned()),
            Err(error) => {
                tracing::error!(%error, "Command execution failed");
                (ExecutionMode::Elevated, format!("Execution failed: {error}"))
            }
        }
    } else if execute {
        (ExecutionMode::Elevated, "Denied by policy.".to_owned())
    } else {
        (
            ExecutionMode::SimulatedElevated,
            "Dry-run: command not executed.".to_owned(),
        )
    };

    let completed_at = chrono::Utc::now().to_rfc3339();

    let response = BrokerResponse {
        response_version: "1.0.0".to_owned(),
        response_type: "packageBrokerResponse".to_owned(),
        broker: BrokerInfo {
            name: "Devolutions Agent UniGetUI Broker".to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            transport: Transport::HttpNamedPipe,
            pipe_name: Some(state.pipe_name.clone()),
            elevated_simulation: !execute,
        },
        audit_id: audit_id.clone(),
        request_id: Some(request.request_id.clone()),
        received_at,
        completed_at,
        manager: Some(request.manager.name.to_string()),
        source: Some(request.source.name.clone()),
        package_id: Some(request.package.id.clone()),
        operation: Some(request.operation),
        decision: decision.decision,
        rule_id: decision.rule_id,
        reason: decision.reason,
        would_execute,
        policy: ResponsePolicyInfo {
            id: state.policy.metadata.id.clone(),
            revision: state.policy.metadata.revision,
            policy_version: state.policy.policy_version.clone(),
        },
        execution: ExecutionInfo {
            mode: execution_mode,
            command,
            note,
        },
    };

    let status = if decision.decision == Decision::Allow {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };

    let body = serde_json::to_vec_pretty(&response).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", RESPONSE_MEDIA_TYPE)
        .header("UniGetUI-Protocol-Version", PROTOCOL_VERSION)
        .header("UniGetUI-Audit-Id", &audit_id)
        .header("UniGetUI-Policy-Id", &state.policy.metadata.id)
        .header("UniGetUI-Policy-Revision", state.policy.metadata.revision.to_string())
        .body(Full::new(Bytes::from(body)))
        .expect("BUG: response builder with valid status and ASCII headers")
}

fn make_error_response(
    policy: &PolicyDocument,
    audit_id: &str,
    received_at: &str,
    reason: &str,
    status: StatusCode,
    pipe_name: &str,
) -> Response<Full<Bytes>> {
    let completed_at = chrono::Utc::now().to_rfc3339();
    let response = BrokerResponse {
        response_version: "1.0.0".to_owned(),
        response_type: "packageBrokerResponse".to_owned(),
        broker: BrokerInfo {
            name: "Devolutions Agent UniGetUI Broker".to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            transport: Transport::HttpNamedPipe,
            pipe_name: Some(pipe_name.to_owned()),
            elevated_simulation: false,
        },
        audit_id: audit_id.to_owned(),
        request_id: None,
        received_at: received_at.to_owned(),
        completed_at,
        manager: None,
        source: None,
        package_id: None,
        operation: None,
        decision: Decision::Deny,
        rule_id: "<validation-failure>".to_owned(),
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

    let body = serde_json::to_vec_pretty(&response).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", RESPONSE_MEDIA_TYPE)
        .header("UniGetUI-Protocol-Version", PROTOCOL_VERSION)
        .header("UniGetUI-Audit-Id", audit_id)
        .header("UniGetUI-Policy-Id", &policy.metadata.id)
        .header("UniGetUI-Policy-Revision", policy.metadata.revision.to_string())
        .body(Full::new(Bytes::from(body)))
        .expect("BUG: response builder with valid status and ASCII headers")
}

fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(r#"{"error":"not found"}"#.as_bytes().to_vec())))
        .expect("BUG: static response builder")
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec_pretty(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("BUG: response builder with valid status")
}

fn generate_audit_id() -> String {
    format!("audit-{}", uuid::Uuid::new_v4())
}
