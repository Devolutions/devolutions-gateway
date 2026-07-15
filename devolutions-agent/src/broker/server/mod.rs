//! Runtime implementation of the shared NOW package broker server facade.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use now_policy::PolicyDocument;
use now_policy_api::{
    Base64Utf8Data, CapabilitiesResponse, CapabilitiesResponseKind, Decision, DecisionInfo, ErrorCode, ErrorResponse,
    EvaluationResponse, EvaluationResponseKind, ExecutionResponse, ExecutionResponseKind, HealthResponse,
    HealthResponseKind, HealthStatus, OperationStatus, OperationSubmission, PackageRequest, StatusRequest,
    StatusResponse, StatusResponseKind, Transport,
};
use now_policy_server_template::{MAX_REQUEST_BODY_BYTES, PackageBrokerServer, SharedPackageBrokerServer};
use tracing::{info, trace, warn};

use crate::broker::auth::PipeClient;
use crate::broker::command_builder::build_command;
use crate::broker::evaluator;
use crate::broker::executor::{CommandExecutor, ExecutionContext};
use crate::broker::operation_tracker::OperationTracker;

mod connection;
mod execution;
mod responses;

pub use connection::serve_connection;
use responses::{
    api_version, default_manager_capabilities, diagnostics, error_response, new_operation_id, parse_rule_id,
    policy_info, policy_validity_failure, request_summary, server_context,
};

/// Shared server state.
pub struct BrokerState {
    /// Current policy. `None` means the broker is paused (policy file missing or corrupted).
    pub policy: RwLock<Option<Arc<PolicyDocument>>>,
    pub executor: Arc<dyn CommandExecutor>,
    pub pipe_name: String,
    pub tracker: OperationTracker,
    pub skip_signature_validation: bool,
}

struct EvaluatedRequest {
    policy: Arc<PolicyDocument>,
    received_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    decision: DecisionInfo,
    would_execute: bool,
    command: Vec<String>,
}

/// Build the axum router for a single authenticated pipe client.
pub(crate) fn build_router_for_client(state: Arc<BrokerState>, client: PipeClient) -> axum::Router {
    let server: SharedPackageBrokerServer = Arc::new(BrokerConnection { state, client });
    axum::Router::from(now_policy_server_template::api_router_from_shared(server))
}

struct BrokerConnection {
    state: Arc<BrokerState>,
    client: PipeClient,
}

#[async_trait]
impl PackageBrokerServer for BrokerConnection {
    async fn health(&self) -> HealthResponse {
        self.state.health().await
    }

    async fn capabilities(&self) -> CapabilitiesResponse {
        self.state.capabilities().await
    }

    async fn evaluate(&self, request: PackageRequest) -> Result<EvaluationResponse, ErrorResponse> {
        self.client
            .validate_request(&request, self.state.skip_signature_validation)
            .map_err(|error| {
                warn!(error = format!("{error:#}"), "Rejected package broker evaluate request");
                error_response(ErrorCode::Unauthorized, "pipe client authentication failed")
            })?;

        self.state.evaluate(request).await
    }

    async fn execute(&self, request: PackageRequest) -> Result<ExecutionResponse, ErrorResponse> {
        self.client
            .validate_request(&request, self.state.skip_signature_validation)
            .map_err(|error| {
                warn!(error = format!("{error:#}"), "Rejected package broker execute request");
                error_response(ErrorCode::Unauthorized, "pipe client authentication failed")
            })?;

        self.state.execute(request).await
    }

    async fn status(&self, request: StatusRequest) -> Result<StatusResponse, ErrorResponse> {
        self.client
            .validate_status_request(&request, self.state.skip_signature_validation)
            .map_err(|error| {
                warn!(error = format!("{error:#}"), "Rejected package broker status request");
                error_response(ErrorCode::Unauthorized, "pipe client authentication failed")
            })?;

        let owner_key = request.client.owner_key();
        self.state.status_for_client(request, owner_key).await
    }
}

#[async_trait]
impl PackageBrokerServer for BrokerState {
    async fn health(&self) -> HealthResponse {
        let policy_guard = self.policy.read().expect("policy lock poisoned");
        let (status, policy_id) = match policy_guard.as_ref() {
            Some(policy) => (HealthStatus::Ready, policy.metadata.id.to_string()),
            None => (HealthStatus::Paused, String::new()),
        };

        HealthResponse {
            response_kind: HealthResponseKind,
            response_version: api_version(),
            server: server_context(),
            status,
            policy_id,
        }
    }

    async fn capabilities(&self) -> CapabilitiesResponse {
        CapabilitiesResponse {
            response_kind: CapabilitiesResponseKind,
            response_version: api_version(),
            server: server_context(),
            transports: vec![Transport::HttpNamedPipe],
            managers: default_manager_capabilities(),
            max_request_body_bytes: MAX_REQUEST_BODY_BYTES as u64,
        }
    }

    async fn evaluate(&self, request: PackageRequest) -> Result<EvaluationResponse, ErrorResponse> {
        let evaluated = self.evaluate_request(&request)?;

        Ok(EvaluationResponse {
            response_kind: EvaluationResponseKind,
            response_version: api_version(),
            server: server_context(),
            request_id: request.request_id.clone(),
            received_at: evaluated.received_at,
            completed_at: evaluated.completed_at,
            request: request_summary(&request),
            decision: evaluated.decision,
            would_execute: evaluated.would_execute,
            policy: policy_info(&evaluated.policy),
            diagnostics: diagnostics(&evaluated.command, request.include_command_preview)?,
        })
    }

    async fn execute(&self, request: PackageRequest) -> Result<ExecutionResponse, ErrorResponse> {
        let evaluated = self.evaluate_request(&request)?;
        let operation = if evaluated.would_execute {
            let generated_operation_id = new_operation_id()?;
            let submitted_at = Utc::now();
            let context = ExecutionContext {
                kill_processes: request
                    .options
                    .kill_before_operation
                    .iter()
                    .map(|process| process.0.clone())
                    .collect(),
                pre_command: request.options.pre_operation_command.clone(),
                command: evaluated.command.clone(),
                post_command: request.options.post_operation_command.clone(),
                effective_user: request.client.effective_user.clone(),
                elevation: request.client.requested_elevation,
                scope: request.options.scope,
                capture_output: request.capture_output,
            };

            let owner_key = request.client_owner_key();
            let (operation_id, is_new_operation) = self
                .tracker
                .register(&owner_key, &request, generated_operation_id)
                .map_err(|error| error_response(ErrorCode::Conflict, format!("{error:#}")))?;
            if is_new_operation {
                execution::spawn_execution(
                    Arc::clone(&self.executor),
                    self.tracker.clone(),
                    operation_id.clone(),
                    context,
                );
            }
            let status = self
                .tracker
                .get(&operation_id)
                .map_or(OperationStatus::Starting, |operation| operation.status);

            Some(OperationSubmission {
                operation_id,
                status,
                submitted_at,
            })
        } else {
            None
        };

        Ok(ExecutionResponse {
            response_kind: ExecutionResponseKind,
            response_version: api_version(),
            server: server_context(),
            request_id: request.request_id.clone(),
            received_at: evaluated.received_at,
            completed_at: evaluated.completed_at,
            request: request_summary(&request),
            decision: evaluated.decision,
            policy: policy_info(&evaluated.policy),
            operation,
            diagnostics: diagnostics(&evaluated.command, request.include_command_preview)?,
        })
    }

    async fn status(&self, request: StatusRequest) -> Result<StatusResponse, ErrorResponse> {
        self.status_for_client(request, String::new()).await
    }
}

impl BrokerState {
    async fn status_for_client(
        &self,
        request: StatusRequest,
        owner_key: String,
    ) -> Result<StatusResponse, ErrorResponse> {
        let operation = if owner_key.is_empty() {
            self.tracker.get(&request.operation_id)
        } else {
            self.tracker.get_for_owner(&request.operation_id, &owner_key)
        };
        let Some(operation) = operation else {
            return Err(error_response(ErrorCode::NotFound, "operation not found"));
        };

        Ok(StatusResponse {
            response_kind: StatusResponseKind,
            response_version: api_version(),
            server: server_context(),
            operation_id: request.operation_id,
            request_id: operation.request_id,
            status: operation.status,
            started_at: operation.started_at,
            completed_at: operation.completed_at,
            exit_code: operation.exit_code,
            message: operation.note,
            details: None,
            stdout: operation
                .stdout
                .map(|stdout| Base64Utf8Data(base64::engine::general_purpose::STANDARD.encode(stdout))),
        })
    }

    fn evaluate_request(&self, request: &PackageRequest) -> Result<EvaluatedRequest, ErrorResponse> {
        let received_at = Utc::now();
        let policy = {
            let guard = self.policy.read().expect("policy lock poisoned");
            match guard.as_ref() {
                Some(policy) => Arc::clone(policy),
                None => {
                    return Err(error_response(
                        ErrorCode::BrokerPaused,
                        "policy file is unavailable or corrupted",
                    ));
                }
            }
        };

        if let Some(reason) = policy_validity_failure(&policy, received_at) {
            warn!(%reason, "Rejecting request: policy outside validity window");
            return Err(error_response(ErrorCode::Forbidden, reason));
        }

        trace!(
            operation = %request.operation,
            manager = %request.manager,
            package_id = %request.package.id,
            request_id = %request.request_id,
            "Evaluating policy for request",
        );

        let decision = evaluator::evaluate(&policy, request);
        let audit_mode = policy.enforcement.audit_mode == Some(true);
        if audit_mode {
            info!(
                real_decision = %decision.decision,
                rule_id = %decision.rule_id,
                "Audit mode enabled; decision is not enforced",
            );
        }

        let effective_decision = if audit_mode {
            Decision::Allow
        } else {
            decision.decision.into()
        };

        let reason = if audit_mode && decision.decision != now_policy::Decision::Allow {
            format!(
                "[Audit mode] Not enforced. Policy decision was {} (rule '{}'): {}",
                decision.decision, decision.rule_id, decision.reason
            )
        } else {
            decision.reason
        };

        let command = if effective_decision == Decision::Allow {
            build_command(request).map_err(|error| error_response(ErrorCode::ValidationFailed, format!("{error:#}")))?
        } else {
            Vec::new()
        };

        Ok(EvaluatedRequest {
            policy,
            received_at,
            completed_at: Utc::now(),
            decision: DecisionInfo {
                decision: effective_decision,
                rule_id: parse_rule_id(&decision.rule_id)?,
                reason,
            },
            would_execute: effective_decision == Decision::Allow,
            command,
        })
    }
}

trait ClientOwnerKey {
    fn owner_key(&self) -> String;
}

impl ClientOwnerKey for now_policy_api::ClientContext {
    fn owner_key(&self) -> String {
        format!(
            "{}|{}",
            self.effective_user.to_lowercase(),
            self.client_executable_path.to_lowercase()
        )
    }
}

trait PackageRequestClientOwner {
    fn client_owner_key(&self) -> String;
}

impl PackageRequestClientOwner for PackageRequest {
    fn client_owner_key(&self) -> String {
        self.client.owner_key()
    }
}
