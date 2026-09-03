//! Runtime implementation of the shared NOW package broker server facade.

// See `responses.rs` for why `ErrorResponse` is large and not boxed.
#![expect(
    clippy::result_large_err,
    reason = "ErrorResponse's size is dictated by the shared now-policy-api contract, not under this crate's control"
)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use now_policy::PolicyDocument;
use now_policy_api::{
    CancelRequest, CancelResponse, CancelResponseKind, CapabilitiesResponse, CapabilitiesResponseKind, Decision,
    DecisionInfo, Elevation, ErrorCode, ErrorResponse, EvaluationResponse, EvaluationResponseKind, ExecutionResponse,
    ExecutionResponseKind, HealthResponse, HealthResponseKind, HealthStatus, ManagerCapability, ManagerName,
    OperationStatus, OperationSubmission, PackageRequest, PolicyManagementResponse, PolicyManagementResponseKind,
    PolicyReplacementRequest, PolicyReplacementResponse, PolicyReplacementResponseKind, PolicyResponse,
    PolicyResponseKind, PolicyValidationRequest, PolicyValidationResponse, PolicyValidationResponseKind, Scope,
    StatusRequest, StatusResponse, StatusResponseKind, Transport,
};
use now_policy_server_template::{MAX_REQUEST_BODY_BYTES, PackageBrokerServer, SharedPackageBrokerServer};
use tracing::{info, trace, warn};
use win_api_wrappers::identity::sid::Sid;

use crate::auth::PipeClient;
use crate::command_builder::build_command;
use crate::evaluator;
use crate::executor::{CommandExecutor, ExecutionContext};
use crate::operation_tracker::OperationTracker;
use crate::policy_store::{PolicyStore, PolicyWriteActor};

mod connection;
mod execution;
pub(crate) mod responses;

pub use connection::serve_connection;
use responses::{
    api_version, diagnostics, error_response, filter_manager_capabilities, new_operation_id, parse_rule_id,
    policy_info, policy_validity_failure, request_summary, server_context, supported_manager_capabilities,
};

/// How long a per-user manager availability probe stays fresh before it is re-run.
const MANAGER_PROBE_TTL: Duration = Duration::from_secs(60);

/// Per-user cache of probed manager availability.
///
/// Probing walks the target user's environment (PATH lookups and file checks); the cache
/// keeps capability requests cheap while still picking up newly (un)installed managers
/// after the TTL elapses.
pub struct ManagerProbeCache {
    ttl: Duration,
    entries: parking_lot::Mutex<HashMap<String, (Instant, Vec<ManagerName>)>>,
}

impl Default for ManagerProbeCache {
    fn default() -> Self {
        Self::with_ttl(MANAGER_PROBE_TTL)
    }
}

impl ManagerProbeCache {
    fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    fn get_fresh(&self, user_key: &str) -> Option<Vec<ManagerName>> {
        let entries = self.entries.lock();
        entries
            .get(user_key)
            .filter(|(probed_at, _)| probed_at.elapsed() < self.ttl)
            .map(|(_, managers)| managers.clone())
    }

    fn insert(&self, user_key: String, managers: Vec<ManagerName>) {
        self.entries.lock().insert(user_key, (Instant::now(), managers));
    }
}

/// Shared server state.
pub struct BrokerState {
    /// Owns the configured/resolved policy path, observed state, and transactional
    /// replacement; the store's state is Missing/Invalid when the broker is paused.
    pub policy_store: Arc<PolicyStore>,
    pub executor: Arc<dyn CommandExecutor>,
    pub pipe_name: String,
    pub tracker: OperationTracker,
    pub skip_signature_validation: bool,
    pub manager_probe_cache: ManagerProbeCache,
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
///
/// Body-size limiting is entirely owned by `now_policy_server_template::api_router_from_shared`
/// (route ownership stays there; see the shared-contract pin comment in the workspace
/// `Cargo.toml`): it applies [`MAX_REQUEST_BODY_BYTES`] (256 KiB) to every operation
/// endpoint (`POST /v1/package-operations/*`) and the larger, dedicated
/// `MAX_POLICY_MANAGEMENT_BODY_BYTES` (16 MiB) to the two policy-management routes,
/// `POST /v1/policy/validate` and `PUT /v1/policy`. This broker has nothing to add for
/// either limit -- both are applied inside `api_router_from_shared` itself, not here --
/// and must never re-apply a body-size layer of its own on top, which would only risk
/// silently drifting from the shared contract's own limits. See
/// `agent_policy_tester::windows::policy_management_body_size_limits` for the end-to-end
/// `>256 KiB` valid / `>16 MiB` reject coverage.
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
        self.state.capabilities(self.client.user_sid()).await
    }

    async fn active_policy(&self) -> Result<PolicyResponse, ErrorResponse> {
        self.client
            .validate_connection(self.state.skip_signature_validation)
            .map_err(|error| auth_error("policy", error))?;

        self.state.policy_response()
    }

    async fn policy_management(&self) -> Result<PolicyManagementResponse, ErrorResponse> {
        self.client
            .validate_connection(self.state.skip_signature_validation)
            .map_err(|error| auth_error("policy management", error))?;

        Ok(PolicyManagementResponse {
            response_kind: PolicyManagementResponseKind,
            response_version: api_version(),
            server: server_context(),
            management: self.state.policy_store.management_snapshot(),
        })
    }

    async fn validate_policy(
        &self,
        request: PolicyValidationRequest,
    ) -> Result<PolicyValidationResponse, ErrorResponse> {
        self.client
            .validate_connection(self.state.skip_signature_validation)
            .map_err(|error| auth_error("policy validation", error))?;

        // Bound to the same process-random key `replace_policy`'s transaction verifies
        // against, so a receipt issued here is always accepted there.
        let validation = self.state.policy_store.validate_draft(&request.draft);

        Ok(PolicyValidationResponse {
            response_kind: PolicyValidationResponseKind,
            response_version: api_version(),
            server: server_context(),
            validation,
        })
    }

    async fn replace_policy(
        &self,
        request: PolicyReplacementRequest,
    ) -> Result<PolicyReplacementResponse, ErrorResponse> {
        let intent = format!("{:?}", request.operation);
        let configured_path = PathBuf::from(self.state.policy_store.management_snapshot().configured_path);

        // One attempted sysevent+trace for the whole write lifecycle, recorded here at
        // the server boundary (where the OS-verified pipe client SID/executable, request
        // intent, and configured path are all in hand) rather than duplicated again once
        // the request reaches `PolicyStore::replace`.
        crate::audit::write_attempted(
            self.client.user_sid(),
            self.client.executable_path(),
            &intent,
            &configured_path,
        );

        if let Err(error) = self.client.validate_connection(self.state.skip_signature_validation) {
            // Sanitized reason to the tamper-evident sysevent trail; the detailed
            // Authenticode failure is only ever traced (inside `auth_error`), never
            // logged as a security-audit event.
            let reason = "pipe client authentication failed";
            crate::audit::write_denied(
                self.client.user_sid(),
                self.client.executable_path(),
                &intent,
                &configured_path,
                reason,
            );
            return Err(auth_error("policy replacement", error));
        }

        // Authenticode validation only proves *which* signed client is calling; policy
        // writes additionally require the actual named-pipe process token to be both
        // elevated and an enabled member of the built-in Administrators group. This is
        // captured from the OS token at connect time and is never derived from request
        // fields, so a client cannot self-declare its way into write access.
        if !self.client.is_elevated_administrator() {
            let reason = "pipe client token is not an elevated Administrator";
            crate::audit::write_denied(
                self.client.user_sid(),
                self.client.executable_path(),
                &intent,
                &configured_path,
                reason,
            );
            warn!(user_sid = %self.client.user_sid(), "Rejected package broker policy replacement request: {reason}");
            return Err(error_response(ErrorCode::AdministratorRequired, reason));
        }

        let actor = PolicyWriteActor {
            sid: self.client.user_sid(),
            executable: self.client.executable_path(),
        };

        self.state
            .policy_store
            .replace(request, actor)
            .await
            .map(|success| PolicyReplacementResponse {
                response_kind: PolicyReplacementResponseKind,
                response_version: api_version(),
                server: server_context(),
                policy: success.policy,
                validation: success.validation,
                management: success.management,
            })
    }

    async fn evaluate(&self, request: PackageRequest) -> Result<EvaluationResponse, ErrorResponse> {
        self.client
            .validate_request(&request, self.state.skip_signature_validation)
            .map_err(|error| auth_error("evaluate", error))?;

        self.state.evaluate(request).await
    }

    async fn execute(&self, request: PackageRequest) -> Result<ExecutionResponse, ErrorResponse> {
        self.client
            .validate_request(&request, self.state.skip_signature_validation)
            .map_err(|error| auth_error("execute", error))?;

        self.state.execute(request, self.client.user_sid()).await
    }

    async fn status(&self, request: StatusRequest) -> Result<StatusResponse, ErrorResponse> {
        self.client
            .validate_status_request(&request, self.state.skip_signature_validation)
            .map_err(|error| auth_error("status", error))?;

        let owner_key = request.client.owner_key();
        self.state.status_for_client(request, owner_key).await
    }

    async fn cancel(&self, request: CancelRequest) -> Result<CancelResponse, ErrorResponse> {
        self.client
            .validate_cancel_request(&request, self.state.skip_signature_validation)
            .map_err(|error| auth_error("cancel", error))?;

        let owner_key = request.client.owner_key();
        self.state.cancel_for_client(request, owner_key).await
    }
}

/// Reject a request whose pipe client failed Authenticode/identity validation
/// (`PipeClient::validate_connection` and friends): trace the detailed underlying error
/// for diagnosis, and return the sanitized, consistent `Unauthorized` response every
/// route uses for this condition.
fn auth_error(context: &str, error: anyhow::Error) -> ErrorResponse {
    warn!(
        error = format!("{error:#}"),
        "Rejected package broker {context} request"
    );
    error_response(ErrorCode::Unauthorized, "pipe client authentication failed")
}

impl BrokerState {
    fn active_policy_snapshot(&self) -> Option<Arc<PolicyDocument>> {
        self.policy_store.active_policy()
    }

    fn active_policy(&self) -> Result<Arc<PolicyDocument>, ErrorResponse> {
        self.active_policy_snapshot()
            .ok_or_else(|| error_response(ErrorCode::BrokerPaused, "active policy is unavailable"))
    }

    #[expect(
        clippy::result_large_err,
        reason = "the shared API contract requires ErrorResponse values"
    )]
    fn policy_response(&self) -> Result<PolicyResponse, ErrorResponse> {
        let policy = self
            .active_policy_snapshot()
            .ok_or_else(|| error_response(ErrorCode::NotFound, "active policy is unavailable"))?;

        Ok(PolicyResponse {
            response_kind: PolicyResponseKind,
            response_version: api_version(),
            server: server_context(),
            policy: (*policy).clone(),
        })
    }

    async fn health(&self) -> HealthResponse {
        let policy = self.policy_store.active_policy();
        let (status, policy_id) = match &policy {
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

    async fn capabilities(&self, user_sid: &Sid) -> CapabilitiesResponse {
        CapabilitiesResponse {
            response_kind: CapabilitiesResponseKind,
            response_version: api_version(),
            server: server_context(),
            transports: vec![Transport::HttpNamedPipe],
            managers: self.probed_manager_capabilities(user_sid).await,
            // The shared contract exposes a single `max_request_body_bytes` figure, with
            // no separate field for the larger policy-management limit (see
            // `build_router_for_client`): this always reflects the general per-operation
            // limit, which is what every `POST /v1/package-operations/*` caller actually
            // needs to know to size its own requests.
            max_request_body_bytes: MAX_REQUEST_BODY_BYTES as u64,
        }
    }

    /// Capabilities for the managers actually available to the target user.
    ///
    /// Availability is probed through the executor (mirroring execution-time resolution)
    /// and cached per user for [`MANAGER_PROBE_TTL`].
    async fn probed_manager_capabilities(&self, user_sid: &Sid) -> Vec<ManagerCapability> {
        let user_key = user_sid.to_string();

        let available = match self.manager_probe_cache.get_fresh(&user_key) {
            Some(available) => available,
            None => {
                let available = self.executor.probe_managers(user_sid).await;
                info!(
                    user_sid = %user_key,
                    available_managers = ?available,
                    "Probed package manager availability"
                );
                self.manager_probe_cache.insert(user_key, available.clone());
                available
            }
        };

        filter_manager_capabilities(supported_manager_capabilities(), &available)
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

    async fn execute(&self, request: PackageRequest, user_sid: &Sid) -> Result<ExecutionResponse, ErrorResponse> {
        let evaluated = self.evaluate_request(&request)?;
        let operation = if evaluated.would_execute {
            let generated_operation_id = new_operation_id()?;
            let submitted_at = Utc::now();
            let mut context = ExecutionContext {
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
                user_sid: user_sid.clone(),
                elevation: request.client.requested_elevation,
                scope: request.options.scope,
                capture_output: request.capture_output,
                cancel_token: tokio_util::sync::CancellationToken::new(),
                event_sink: None,
            };

            let owner_key = request.client_owner_key();
            let (operation_id, is_new_operation) = self
                .tracker
                .register(&owner_key, &request, generated_operation_id)
                .map_err(|error| error_response(ErrorCode::Conflict, format!("{error:#}")))?;
            // On idempotent resubmission, return the originally created channel descriptor.
            #[cfg_attr(
                not(windows),
                expect(unused_mut, reason = "only mutated on Windows where event channels exist")
            )]
            let mut event_channel = self
                .tracker
                .get(&operation_id)
                .and_then(|operation| operation.event_channel);
            if is_new_operation {
                // The executor observes the tracked operation's cancel token so a later
                // cancel request can terminate the spawned process.
                if let Some(tracked) = self.tracker.get(&operation_id) {
                    context.cancel_token = tracked.cancel_token;
                }

                // Open the per-operation event channel before returning the response so
                // the advertised pipe is immediately connectable. Best-effort: the
                // operation proceeds without a channel if creation fails.
                #[cfg(windows)]
                {
                    let operation_key = operation_id.to_string();
                    match crate::event_channel::open_operation_channel(&operation_key, user_sid) {
                        Ok((sink, descriptor)) => {
                            self.tracker
                                .set_event_channel(&operation_key, sink.clone(), descriptor.clone());
                            context.event_sink = Some(sink);
                            event_channel = Some(descriptor);
                        }
                        Err(error) => {
                            warn!(
                                operation_id = %operation_key,
                                error = format!("{error:#}"),
                                "Failed to open per-operation event channel; continuing without it"
                            );
                        }
                    }
                }

                execution::spawn_execution(
                    Arc::clone(&self.executor),
                    self.tracker.clone(),
                    operation_id.clone(),
                    context,
                );
            }
            // Query the status after spawning so fast executions are reflected in the response.
            let status = self
                .tracker
                .get(&operation_id)
                .map_or(OperationStatus::Starting, |operation| operation.status);

            Some(OperationSubmission {
                operation_id,
                status,
                submitted_at,
                event_channel,
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
        })
    }

    async fn cancel_for_client(
        &self,
        request: CancelRequest,
        owner_key: String,
    ) -> Result<CancelResponse, ErrorResponse> {
        let Some(operation) = self.tracker.request_cancel(&request.operation_id, &owner_key) else {
            return Err(error_response(ErrorCode::NotFound, "operation not found"));
        };

        let message = if operation.status == OperationStatus::Canceling {
            info!(operation_id = %request.operation_id, "Cancellation requested for operation");
            "cancellation requested; poll the status endpoint until a terminal status is reached".to_owned()
        } else {
            format!("operation already reached terminal status {:?}", operation.status)
        };

        Ok(CancelResponse {
            response_kind: CancelResponseKind,
            response_version: api_version(),
            server: server_context(),
            operation_id: request.operation_id,
            request_id: operation.request_id,
            status: operation.status,
            message: Some(message),
        })
    }

    #[expect(
        clippy::result_large_err,
        reason = "the shared API contract requires ErrorResponse values"
    )]
    fn evaluate_request(&self, request: &PackageRequest) -> Result<EvaluatedRequest, ErrorResponse> {
        // SECURITY: Pre/post operation commands are raw command strings executed via
        // cmd.exe with the execution token, and the policy schema cannot restrict
        // their content yet. Running them elevated would grant arbitrary elevated
        // code execution and make the package allowlist moot, so they are only
        // accepted for non-elevated execution (standard elevation and non-machine
        // scope; machine scope also elevates the execution token).
        // This gate is intentionally not bypassable by policy rules, `defaultDecision`,
        // or audit mode; revisit once the policy schema supports a content allowlist.
        let has_pre_post_commands =
            request.options.pre_operation_command.is_some() || request.options.post_operation_command.is_some();
        let requires_elevation =
            request.client.requested_elevation == Elevation::Elevated || request.options.scope == Some(Scope::Machine);
        if has_pre_post_commands && requires_elevation {
            warn!(
                request_id = %request.request_id,
                "Rejecting request: pre/post operation commands are not allowed for elevated execution"
            );
            return Err(error_response(
                ErrorCode::ValidationFailed,
                "pre/post operation commands are only allowed for non-elevated execution",
            ));
        }

        let received_at = Utc::now();
        let policy = self
            .active_policy_snapshot()
            .ok_or_else(|| error_response(ErrorCode::BrokerPaused, "active policy is unavailable"))?;

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
            match decision.decision {
                now_policy::Decision::Allow => Decision::Allow,
                now_policy::Decision::Deny => Decision::Deny,
            }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use chrono::Utc;
    use now_policy::{
        PackageBrokerPolicy, PolicyEnforcement, PolicyMetadata, PolicySchemaUri, ResourceId, RulePrecedence,
        SemanticVersion,
    };
    use now_policy_api as api;
    use tower_service::Service as _;

    use super::*;
    use crate::executor::{ExecutionOutput, OperationCanceled, ProcessStartedCallback};
    use crate::test_support::system_sid;

    struct NoopExecutor;

    #[async_trait]
    impl CommandExecutor for NoopExecutor {
        async fn execute(
            &self,
            _ctx: &ExecutionContext,
            _process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            anyhow::bail!("not used in tests")
        }
    }

    struct FakeExecutor {
        available: Vec<ManagerName>,
        probe_count: AtomicUsize,
    }

    #[async_trait]
    impl CommandExecutor for FakeExecutor {
        async fn execute(
            &self,
            _ctx: &ExecutionContext,
            _process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            anyhow::bail!("not used in this test")
        }

        async fn probe_managers(&self, _user_sid: &Sid) -> Vec<ManagerName> {
            self.probe_count.fetch_add(1, Ordering::SeqCst);
            self.available.clone()
        }
    }

    /// The most permissive policy possible: default Allow, no rules, audit mode on.
    fn permissive_policy() -> PolicyDocument {
        PolicyDocument {
            _schema: PolicySchemaUri,
            policy_version: SemanticVersion::from("1.0.0"),
            policy_type: PackageBrokerPolicy,
            metadata: PolicyMetadata {
                id: ResourceId::from("test-policy"),
                publisher: "Test".to_owned(),
                revision: 1,
                published_at: Utc::now(),
                valid_from: None,
                valid_until: None,
                description: None,
                support_url: None,
            },
            enforcement: PolicyEnforcement {
                default_decision: now_policy::Decision::Allow,
                rule_precedence: RulePrecedence::PriorityThenDeny,
                audit_mode: Some(true),
            },
            rules: Vec::new(),
        }
    }

    fn state() -> BrokerState {
        BrokerState {
            policy_store: PolicyStore::for_tests(Some(permissive_policy())),
            executor: Arc::new(NoopExecutor),
            pipe_name: "test-pipe".to_owned(),
            tracker: OperationTracker::new(),
            skip_signature_validation: true,
            manager_probe_cache: Default::default(),
        }
    }

    fn shared_state(policy: Option<PolicyDocument>) -> Arc<BrokerState> {
        let mut state = state();
        state.policy_store = PolicyStore::for_tests(policy);
        Arc::new(state)
    }

    async fn route_request(state: Arc<BrokerState>, method: Method, uri: &str) -> Response {
        let client = PipeClient::from_current_process().expect("capture current test process");
        let mut router = build_router_for_client(state, client);
        router
            .call(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("valid test request"),
            )
            .await
            .expect("router is infallible")
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        serde_json::from_slice(&body).expect("response is valid JSON")
    }

    #[tokio::test]
    async fn policy_route_rejects_unsigned_client() {
        let mut state = state();
        state.skip_signature_validation = false;
        let response = route_request(Arc::new(state), Method::GET, "/v1/policy").await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response_json(response).await;
        let error: ErrorResponse = serde_json::from_value(body.clone()).expect("deserialize error response");
        assert_eq!(error.code, ErrorCode::Unauthorized);
        assert_eq!(error.message, "pipe client authentication failed");
        assert!(body.get("Policy").is_none());
    }

    // ─── Elevation/administrator gating at the HTTP route layer (item 23/25) ──
    //
    // Only meaningful with the `dev-skip-broker-signature` feature: without it, every
    // pipe client (including these synthetic ones, whose `executable_path` does not
    // point at a real Devolutions-signed binary) fails Authenticode validation
    // regardless of elevation, so these tests would only ever observe 401 and never
    // actually reach the elevation gate they exist to exercise. See
    // `crate::auth::PipeClient::{test_elevated_administrator, test_unelevated}`.
    #[cfg(feature = "dev-skip-broker-signature")]
    mod elevation_gating {
        use super::*;

        async fn route_request_as(
            state: Arc<BrokerState>,
            client: PipeClient,
            method: Method,
            uri: &str,
            body: Option<serde_json::Value>,
        ) -> axum::response::Response {
            let mut router = build_router_for_client(state, client);
            let request = match body {
                Some(value) => Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&value).expect("serialize test body")))
                    .expect("valid test request"),
                None => Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("valid test request"),
            };
            router.call(request).await.expect("router is infallible")
        }

        fn draft_json(id: &str) -> serde_json::Value {
            serde_json::json!({
                "$schema": now_policy::POLICY_DRAFT_SCHEMA_URI,
                "PolicyVersion": "1.0.0",
                "PolicyType": "PackageBrokerPolicy",
                "Metadata": { "Id": id, "Publisher": "Test" },
                "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
                "Rules": [],
            })
        }

        fn dev_state() -> Arc<BrokerState> {
            let mut broker_state = state();
            broker_state.skip_signature_validation = true;
            Arc::new(broker_state)
        }

        #[tokio::test]
        async fn management_and_validation_succeed_without_elevation() {
            let state = dev_state();
            let client = PipeClient::test_unelevated(system_sid(), PathBuf::from("unelevated.exe"));

            let management = route_request_as(
                Arc::clone(&state),
                client.clone(),
                Method::GET,
                "/v1/policy/management",
                None,
            )
            .await;
            assert_eq!(management.status(), StatusCode::OK);

            let validate_body = serde_json::json!({
                "RequestKind": "PolicyValidationRequest",
                "RequestVersion": "1.0",
                "Draft": draft_json("policy-a"),
            });
            let validate =
                route_request_as(state, client, Method::POST, "/v1/policy/validate", Some(validate_body)).await;
            assert_eq!(validate.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn replace_requires_administrator_even_with_signature_bypass_active() {
            let state = dev_state();
            let client = PipeClient::test_unelevated(system_sid(), PathBuf::from("unelevated.exe"));

            let management = response_json(
                route_request_as(
                    Arc::clone(&state),
                    client.clone(),
                    Method::GET,
                    "/v1/policy/management",
                    None,
                )
                .await,
            )
            .await;
            let store_token = management["Management"]["StoreToken"].as_str().unwrap().to_owned();

            let replace_body = serde_json::json!({
                "RequestKind": "PolicyReplacementRequest",
                "RequestVersion": "1.0",
                "ExpectedStoreToken": store_token,
                "Operation": "Update",
                "ConflictHandling": "Reject",
                "WarningsAcknowledged": true,
                "Draft": draft_json("test-policy"),
                "ValidationReceipt": "hmac-sha256:0000",
            });
            let replace = route_request_as(state, client, Method::PUT, "/v1/policy", Some(replace_body)).await;

            // The dev-only signature bypass proves it took effect (this is not a 401),
            // but it must never also bypass elevation/Administrators membership: the
            // request is rejected before the store (and therefore the bogus receipt)
            // is ever consulted.
            assert_eq!(replace.status(), StatusCode::FORBIDDEN);
            let body = response_json(replace).await;
            let error: ErrorResponse = serde_json::from_value(body).expect("deserialize error response");
            assert_eq!(error.code, ErrorCode::AdministratorRequired);
        }

        #[tokio::test]
        async fn replace_reaches_the_store_for_an_elevated_administrator() {
            let state = dev_state();
            let unelevated = PipeClient::test_unelevated(system_sid(), PathBuf::from("unelevated.exe"));
            let elevated = PipeClient::test_elevated_administrator(system_sid(), PathBuf::from("elevated.exe"));

            let management = response_json(
                route_request_as(
                    Arc::clone(&state),
                    unelevated,
                    Method::GET,
                    "/v1/policy/management",
                    None,
                )
                .await,
            )
            .await;
            let store_token = management["Management"]["StoreToken"].as_str().unwrap().to_owned();

            // A deliberately bogus receipt: this proves the request passed the
            // elevation/Administrators gate (it is rejected by store-level validation,
            // not by `AdministratorRequired`), without needing the full validate-then-
            // replace round trip.
            let replace_body = serde_json::json!({
                "RequestKind": "PolicyReplacementRequest",
                "RequestVersion": "1.0",
                "ExpectedStoreToken": store_token,
                "Operation": "Update",
                "ConflictHandling": "Reject",
                "WarningsAcknowledged": true,
                "Draft": draft_json("test-policy"),
                "ValidationReceipt": "hmac-sha256:0000",
            });
            let replace = route_request_as(state, elevated, Method::PUT, "/v1/policy", Some(replace_body)).await;

            let body = response_json(replace).await;
            let error: ErrorResponse = serde_json::from_value(body).expect("deserialize error response");
            assert_ne!(
                error.code,
                ErrorCode::AdministratorRequired,
                "an elevated Administrator's request must reach the store, not be denied at the auth gate"
            );
        }
    }

    // ─── Policy-management body-size limit, applied by the shared router ──────
    //
    // Same feature-gating rationale as `elevation_gating` above: without the dev
    // signature bypass, every request (regardless of size) is rejected with 401 before
    // the body-size layer is ever reached, so these tests would not actually exercise
    // it. The router used here is the exact same `build_router_for_client` the real
    // named-pipe server serves every connection through (see its doc comment): the
    // 16 MiB policy-management limit and 256 KiB operation-endpoint limit are both
    // applied entirely inside `now_policy_server_template::api_router_from_shared`, so
    // this proves the *final* (not this broker's own) limit end to end. The Agent E2E
    // suite (`agent_policy_tester::windows::policy_management_body_size_limits`)
    // exercises the same two limits again over the real named-pipe HTTP transport.
    #[cfg(feature = "dev-skip-broker-signature")]
    mod policy_management_body_limits {
        use now_policy_server_template::MAX_POLICY_MANAGEMENT_BODY_BYTES;

        use super::*;

        /// Post a `/v1/policy/validate` request whose serialized body is at least
        /// `target_len` bytes, via a single large filler string in `Draft` (not a
        /// well-formed policy draft): `Draft` is a raw `serde_json::Value`, so any valid
        /// JSON value deserializes, and the body-size limit is enforced by the router
        /// before the draft's content is ever inspected. One contiguous allocation for
        /// the filler plus one for its serialized form, instead of building a large tree
        /// of many small values.
        async fn route_oversized_validate(state: Arc<BrokerState>, target_len: usize) -> axum::response::Response {
            let client = PipeClient::test_unelevated(system_sid(), PathBuf::from("unelevated.exe"));
            let mut router = build_router_for_client(state, client);
            let body = serde_json::json!({
                "RequestKind": "PolicyValidationRequest",
                "RequestVersion": "1.0",
                "Draft": "a".repeat(target_len),
            });
            let request = Request::builder()
                .method(Method::POST)
                .uri("/v1/policy/validate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize test body")))
                .expect("valid test request");
            router.call(request).await.expect("router is infallible")
        }

        fn dev_state() -> Arc<BrokerState> {
            let mut broker_state = state();
            broker_state.skip_signature_validation = true;
            Arc::new(broker_state)
        }

        #[tokio::test]
        async fn validate_accepts_a_body_over_the_operation_limit_but_under_the_management_limit() {
            // Comfortably above the 256 KiB operation-endpoint limit
            // (`MAX_REQUEST_BODY_BYTES`) but still well inside the dedicated 16 MiB
            // policy-management limit: proves `/v1/policy/validate` does not share the
            // smaller operation-endpoint limit.
            let response = route_oversized_validate(dev_state(), MAX_REQUEST_BODY_BYTES * 2).await;
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn validate_rejects_a_body_over_the_management_limit() {
            let response =
                route_oversized_validate(dev_state(), MAX_POLICY_MANAGEMENT_BODY_BYTES + MAX_REQUEST_BODY_BYTES).await;

            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let error: ErrorResponse =
                serde_json::from_value(response_json(response).await).expect("deserialize error response");
            assert_eq!(error.code, ErrorCode::PayloadTooLarge);
        }
    }

    #[test]
    fn policy_response_returns_not_found_when_unavailable() {
        let Err(error) = shared_state(None).policy_response() else {
            panic!("expected unavailable policy response");
        };
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(error.message, "active policy is unavailable");
    }

    #[tokio::test]
    async fn phase_one_router_does_not_expose_policy_management_routes() {
        for (method, uri, expected_status) in [
            (Method::GET, "/v1/policy/management", StatusCode::NOT_FOUND),
            (Method::POST, "/v1/policy/validate", StatusCode::NOT_FOUND),
            (Method::PUT, "/v1/policy", StatusCode::METHOD_NOT_ALLOWED),
            (Method::DELETE, "/v1/policy", StatusCode::METHOD_NOT_ALLOWED),
        ] {
            let response = route_request(shared_state(Some(permissive_policy())), method, uri).await;
            assert_eq!(response.status(), expected_status, "{uri}");
            if expected_status == StatusCode::METHOD_NOT_ALLOWED {
                assert_eq!(response.headers().get(header::ALLOW).unwrap(), "GET, HEAD");
            }
        }
    }

    #[test]
    fn concurrent_policy_replacement_returns_only_complete_snapshots() {
        let policy_a = permissive_policy();
        let mut policy_b =
            now_policy::schema::parse_policy_json(include_str!("../assets/samples/corporate-allowlist.policy.json"))
                .expect("sample policy is valid");
        policy_b.metadata.id = ResourceId::from("replacement-policy");
        policy_b.metadata.revision = 42;

        let current_policy_json = serde_json::to_value(&policy_a).unwrap();
        let replacement_policy_json = serde_json::to_value(&policy_b).unwrap();
        let policy_a = Arc::new(policy_a);
        let policy_b = Arc::new(policy_b);
        let state = shared_state(None);
        state.policy_store.test_set_active(Arc::clone(&policy_a));

        const READER_COUNT: usize = 4;
        const ITERATIONS: usize = 1_000;
        let barrier = Arc::new(std::sync::Barrier::new(READER_COUNT + 1));

        std::thread::scope(|scope| {
            for _ in 0..READER_COUNT {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                let current_policy_json = &current_policy_json;
                let replacement_policy_json = &replacement_policy_json;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..ITERATIONS {
                        let response = state.policy_response().expect("active policy response");
                        let actual = serde_json::to_value(response.policy).unwrap();
                        assert!(
                            actual == *current_policy_json || actual == *replacement_policy_json,
                            "response mixed two policy snapshots"
                        );
                        std::thread::yield_now();
                    }
                });
            }

            barrier.wait();
            for index in 0..ITERATIONS {
                let replacement = if index % 2 == 0 {
                    Arc::clone(&policy_b)
                } else {
                    Arc::clone(&policy_a)
                };
                state.policy_store.test_set_active(replacement);
                std::thread::yield_now();
            }
        });
    }

    fn request() -> PackageRequest {
        PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: api::API_VERSION_STR.into(),
            request_id: api::ResourceId::from("req-1"),
            created_at: Utc::now(),
            operation: api::Operation::Install,
            manager: ManagerName::Winget,
            source: api::RequestSource {
                name: "winget".to_owned(),
                url: None,
            },
            package: api::RequestPackage {
                id: api::PackageIdentifier("Contoso.Tools".to_owned()),
                version: None,
                architecture: None,
                channel: None,
            },
            options: api::RequestOptions {
                scope: None,
                interactive: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: Vec::new(),
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: Vec::new(),
                uninstall_previous: false,
                no_upgrade: false,
            },
            client: api::ClientContext {
                transport: Transport::HttpNamedPipe,
                requested_elevation: Elevation::Elevated,
                effective_user: "DOMAIN\\user".to_owned(),
                client_executable_path: "C:\\Program Files\\Devolutions\\Package Broker\\PackageBrokerClient.exe"
                    .to_owned(),
                client_version: "1.0.0".to_owned(),
            },
            include_command_preview: false,
            capture_output: false,
        }
    }

    #[test]
    fn elevated_pre_operation_command_is_rejected_even_under_permissive_policy() {
        let mut request = request();
        request.client.requested_elevation = Elevation::Elevated;
        request.options.pre_operation_command = Some("calc.exe".to_owned());

        let Err(error) = state().evaluate_request(&request) else {
            panic!("expected pre-operation command to be rejected");
        };
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn elevated_post_operation_command_is_rejected_even_under_permissive_policy() {
        let mut request = request();
        request.client.requested_elevation = Elevation::Elevated;
        request.options.post_operation_command = Some("calc.exe".to_owned());

        let Err(error) = state().evaluate_request(&request) else {
            panic!("expected post-operation command to be rejected");
        };
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn machine_scope_pre_operation_command_is_rejected() {
        // Machine scope elevates the execution token even with standard elevation.
        let mut request = request();
        request.client.requested_elevation = Elevation::Standard;
        request.options.scope = Some(Scope::Machine);
        request.options.pre_operation_command = Some("calc.exe".to_owned());

        let Err(error) = state().evaluate_request(&request) else {
            panic!("expected pre-operation command to be rejected");
        };
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn non_elevated_pre_post_commands_are_accepted() {
        let mut request = request();
        request.client.requested_elevation = Elevation::Standard;
        request.options.scope = Some(Scope::User);
        request.options.pre_operation_command = Some("echo before".to_owned());
        request.options.post_operation_command = Some("echo after".to_owned());

        let Ok(evaluated) = state().evaluate_request(&request) else {
            panic!("expected non-elevated pre/post commands to be accepted");
        };
        assert!(evaluated.would_execute);
    }

    #[test]
    fn request_without_pre_post_commands_is_evaluated() {
        let Ok(evaluated) = state().evaluate_request(&request()) else {
            panic!("expected request to be evaluated");
        };
        assert!(evaluated.would_execute);
    }

    #[test]
    fn package_evaluation_without_policy_remains_paused() {
        let Err(error) = shared_state(None).evaluate_request(&request()) else {
            panic!("expected unavailable policy to pause package evaluation");
        };
        assert_eq!(error.code, ErrorCode::BrokerPaused);
    }

    fn make_state(available: Vec<ManagerName>) -> (Arc<BrokerState>, Arc<FakeExecutor>) {
        make_state_with_cache(available, Default::default())
    }

    fn make_state_with_cache(
        available: Vec<ManagerName>,
        manager_probe_cache: ManagerProbeCache,
    ) -> (Arc<BrokerState>, Arc<FakeExecutor>) {
        let executor = Arc::new(FakeExecutor {
            available,
            probe_count: AtomicUsize::new(0),
        });
        let state = Arc::new(BrokerState {
            policy_store: PolicyStore::for_tests(None),
            executor: Arc::clone(&executor) as Arc<dyn CommandExecutor>,
            pipe_name: "test-pipe".to_owned(),
            tracker: OperationTracker::new(),
            skip_signature_validation: true,
            manager_probe_cache,
        });
        (state, executor)
    }

    #[tokio::test]
    async fn capabilities_only_advertise_probed_managers() {
        let (state, _) = make_state(vec![ManagerName::Winget, ManagerName::PowerShell]);

        let response = state.capabilities(&system_sid()).await;

        let managers: Vec<ManagerName> = response.managers.iter().map(|capability| capability.manager).collect();
        assert_eq!(managers, vec![ManagerName::Winget, ManagerName::PowerShell]);
    }

    #[tokio::test]
    async fn capabilities_empty_when_no_manager_available() {
        let (state, _) = make_state(Vec::new());

        let response = state.capabilities(&system_sid()).await;

        assert!(response.managers.is_empty());
    }

    /// The capabilities response advertises the general per-operation body-size limit:
    /// the shared contract has no separate field for the larger policy-management
    /// limit, so this must never be conflated with `MAX_POLICY_MANAGEMENT_BODY_BYTES`.
    #[tokio::test]
    async fn capabilities_advertise_the_operation_endpoint_body_limit() {
        let (state, _) = make_state(Vec::new());

        let response = state.capabilities(&system_sid()).await;

        assert_eq!(response.max_request_body_bytes, MAX_REQUEST_BODY_BYTES as u64);
    }

    #[tokio::test]
    async fn manager_probe_is_cached_per_user() {
        let (state, executor) = make_state(vec![ManagerName::Winget]);
        let sid = system_sid();

        state.capabilities(&sid).await;
        state.capabilities(&sid).await;

        assert_eq!(executor.probe_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn manager_probe_is_refreshed_after_ttl_expiry() {
        let (state, executor) =
            make_state_with_cache(vec![ManagerName::Winget], ManagerProbeCache::with_ttl(Duration::ZERO));
        let sid = system_sid();

        state.capabilities(&sid).await;
        state.capabilities(&sid).await;

        assert_eq!(executor.probe_count.load(Ordering::SeqCst), 2);
    }

    // ─── Cancellation ────────────────────────────────────────────────────────

    /// Executor that blocks until the operation's cancel token fires, then reports cancellation.
    struct CancelableExecutor;

    #[async_trait]
    impl CommandExecutor for CancelableExecutor {
        async fn execute(
            &self,
            ctx: &ExecutionContext,
            _process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            ctx.cancel_token.cancelled().await;
            Err(anyhow::Error::new(OperationCanceled))
        }
    }

    /// Executor that never finishes, even when canceled (keeps operations in Canceling).
    struct StuckExecutor;

    #[async_trait]
    impl CommandExecutor for StuckExecutor {
        async fn execute(
            &self,
            _ctx: &ExecutionContext,
            _process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            std::future::pending().await
        }
    }

    /// Executor that completes instantly with exit code 0.
    struct InstantExecutor;

    #[async_trait]
    impl CommandExecutor for InstantExecutor {
        async fn execute(
            &self,
            _ctx: &ExecutionContext,
            _process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            Ok(ExecutionOutput {
                exit_code: 0,
                stdout: String::new(),
                started_at: Some(Utc::now()),
            })
        }
    }

    fn state_with_executor(executor: Arc<dyn CommandExecutor>) -> BrokerState {
        BrokerState {
            policy_store: PolicyStore::for_tests(Some(permissive_policy())),
            executor,
            pipe_name: "test-pipe".to_owned(),
            tracker: OperationTracker::new(),
            skip_signature_validation: true,
            manager_probe_cache: Default::default(),
        }
    }

    fn cancel_request(operation_id: &api::ResourceId, client: &api::ClientContext) -> CancelRequest {
        CancelRequest {
            request_kind: api::CancelRequestKind,
            request_version: api::API_VERSION_STR.into(),
            operation_id: operation_id.clone(),
            client: client.clone(),
        }
    }

    fn status_request(operation_id: &api::ResourceId, client: &api::ClientContext) -> StatusRequest {
        StatusRequest {
            request_kind: api::StatusRequestKind,
            request_version: api::API_VERSION_STR.into(),
            operation_id: operation_id.clone(),
            client: client.clone(),
        }
    }

    async fn submit_operation(state: &BrokerState, request: &PackageRequest) -> OperationSubmission {
        // Use the real test-process user SID: the per-operation event pipe ACL only
        // admits the requesting client user (plus SYSTEM/Administrators).
        let user_sid = win_api_wrappers::process::Process::current_process()
            .token(windows::Win32::Security::TOKEN_QUERY)
            .expect("open current process token")
            .sid_and_attributes()
            .expect("query token user SID")
            .sid;
        let response = state
            .execute(request.clone(), &user_sid)
            .await
            .expect("execute request accepted");
        response.operation.expect("operation submitted")
    }

    async fn wait_for_status(
        state: &BrokerState,
        request: &PackageRequest,
        operation_id: &api::ResourceId,
    ) -> StatusResponse {
        for _ in 0..100 {
            let status = state
                .status_for_client(
                    status_request(operation_id, &request.client),
                    request.client_owner_key(),
                )
                .await
                .expect("status query succeeds");
            if status.status.is_terminal() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("operation did not reach a terminal status in time");
    }

    #[tokio::test]
    async fn cancel_of_running_operation_reports_canceling_then_canceled() {
        let state = state_with_executor(Arc::new(CancelableExecutor));
        let request = request();
        let operation = submit_operation(&state, &request).await;

        let response = state
            .cancel_for_client(
                cancel_request(&operation.operation_id, &request.client),
                request.client_owner_key(),
            )
            .await
            .expect("cancel accepted");

        assert_eq!(response.status, OperationStatus::Canceling);
        assert_eq!(response.request_id, request.request_id);

        let status = wait_for_status(&state, &request, &operation.operation_id).await;
        assert_eq!(status.status, OperationStatus::Canceled);
    }

    #[tokio::test]
    async fn cancel_is_idempotent_while_canceling() {
        let state = state_with_executor(Arc::new(StuckExecutor));
        let request = request();
        let operation = submit_operation(&state, &request).await;

        for _ in 0..2 {
            let response = state
                .cancel_for_client(
                    cancel_request(&operation.operation_id, &request.client),
                    request.client_owner_key(),
                )
                .await
                .expect("cancel accepted");
            assert_eq!(response.status, OperationStatus::Canceling);
        }

        let status = state
            .status_for_client(
                status_request(&operation.operation_id, &request.client),
                request.client_owner_key(),
            )
            .await
            .expect("status query succeeds");
        assert_eq!(status.status, OperationStatus::Canceling);
    }

    #[tokio::test]
    async fn cancel_of_completed_operation_returns_terminal_status() {
        let state = state_with_executor(Arc::new(InstantExecutor));
        let request = request();
        let operation = submit_operation(&state, &request).await;

        let terminal = wait_for_status(&state, &request, &operation.operation_id).await;
        assert_eq!(terminal.status, OperationStatus::Completed);

        let response = state
            .cancel_for_client(
                cancel_request(&operation.operation_id, &request.client),
                request.client_owner_key(),
            )
            .await
            .expect("cancel of terminal operation is idempotent");
        assert_eq!(response.status, OperationStatus::Completed);

        // The operation stays Completed after the cancel attempt.
        let status = state
            .status_for_client(
                status_request(&operation.operation_id, &request.client),
                request.client_owner_key(),
            )
            .await
            .expect("status query succeeds");
        assert_eq!(status.status, OperationStatus::Completed);
    }

    #[tokio::test]
    async fn cancel_of_unknown_operation_is_not_found() {
        let state = state_with_executor(Arc::new(StuckExecutor));
        let request = request();

        let error = state
            .cancel_for_client(
                cancel_request(&api::ResourceId::from("does-not-exist"), &request.client),
                request.client_owner_key(),
            )
            .await
            .expect_err("unknown operation is rejected");
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn cancel_by_different_owner_is_not_found() {
        let state = state_with_executor(Arc::new(StuckExecutor));
        let request = request();
        let operation = submit_operation(&state, &request).await;

        let error = state
            .cancel_for_client(
                cancel_request(&operation.operation_id, &request.client),
                "someone|else".to_owned(),
            )
            .await
            .expect_err("foreign operation is rejected");
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    // ─── Event channel ───────────────────────────────────────────────────────

    use now_policy_api::event_channel::{
        EVENT_CHANNEL_VERSION_MAJOR, EVENT_CHANNEL_VERSION_MINOR, EventFrame, EventFrameDecoder,
    };

    /// Executor that emits output through the operation's event sink, honoring `capture_output`.
    struct StreamingExecutor;

    #[async_trait]
    impl CommandExecutor for StreamingExecutor {
        async fn execute(
            &self,
            ctx: &ExecutionContext,
            process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            if let Some(process_started) = process_started {
                process_started(Utc::now());
            }
            if ctx.capture_output
                && let Some(sink) = &ctx.event_sink
            {
                sink.stdout("installing π...\n".as_bytes());
                sink.stderr(b"warning: low disk space\n");
            }
            Ok(ExecutionOutput {
                exit_code: 0,
                stdout: String::new(),
                started_at: Some(Utc::now()),
            })
        }
    }

    /// Connect to an operation's event pipe (bare name) and read frames until `Finish`.
    async fn read_channel_frames(pipe_name: &str) -> Vec<EventFrame> {
        use tokio::io::AsyncReadExt as _;

        let path = format!(r"\\.\pipe\{pipe_name}");
        let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
            .write(false)
            .open(&path)
            .expect("connect to event channel pipe");

        let mut decoder = EventFrameDecoder::new();
        let mut frames = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = match client.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => break,
            };
            decoder.extend(&buffer[..read]);
            while let Some(frame) = decoder.next_frame().expect("valid frame stream") {
                let finish = frame == EventFrame::Finish;
                frames.push(frame);
                if finish {
                    return frames;
                }
            }
        }
        panic!("event channel stream ended without a Finish frame");
    }

    #[tokio::test]
    async fn execute_returns_connectable_event_channel_with_status_frames_only() {
        let state = state_with_executor(Arc::new(InstantExecutor));
        let request = request(); // capture_output: false.
        let operation = submit_operation(&state, &request).await;

        let channel = operation.event_channel.expect("event channel advertised");
        assert_eq!(channel.kind, api::EventChannelKind::LocalPipe);
        assert_eq!(
            channel.path,
            format!("Devolutions.Now.PackageBroker.Operation.{}", operation.operation_id)
        );

        wait_for_status(&state, &request, &operation.operation_id).await;

        let frames = read_channel_frames(&channel.path).await;
        assert_eq!(
            frames.first(),
            Some(&EventFrame::Hello {
                version_major: EVENT_CHANNEL_VERSION_MAJOR,
                version_minor: EVENT_CHANNEL_VERSION_MINOR,
            })
        );
        assert_eq!(frames.last(), Some(&EventFrame::Finish));
        assert!(
            frames[1..frames.len() - 1]
                .iter()
                .all(|frame| *frame == EventFrame::StatusUpdated),
            "CaptureOutput=false must yield status frames only: {frames:?}"
        );
        assert!(
            frames[1..].contains(&EventFrame::StatusUpdated),
            "at least the terminal transition must be signalled"
        );
    }

    #[tokio::test]
    async fn execute_streams_captured_output_over_event_channel() {
        let state = state_with_executor(Arc::new(StreamingExecutor));
        let mut request = request();
        request.capture_output = true;
        let operation = submit_operation(&state, &request).await;
        let channel = operation.event_channel.expect("event channel advertised");

        wait_for_status(&state, &request, &operation.operation_id).await;

        let frames = read_channel_frames(&channel.path).await;
        assert_eq!(
            frames,
            [
                EventFrame::Hello {
                    version_major: EVENT_CHANNEL_VERSION_MAJOR,
                    version_minor: EVENT_CHANNEL_VERSION_MINOR,
                },
                EventFrame::StatusUpdated, // Running.
                EventFrame::Stdout("installing π...\n".to_owned()),
                EventFrame::Stderr("warning: low disk space\n".to_owned()),
                EventFrame::StatusUpdated, // Completed.
                EventFrame::Finish,
            ]
        );
    }

    #[tokio::test]
    async fn resubmitted_request_reuses_the_same_event_channel() {
        let state = state_with_executor(Arc::new(StuckExecutor));
        let request = request();
        let first = submit_operation(&state, &request).await;
        let second = submit_operation(&state, &request).await;

        assert_eq!(second.operation_id, first.operation_id);
        assert_eq!(second.event_channel, first.event_channel);
        assert!(first.event_channel.is_some());
    }
}
