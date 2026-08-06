//! Runtime implementation of the shared NOW package broker server facade.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use now_policy::PolicyDocument;
use now_policy_api::{
    CancelRequest, CancelResponse, CancelResponseKind, CapabilitiesResponse, CapabilitiesResponseKind, Decision,
    DecisionInfo, Elevation, ErrorCode, ErrorResponse, EvaluationResponse, EvaluationResponseKind, ExecutionResponse,
    ExecutionResponseKind, HealthResponse, HealthResponseKind, HealthStatus, ManagerCapability, ManagerName,
    OperationStatus, OperationSubmission, PackageRequest, Scope, StatusRequest, StatusResponse, StatusResponseKind,
    Transport,
};
use now_policy_server_template::{MAX_REQUEST_BODY_BYTES, PackageBrokerServer, SharedPackageBrokerServer};
use tracing::{info, trace, warn};
use win_api_wrappers::identity::sid::Sid;

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
    /// Current policy. `None` means the broker is paused (policy file missing or corrupted).
    pub policy: RwLock<Option<Arc<PolicyDocument>>>,
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

        self.state.execute(request, self.client.user_sid()).await
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

    async fn cancel(&self, request: CancelRequest) -> Result<CancelResponse, ErrorResponse> {
        self.client
            .validate_cancel_request(&request, self.state.skip_signature_validation)
            .map_err(|error| {
                warn!(error = format!("{error:#}"), "Rejected package broker cancel request");
                error_response(ErrorCode::Unauthorized, "pipe client authentication failed")
            })?;

        let owner_key = request.client.owner_key();
        self.state.cancel_for_client(request, owner_key).await
    }
}

impl BrokerState {
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

    async fn capabilities(&self, user_sid: &Sid) -> CapabilitiesResponse {
        CapabilitiesResponse {
            response_kind: CapabilitiesResponseKind,
            response_version: api_version(),
            server: server_context(),
            transports: vec![Transport::HttpNamedPipe],
            managers: self.probed_manager_capabilities(user_sid).await,
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
            };

            let owner_key = request.client_owner_key();
            let (operation_id, is_new_operation) = self
                .tracker
                .register(&owner_key, &request, generated_operation_id)
                .map_err(|error| error_response(ErrorCode::Conflict, format!("{error:#}")))?;
            if is_new_operation {
                // The executor observes the tracked operation's cancel token so a later
                // cancel request can terminate the spawned process.
                if let Some(tracked) = self.tracker.get(&operation_id) {
                    context.cancel_token = tracked.cancel_token;
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
                // The per-operation event channel is not implemented yet.
                event_channel: None,
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
            "Cancellation requested; poll the status endpoint until a terminal status is reached".to_owned()
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Utc;
    use now_policy::{
        PackageBrokerPolicy, PolicyEnforcement, PolicyMetadata, PolicySchemaUri, ResourceId, RulePrecedence,
        SemanticVersion,
    };
    use now_policy_api as api;

    use super::*;
    use crate::broker::executor::{ExecutionOutput, OperationCanceled, ProcessStartedCallback};

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
            policy: RwLock::new(Some(Arc::new(permissive_policy()))),
            executor: Arc::new(NoopExecutor),
            pipe_name: "test-pipe".to_owned(),
            tracker: OperationTracker::new(),
            skip_signature_validation: true,
            manager_probe_cache: Default::default(),
        }
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
            policy: RwLock::new(None),
            executor: Arc::clone(&executor) as Arc<dyn CommandExecutor>,
            pipe_name: "test-pipe".to_owned(),
            tracker: OperationTracker::new(),
            skip_signature_validation: true,
            manager_probe_cache,
        });
        (state, executor)
    }

    fn test_sid() -> Sid {
        Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None).unwrap()
    }

    #[tokio::test]
    async fn capabilities_only_advertise_probed_managers() {
        let (state, _) = make_state(vec![ManagerName::Winget, ManagerName::PowerShell]);

        let response = state.capabilities(&test_sid()).await;

        let managers: Vec<ManagerName> = response.managers.iter().map(|capability| capability.manager).collect();
        assert_eq!(managers, vec![ManagerName::Winget, ManagerName::PowerShell]);
    }

    #[tokio::test]
    async fn capabilities_empty_when_no_manager_available() {
        let (state, _) = make_state(Vec::new());

        let response = state.capabilities(&test_sid()).await;

        assert!(response.managers.is_empty());
    }

    #[tokio::test]
    async fn manager_probe_is_cached_per_user() {
        let (state, executor) = make_state(vec![ManagerName::Winget]);
        let sid = test_sid();

        state.capabilities(&sid).await;
        state.capabilities(&sid).await;

        assert_eq!(executor.probe_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn manager_probe_is_refreshed_after_ttl_expiry() {
        let (state, executor) =
            make_state_with_cache(vec![ManagerName::Winget], ManagerProbeCache::with_ttl(Duration::ZERO));
        let sid = test_sid();

        state.capabilities(&sid).await;
        state.capabilities(&sid).await;

        assert_eq!(executor.probe_count.load(Ordering::SeqCst), 2);
    }

    // ─── Cancellation ────────────────────────────────────────────────────────

    /// Executor that blocks until the operation's cancel token fires, then reports Cancellation.
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
            policy: RwLock::new(Some(Arc::new(permissive_policy()))),
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
        let response = state
            .execute(request.clone(), &test_sid())
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
}
