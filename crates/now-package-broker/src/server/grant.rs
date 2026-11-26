//! The remote-grant execution route.
//!
//! The grant authorizes one exact request for one pipe caller; local policy is deliberately not consulted.
//! Every rejection happens before the grant is consumed, so a rejected request spends nothing.

use std::sync::Arc;

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use now_policy_api::{
    self as api, Elevation, ErrorCode, ErrorResponse, GrantExecutionResponse, ManagerName, PackageGrant,
    PackageRequest, Scope,
};
use now_policy_server_template::MAX_REQUEST_BODY_BYTES;
use tracing::warn;

use super::responses::{error_response, new_operation_id, request_summary, server_context};
use super::{
    BrokerState, ClientOwnerKey as _, PipeIdentity, execution, is_json_content_type, reject_duplicate_json_members,
};
use crate::auth::PipeClient;
use crate::command_builder::build_remote_grant_command;
use crate::evaluator;
use crate::executor::{ExecutionContext, TokenElevationCheck};
use crate::remote_grant::VerifiedCaller;

pub(super) const GRANT_ROUTE: &str = "/v1/package-operations/execute-grant";
const WINDOWS_MANAGERS: [ManagerName; 11] = [
    ManagerName::Winget,
    ManagerName::PowerShell,
    ManagerName::PowerShell7,
    ManagerName::Bun,
    ManagerName::Cargo,
    ManagerName::Chocolatey,
    ManagerName::Dotnet,
    ManagerName::Npm,
    ManagerName::Pip,
    ManagerName::Scoop,
    ManagerName::Vcpkg,
];

/// Rejects duplicate JSON members and normalizes Broker manager names before the shared facade parses the request.
pub(super) async fn normalize_grant_request(request: Request, next: Next) -> Response {
    if request.method() != Method::POST
        || request.uri().path() != GRANT_ROUTE
        || !is_json_content_type(request.headers())
    {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error)
            if std::error::Error::source(&error)
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return rejection(ErrorCode::PayloadTooLarge, "request body exceeds the broker limit");
        }
        Err(_) => return rejection(ErrorCode::BadRequest, "request body could not be read"),
    };
    if reject_duplicate_json_members(&bytes).is_err() {
        return rejection(ErrorCode::BadRequest, "request is not a valid package request");
    }
    let Ok(mut request) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return rejection(ErrorCode::BadRequest, "request is not a valid package request");
    };
    if let Some(value) = request.get_mut("Manager")
        && let Some(manager) = value.as_str().and_then(|name| {
            WINDOWS_MANAGERS
                .iter()
                .find(|manager| manager.to_string().eq_ignore_ascii_case(name))
        })
    {
        *value = serde_json::Value::String(manager.to_string());
    }
    let Ok(bytes) = serde_json::to_vec(&request) else {
        return rejection(ErrorCode::BadRequest, "request is not a valid package request");
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    next.run(Request::from_parts(parts, Body::from(bytes))).await
}

/// Authenticates and consumes one grant after the shared facade validates its request envelope.
pub(super) async fn execute_grant(
    state: &BrokerState,
    client: &PipeClient,
    identity: Option<&PipeIdentity>,
    request: PackageRequest,
    grant: PackageGrant,
) -> Result<GrantExecutionResponse, Box<ErrorResponse>> {
    let received_at = Utc::now();

    client
        .validate_request(&request, state.skip_signature_validation)
        .map_err(|error| {
            warn!(error = format!("{error:#}"), "Rejected package broker grant request");
            error_response(ErrorCode::Unauthorized, "pipe client authentication failed")
        })?;

    // The pipe's client security context and the connecting process must have the same SID.
    let caller_sid = identity
        .and_then(|identity| identity.current_user_sid().ok())
        .filter(|sid| sid == client.user_sid())
        .ok_or_else(|| error_response(ErrorCode::Unauthorized, "pipe client authentication failed"))?;

    if let Err((code, message)) = check_request(&request) {
        return Err(Box::new(error_response(code, message)));
    }

    // Built before the grant is consumed, so a request the builder rejects spends nothing.
    let command = build_remote_grant_command(&request)
        .map_err(|error| error_response(ErrorCode::ValidationFailed, format!("{error:#}")))?;
    let generated_operation_id = new_operation_id()?;

    let mut context = ExecutionContext {
        kill_processes: Vec::new(),
        pre_command: None,
        command,
        post_command: None,
        effective_user: request.client.effective_user.clone(),
        user_sid: caller_sid,
        elevation: request.client.requested_elevation,
        scope: request.options.scope,
        token_elevation_check: TokenElevationCheck::Exact,
        capture_output: true,
        cancel_token: tokio_util::sync::CancellationToken::new(),
        event_sink: None,
    };

    let owner_key = request.client.owner_key();
    // The tracker reserves the identity and consumes the grant together, after checking for conflicts.
    let outcome = state
        .tracker
        .register_authorized(&owner_key, &request, &generated_operation_id, || {
            state
                .remote_grants
                .consume(grant.expose(), &VerifiedCaller::new(context.user_sid.clone()), &request)
        })
        .map_err(|_| error_response(ErrorCode::Conflict, "conflicting request or operation identity"))?
        .map_err(|_| error_response(ErrorCode::Forbidden, "the grant does not authorize this request"))?;
    let operation_id = generated_operation_id;
    if let Some(tracked) = state.tracker.get(&operation_id) {
        context.cancel_token = tracked.cancel_token;
    }

    let submitted_at = Utc::now();
    execution::spawn_execution(
        Arc::clone(&state.executor),
        state.tracker.clone(),
        operation_id.clone(),
        context,
        Some(outcome),
    );
    let status = state
        .tracker
        .get(&operation_id)
        .map_or(now_policy_api::OperationStatus::Starting, |operation| operation.status);

    // An empty source (default feed, or uninstall) is omitted rather than echoed as "".
    let mut summary = request_summary(&request);
    if summary.source.as_deref() == Some("") {
        summary.source = None;
    }

    // No event channel is advertised: the contract requires frames only after the connecting process is
    // authenticated and `Finish` only after lossless readers, which the shared channel does not provide.
    Ok(GrantExecutionResponse {
        response_kind: api::GrantExecutionResponseKind,
        response_version: api::GrantResponseVersion,
        server: server_context(),
        request_id: request.request_id,
        received_at,
        completed_at: Utc::now(),
        request: summary,
        authorization: api::GrantAuthorization {
            kind: api::GrantAuthorizationKind::RemoteGrant,
        },
        operation: api::GrantOperation {
            operation_id,
            status,
            submitted_at,
            event_channel: None,
        },
    })
}

/// Checks everything a grant does not already bind, before the grant is consumed.
fn check_request(request: &PackageRequest) -> Result<(), (ErrorCode, &'static str)> {
    if !request.capture_output || request.include_command_preview {
        return Err((
            ErrorCode::ValidationFailed,
            "CaptureOutput must be true and IncludeCommandPreview must be false",
        ));
    }

    if !evaluator::source_name_is_unambiguous_for_manager(request.manager, &request.source.name) {
        return Err((
            ErrorCode::ValidationFailed,
            "package source name has unsupported leading, trailing, default-ignorable, or wildcard characters",
        ));
    }

    let machine_scope = request.options.scope == Some(Scope::Machine);
    let elevated = request.client.requested_elevation == Elevation::Elevated;
    if elevated && !machine_scope {
        return Err((ErrorCode::Forbidden, "a user-scope operation cannot be elevated"));
    }
    // The grant may use a machine selector under a standard token; only WinGet may run elevated.
    if elevated && request.manager != ManagerName::Winget {
        return Err((ErrorCode::Forbidden, "elevated execution is supported only for WinGet"));
    }

    Ok(())
}

fn rejection(code: ErrorCode, message: impl Into<String>) -> Response {
    let status = match code {
        ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
        ErrorCode::Unauthorized | ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ErrorCode::Conflict => StatusCode::CONFLICT,
        ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ErrorCode::ValidationFailed => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedEndpoint => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (status, Json(error_response(code, message))).into_response()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use now_policy_api::{
        self as api, Operation, OperationStatus, PACKAGE_GRANT_HEADER as GRANT_HEADER, PackageIdentifier, Transport,
    };
    use tower_service::Service as _;
    use win_api_wrappers::identity::sid::Sid;

    use super::*;
    use crate::executor::{CommandExecutor, ExecutionOutput, OperationCanceled, ProcessStartedCallback};
    use crate::operation_tracker::OperationTracker;
    use crate::policy_store::PolicyStore;
    use crate::remote_grant::{GrantSpec, IssuedGrant, OutcomeSummary, RemoteGrantStore};
    use crate::server::{PipeIdentity, build_router_for_client, build_router_for_pipe};

    /// Reports a start only when told to, then exits with a fixed code.
    struct ScriptedExecutor {
        reports_start: bool,
        exit_code: i32,
    }

    #[async_trait]
    impl CommandExecutor for ScriptedExecutor {
        async fn execute(
            &self,
            _ctx: &ExecutionContext,
            process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            if self.reports_start
                && let Some(process_started) = process_started
            {
                process_started(Utc::now());
            }

            Ok(ExecutionOutput {
                exit_code: self.exit_code,
                stdout: String::new(),
                started_at: None,
            })
        }
    }

    struct FailingExecutor {
        reports_start: bool,
        canceled: bool,
    }

    #[async_trait]
    impl CommandExecutor for FailingExecutor {
        async fn execute(
            &self,
            _ctx: &ExecutionContext,
            process_started: Option<ProcessStartedCallback>,
        ) -> anyhow::Result<ExecutionOutput> {
            if self.reports_start
                && let Some(process_started) = process_started
            {
                process_started(Utc::now());
            }
            if self.canceled {
                Err(OperationCanceled.into())
            } else {
                anyhow::bail!("injected executor failure")
            }
        }
    }

    // No policy is loaded: a grant must authorize without consulting local policy.
    fn state(reports_start: bool, exit_code: i32) -> Arc<BrokerState> {
        Arc::new(BrokerState {
            policy_store: PolicyStore::for_tests(None),
            executor: Arc::new(ScriptedExecutor {
                reports_start,
                exit_code,
            }),
            pipe_name: "test-pipe".to_owned(),
            tracker: OperationTracker::new(),
            skip_signature_validation: true,
            manager_probe_cache: Default::default(),
            remote_grants: RemoteGrantStore::new(),
        })
    }

    fn client() -> PipeClient {
        PipeClient::from_current_process().expect("capture current test process")
    }

    fn spec(client: &PipeClient) -> GrantSpec {
        GrantSpec {
            operation: Operation::Install,
            manager: ManagerName::Winget,
            source_name: "winget".to_owned(),
            source_url: None,
            package_id: PackageIdentifier("Contoso.Tools".to_owned()),
            version: None,
            scope: Some(Scope::User),
            requested_elevation: Elevation::Standard,
            target_sid: client.user_sid().clone(),
            no_upgrade: true,
        }
    }

    fn body_for(spec: &GrantSpec, issued: &IssuedGrant, client: &PipeClient) -> Vec<u8> {
        let request = PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: api::API_VERSION_STR.into(),
            request_id: api::ResourceId::from(issued.request_id.to_string().as_str()),
            created_at: Utc::now(),
            operation: spec.operation,
            manager: spec.manager,
            source: api::RequestSource {
                name: spec.source_name.clone(),
                url: spec.source_url.clone(),
            },
            package: api::RequestPackage {
                id: spec.package_id.clone(),
                version: None,
                architecture: None,
                channel: None,
            },
            options: api::RequestOptions {
                scope: spec.scope,
                interactive: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: Vec::new(),
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: Vec::new(),
                uninstall_previous: false,
                no_upgrade: spec.no_upgrade,
            },
            client: api::ClientContext {
                transport: Transport::HttpNamedPipe,
                requested_elevation: spec.requested_elevation,
                effective_user: client.display_name().expect("resolve test account"),
                client_executable_path: client.executable_path().to_string_lossy().into_owned(),
                client_version: "1.0.0".to_owned(),
            },
            include_command_preview: false,
            capture_output: true,
        };

        serde_json::to_vec(&request).expect("serialize request")
    }

    async fn send(
        state: &Arc<BrokerState>,
        client: &PipeClient,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        send_as(
            state,
            client,
            Some(PipeIdentity::fixed(client.user_sid().clone())),
            path,
            headers,
            body,
        )
        .await
    }

    async fn send_as(
        state: &Arc<BrokerState>,
        client: &PipeClient,
        identity: Option<PipeIdentity>,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method("POST").uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut router = match identity {
            Some(identity) => build_router_for_pipe(Arc::clone(state), client.clone(), identity),
            None => build_router_for_client(Arc::clone(state), client.clone()),
        };
        let response = router
            .call(builder.body(Body::from(body)).expect("valid test request"))
            .await
            .expect("router is infallible");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("read body");

        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn grant_headers(grant: &str) -> [(&str, &str); 3] {
        [
            ("content-type", "application/json; charset=utf-8"),
            ("accept", "application/json"),
            (GRANT_HEADER, grant),
        ]
    }

    async fn execute(
        state: &Arc<BrokerState>,
        client: &PipeClient,
        spec: &GrantSpec,
        issued: &IssuedGrant,
    ) -> (StatusCode, serde_json::Value) {
        let body = body_for(spec, issued, client);
        send(
            state,
            client,
            GRANT_ROUTE,
            &grant_headers(issued.grant.expose_secret()),
            body,
        )
        .await
    }

    async fn wait_until_finished(state: &BrokerState, response: &serde_json::Value) {
        let id = api::ResourceId::from(response["Operation"]["OperationId"].as_str().expect("operation id"));
        for _ in 0..200 {
            if state.tracker.get(&id).is_some_and(|operation| {
                operation.status != OperationStatus::Starting && operation.status.is_terminal()
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("operation did not finish");
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_grant_runs_its_request_once_without_local_policy() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");

        let (status, first) = execute(&state, &client, &spec, &issued).await;
        let (replay_status, _) = execute(&state, &client, &spec, &issued).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["ResponseKind"], "GrantExecutionResponse");
        assert_eq!(first["Authorization"], serde_json::json!({ "Kind": "RemoteGrant" }));
        assert!(matches!(replay_status, StatusCode::FORBIDDEN | StatusCode::CONFLICT));
        for forbidden in ["Policy", "Decision", "RuleId", "Diagnostics"] {
            assert!(first.get(forbidden).is_none(), "{forbidden} must be absent");
        }
        assert!(!first.to_string().contains(issued.grant.expose_secret()));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn manager_spelling_is_compared_without_ascii_case() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let mut body: serde_json::Value =
            serde_json::from_slice(&body_for(&spec, &issued, &client)).expect("decode request body");
        body["Manager"] = serde_json::json!("wInGeT");

        let (status, _) = send(
            &state,
            &client,
            GRANT_ROUTE,
            &grant_headers(issued.grant.expose_secret()),
            serde_json::to_vec(&body).expect("encode request body"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn default_feed_powershell7_update_uses_the_grant_route() {
        let state = state(true, 0);
        let client = client();
        let mut spec = spec(&client);
        spec.operation = Operation::Update;
        spec.manager = ManagerName::PowerShell7;
        spec.source_name = String::new();
        spec.no_upgrade = false;
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");

        let (status, response) = execute(&state, &client, &spec, &issued).await;

        assert_eq!(status, StatusCode::OK);
        assert!(response["Request"].get("Source").is_none() || response["Request"]["Source"].is_null());
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn outcome_shows_start_and_exit_only_when_the_executor_proved_them() {
        let client = client();

        let proving = state(true, 7);
        let spec = spec(&client);
        let issued = proving.remote_grants.issue(spec.clone()).expect("issue");
        let (_, response) = execute(&proving, &client, &spec, &issued).await;
        wait_until_finished(&proving, &response).await;
        assert_eq!(
            proving.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Exited { exit_code: 7 }
        );

        let silent = state(false, 0);
        let issued = silent.remote_grants.issue(spec.clone()).expect("issue");
        let (_, response) = execute(&silent, &client, &spec, &issued).await;
        wait_until_finished(&silent, &response).await;
        assert_eq!(
            silent.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Consumed
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn executor_failure_ends_the_broker_wait() {
        let mut state = state(true, 0);
        Arc::get_mut(&mut state).expect("state is not shared").executor = Arc::new(FailingExecutor {
            reports_start: true,
            canceled: false,
        });
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let (_, response) = execute(&state, &client, &spec, &issued).await;
        wait_until_finished(&state, &response).await;

        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unobservable { started: true }
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn canceled_execution_ends_the_broker_wait_with_start_evidence() {
        let mut state = state(true, 0);
        Arc::get_mut(&mut state).expect("state is not shared").executor = Arc::new(FailingExecutor {
            reports_start: true,
            canceled: true,
        });
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let (_, response) = execute(&state, &client, &spec, &issued).await;
        wait_until_finished(&state, &response).await;

        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unobservable { started: true }
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn executor_failure_before_start_does_not_claim_a_start() {
        let mut state = state(true, 0);
        Arc::get_mut(&mut state).expect("state is not shared").executor = Arc::new(FailingExecutor {
            reports_start: false,
            canceled: false,
        });
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let (_, response) = execute(&state, &client, &spec, &issued).await;
        wait_until_finished(&state, &response).await;

        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unobservable { started: false }
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §broker-grant-errors
    #[tokio::test]
    async fn header_defects_are_rejected_without_spending_the_grant() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let body = body_for(&spec, &issued, &client);
        let grant = issued.grant.expose_secret();

        let missing = send(
            &state,
            &client,
            GRANT_ROUTE,
            &[("content-type", "application/json"), ("accept", "application/json")],
            body.clone(),
        )
        .await;
        let duplicate = send(
            &state,
            &client,
            GRANT_ROUTE,
            &[
                ("content-type", "application/json"),
                ("accept", "application/json"),
                (GRANT_HEADER, grant),
                (GRANT_HEADER, grant),
            ],
            body.clone(),
        )
        .await;
        let malformed = send(
            &state,
            &client,
            GRANT_ROUTE,
            &grant_headers("not a grant"),
            body.clone(),
        )
        .await;
        let wrong_accept = send(
            &state,
            &client,
            GRANT_ROUTE,
            &[
                ("content-type", "application/json"),
                ("accept", "text/plain"),
                (GRANT_HEADER, grant),
            ],
            body.clone(),
        )
        .await;
        let wrong_type = send(
            &state,
            &client,
            GRANT_ROUTE,
            &[
                ("content-type", "text/plain"),
                ("accept", "application/json"),
                (GRANT_HEADER, grant),
            ],
            body.clone(),
        )
        .await;

        assert_eq!(missing.0, StatusCode::UNAUTHORIZED);
        assert_eq!(missing.1["Code"], "Unauthenticated");
        assert_eq!(duplicate.0, StatusCode::BAD_REQUEST);
        assert_eq!(malformed.0, StatusCode::BAD_REQUEST);
        assert_eq!(wrong_accept.0, StatusCode::BAD_REQUEST);
        assert_eq!(wrong_type.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
        assert_eq!(execute(&state, &client, &spec, &issued).await.0, StatusCode::OK);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §broker-grant-errors
    #[tokio::test]
    async fn legacy_route_rejects_any_grant_header() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let body = body_for(&spec, &issued, &client);

        let (status, response) = send(
            &state,
            &client,
            "/v1/package-operations/execute",
            &grant_headers(issued.grant.expose_secret()),
            body,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["Code"], "BadRequest");
        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn mismatched_request_is_forbidden_and_leaves_the_grant_usable() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let mut other = spec.clone();
        other.package_id = PackageIdentifier("Contoso.Other".to_owned());

        let body = body_for(&other, &issued, &client);
        let (status, _) = send(
            &state,
            &client,
            GRANT_ROUTE,
            &grant_headers(issued.grant.expose_secret()),
            body,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(execute(&state, &client, &spec, &issued).await.0, StatusCode::OK);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §broker-grant-errors
    #[tokio::test]
    async fn tracker_conflict_does_not_consume_the_grant() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let request: PackageRequest =
            serde_json::from_slice(&body_for(&spec, &issued, &client)).expect("package request");
        state
            .tracker
            .register(
                &request.client.owner_key(),
                &request,
                api::ResourceId::from("existing-operation"),
            )
            .expect("register existing request");

        assert_eq!(execute(&state, &client, &spec, &issued).await.0, StatusCode::CONFLICT);
        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
        state
            .remote_grants
            .consume(
                issued.grant.expose_secret(),
                &VerifiedCaller::new(client.user_sid().clone()),
                &request,
            )
            .expect("the rejected request left the grant usable");
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn only_winget_may_elevate_and_user_scope_never_does() {
        let state = state(true, 0);
        let client = client();
        let base = spec(&client);

        let mut user_elevated = base.clone();
        user_elevated.requested_elevation = Elevation::Elevated;

        let mut other_manager = base.clone();
        other_manager.scope = Some(Scope::Machine);
        other_manager.requested_elevation = Elevation::Elevated;
        other_manager.manager = ManagerName::Npm;
        other_manager.no_upgrade = false;

        for rejected in [user_elevated, other_manager] {
            let issued = state.remote_grants.issue(rejected.clone()).expect("issue");
            let (status, _) = execute(&state, &client, &rejected, &issued).await;

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(
                state.remote_grants.outcome(&issued.grant, &issued.request_id),
                OutcomeSummary::Unknown,
                "a rejected request must not spend the grant"
            );
        }

        let mut machine_install = base;
        machine_install.scope = Some(Scope::Machine);
        machine_install.requested_elevation = Elevation::Elevated;
        let issued = state.remote_grants.issue(machine_install.clone()).expect("issue");

        assert_eq!(
            execute(&state, &client, &machine_install, &issued).await.0,
            StatusCode::OK
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn standard_powershell_update_may_target_a_machine_scope() {
        let client = client();
        let mut spec = spec(&client);
        spec.operation = Operation::Update;
        spec.manager = ManagerName::PowerShell7;
        spec.source_name = String::new();
        spec.scope = Some(Scope::Machine);
        spec.requested_elevation = Elevation::Standard;
        spec.no_upgrade = false;
        let issued = RemoteGrantStore::new().issue(spec.clone()).expect("issue");
        let request: PackageRequest = serde_json::from_slice(&body_for(&spec, &issued, &client)).expect("request");

        assert_eq!(check_request(&request), Ok(()));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn winget_machine_uninstall_with_empty_source_passes_the_authorization_checks() {
        let client = client();
        let mut spec = spec(&client);
        spec.operation = Operation::Uninstall;
        spec.scope = Some(Scope::Machine);
        spec.requested_elevation = Elevation::Elevated;
        spec.source_name = String::new();
        spec.no_upgrade = false;
        let issued = RemoteGrantStore::new().issue(spec.clone()).expect("issue");
        let request: PackageRequest = serde_json::from_slice(&body_for(&spec, &issued, &client)).expect("request");

        assert_eq!(check_request(&request), Ok(()));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn unknown_fields_at_any_level_are_rejected_without_spending_the_grant() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let valid: serde_json::Value = serde_json::from_slice(&body_for(&spec, &issued, &client)).expect("json");

        for level in ["", "/Source", "/Package", "/Options", "/Client"] {
            let mut body = valid.clone();
            body.pointer_mut(if level.is_empty() { "" } else { level })
                .expect("object level")
                .as_object_mut()
                .expect("object")
                .insert("Unexpected".to_owned(), serde_json::Value::Bool(true));
            let (status, _) = send(
                &state,
                &client,
                GRANT_ROUTE,
                &grant_headers(issued.grant.expose_secret()),
                serde_json::to_vec(&body).expect("serialize"),
            )
            .await;

            assert_eq!(status, StatusCode::BAD_REQUEST, "unknown field at '{level}'");
        }
        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
        assert_eq!(execute(&state, &client, &spec, &issued).await.0, StatusCode::OK);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_pipe_context_with_a_different_sid_cannot_redeem_the_grant() {
        let state = state(true, 0);
        let client = client();
        let spec = spec(&client);
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");
        let other = Sid::from_well_known(windows::Win32::Security::WinBuiltinUsersSid, None).expect("sid");
        let body = body_for(&spec, &issued, &client);

        let (other_status, _) = send_as(
            &state,
            &client,
            Some(PipeIdentity::fixed(other)),
            GRANT_ROUTE,
            &grant_headers(issued.grant.expose_secret()),
            body.clone(),
        )
        .await;
        let (unverified_status, _) = send_as(
            &state,
            &client,
            None,
            GRANT_ROUTE,
            &grant_headers(issued.grant.expose_secret()),
            body,
        )
        .await;

        assert_eq!(other_status, StatusCode::UNAUTHORIZED);
        assert_eq!(unverified_status, StatusCode::UNAUTHORIZED);
        assert_eq!(execute(&state, &client, &spec, &issued).await.0, StatusCode::OK);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn ambiguous_source_name_is_rejected_without_spending_the_grant() {
        let state = state(true, 0);
        let client = client();
        let mut spec = spec(&client);
        spec.source_name = " winget".to_owned();
        let issued = state.remote_grants.issue(spec.clone()).expect("issue");

        let (status, response) = execute(&state, &client, &spec, &issued).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response["Code"], "ValidationFailed");
        assert_eq!(
            state.remote_grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
    }
}
