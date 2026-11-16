//! Remote package operations: journaling, grant issuing and delivery to one UniGetUI instance.
//!
//! The Broker's in-process record of the issued grant is the only source of start evidence.
//! Once the grant may have reached UniGetUI, the verdict is unknown whatever UniGetUI answers or fails to answer.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use agent_channel_proto::{
    PackageOperationRequest, PackageOperationResult, PackageOperationStatus, PackageOperationType,
};
use devolutions_gateway_task::ShutdownSignal;
use now_package_broker::registration::RequestError;
use now_package_broker::remote_grant::{GrantSpec, IssuedGrant, OutcomeSummary, RemoteGrantStore};
use now_policy_api::{Elevation, ManagerName, Operation, PackageIdentifier, Scope, VersionString};
use tokio::time::Instant;
use uuid::Uuid;
use win_api_wrappers::identity::sid::Sid;

use super::DeviceManagementContext;
use super::operation_journal::{Admission, OperationJournal, Outcome, Settled};

/// Managers whose Broker builders exist on Windows.
const SUPPORTED_MANAGERS: [ManagerName; 10] = [
    ManagerName::Winget,
    ManagerName::PowerShell,
    ManagerName::PowerShell7,
    ManagerName::Bun,
    ManagerName::Cargo,
    ManagerName::Dotnet,
    ManagerName::Npm,
    ManagerName::Pip,
    ManagerName::Scoop,
    ManagerName::Vcpkg,
];

const OUTCOME_POLL_INTERVAL: Duration = Duration::from_millis(250);
const START_WAIT: Duration = Duration::from_secs(60);
const OPERATION_WAIT: Duration = Duration::from_secs(30 * 60);

/// A validated request, in the Broker's vocabulary.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    operation: Operation,
    manager: ManagerName,
    source_name: String,
    package_id: PackageIdentifier,
    version: Option<VersionString>,
    scope: Scope,
    broker_scope: Option<Scope>,
    reported_scope: Option<String>,
    requested_elevation: Elevation,
    no_upgrade: bool,
}

impl Plan {
    /// Rejects what the Broker grant cannot authorize exactly; the message never repeats request values.
    fn parse(request: &PackageOperationRequest) -> Result<Self, &'static str> {
        let operation = match PackageOperationType::try_from(request.r#type) {
            Ok(PackageOperationType::Install) => Operation::Install,
            Ok(PackageOperationType::Update) => Operation::Update,
            Ok(PackageOperationType::Uninstall) => Operation::Uninstall,
            Err(_) => return Err("unsupported operation type"),
        };

        let manager = SUPPORTED_MANAGERS
            .into_iter()
            .find(|manager| manager.to_string().eq_ignore_ascii_case(&request.manager))
            .or_else(|| {
                [
                    ("winps", ManagerName::PowerShell),
                    ("pwsh", ManagerName::PowerShell7),
                    ("dotnet-tool", ManagerName::Dotnet),
                ]
                .into_iter()
                .find_map(|(id, manager)| id.eq_ignore_ascii_case(&request.manager).then_some(manager))
            })
            .ok_or("unsupported package manager")?;

        let (scope, requested_elevation) = if request.scope.eq_ignore_ascii_case("user") {
            (Scope::User, Elevation::Standard)
        } else if request.scope.eq_ignore_ascii_case("machine") {
            (Scope::Machine, Elevation::Elevated)
        } else {
            return Err("package scope must be user or machine");
        };
        if scope == Scope::Machine && manager != ManagerName::Winget {
            return Err("machine scope is only supported for WinGet");
        }

        match operation {
            Operation::Install if request.source.is_empty() => return Err("install requires a source"),
            Operation::Uninstall if !request.source.is_empty() => return Err("uninstall takes no source"),
            Operation::Uninstall if !request.version.is_empty() => return Err("uninstall version is not supported"),
            _ => {}
        }

        let reported_scope = match (operation, &request.reported_scope) {
            (Operation::Install, None) => None,
            (Operation::Install, Some(_)) => return Err("install does not select an installed row"),
            (_, Some(scope)) => Some(scope.clone()),
            (_, None) => return Err("installed row scope is missing"),
        };
        let broker_scope = if operation == Operation::Install || manager == ManagerName::Winget {
            Some(scope)
        } else if matches!(
            (manager, operation),
            (ManagerName::PowerShell | ManagerName::PowerShell7, Operation::Update)
                | (ManagerName::PowerShell7, Operation::Uninstall)
        ) {
            match reported_scope.as_deref() {
                Some("") => None,
                Some(value) if value.eq_ignore_ascii_case("user") => Some(Scope::User),
                Some(value) if value.eq_ignore_ascii_case("machine") => Some(Scope::Machine),
                _ => return Err("unsupported installed row scope"),
            }
        } else {
            Some(Scope::User)
        };
        let package_id = PackageIdentifier::parse(&request.package_id).map_err(|_| "invalid package ID")?;
        let version = if request.version.is_empty() {
            None
        } else {
            Some(VersionString::parse(&request.version).map_err(|_| "invalid package version")?)
        };

        Ok(Self {
            operation,
            manager,
            source_name: request.source.clone(),
            package_id,
            version,
            scope,
            broker_scope,
            reported_scope,
            requested_elevation,
            no_upgrade: manager == ManagerName::Winget && operation == Operation::Install,
        })
    }

    fn grant_spec(&self, target_sid: Sid) -> GrantSpec {
        GrantSpec {
            operation: self.operation,
            manager: self.manager,
            source_name: self.source_name.clone(),
            source_url: None,
            package_id: self.package_id.clone(),
            version: self.version.clone(),
            scope: self.broker_scope,
            requested_elevation: self.requested_elevation,
            target_sid,
            no_upgrade: self.no_upgrade,
        }
    }

    /// The `ExecutePackageOperation` arguments; the grant is the only secret in them.
    fn arguments(&self, operation_id: &str, broker_request_id: &Uuid, grant: &str) -> serde_json::Value {
        let mut arguments = serde_json::json!({
            "operationId": operation_id,
            "brokerRequestId": broker_request_id.to_string(),
            "operation": self.operation.to_string(),
            "manager": self.manager.to_string(),
            "sourceName": self.source_name,
            "packageId": self.package_id.0,
            "version": self.version.as_ref().map(|version| version.0.as_str()).unwrap_or_default(),
            "scope": self.scope.to_string(),
            "grant": grant,
        });
        if let Some(reported_scope) = &self.reported_scope {
            arguments["reportedScope"] = serde_json::Value::String(reported_scope.clone());
        }
        arguments
    }
}

/// Runs one remote package operation and returns its result.
///
/// Admission and execution run in one detached task, so the operation reaches its recorded outcome even when the
/// caller stops waiting, and an admitted record always has its guard.
pub(super) async fn run(
    context: &DeviceManagementContext,
    authority_id: Uuid,
    request: PackageOperationRequest,
) -> PackageOperationResult {
    let operation_id = request.operation_id.clone();
    let authority_id = authority_id.to_string();
    let journal = context.journal().cloned();
    let task = tokio::spawn(settle(context.clone(), authority_id.clone(), request.clone()));
    let settled = match (task.await, journal) {
        (Ok(settled), _) => settled,
        // The task panicked; its guard has ended any admitted record.
        (Err(_), Some(journal)) => wait(journal, authority_id, request).await,
        (Err(_), None) => unknown(false),
    };
    result(operation_id, settled)
}

async fn settle(context: DeviceManagementContext, authority_id: String, request: PackageOperationRequest) -> Settled {
    let Some(journal) = context.journal().cloned() else {
        return unknown(false);
    };

    let admission = {
        let (journal, authority_id, request) = (Arc::clone(&journal), authority_id.clone(), request.clone());
        tokio::task::spawn_blocking(move || journal.admit(&authority_id, &request)).await
    };
    let admission = match admission {
        Ok(Ok(admission)) => admission,
        Ok(Err(error)) => {
            error!(
                error = format!("{error:#}"),
                "Package operation journal admission failed"
            );
            return unknown(false);
        }
        Err(_) => return unknown(false),
    };

    match admission {
        Admission::Admitted => {
            let pending = Pending {
                journal: Arc::clone(&journal),
                authority_id: authority_id.clone(),
                request: request.clone(),
                armed: true,
            };
            execute(context, pending).await
        }
        Admission::InFlight => wait(journal, authority_id, request).await,
        Admission::Recorded(settled) => settled,
        Admission::PayloadMismatch => {
            warn!("Package operation ID was used for a different request");
            unknown(false)
        }
    }
}

async fn wait(journal: Arc<OperationJournal>, authority_id: String, request: PackageOperationRequest) -> Settled {
    match tokio::task::spawn_blocking(move || journal.wait(&authority_id, &request)).await {
        Ok(Ok(settled)) => settled,
        Ok(Err(error)) => {
            error!(
                error = format!("{error:#}"),
                "Waiting for the package operation record failed"
            );
            unknown(false)
        }
        Err(_) => unknown(false),
    }
}

fn unknown(started: bool) -> Settled {
    Settled {
        outcome: Outcome::Unknown,
        execution_started: started.then_some(true),
    }
}

#[derive(Debug)]
struct Completion {
    settled: Settled,
    /// The final outcome and any start evidence were recorded, regardless of earlier start-write errors.
    durably_recorded: bool,
}

/// An admitted operation whose in-flight record must end, even when its task panics or is dropped.
struct Pending {
    journal: Arc<OperationJournal>,
    authority_id: String,
    request: PackageOperationRequest,
    armed: bool,
}

impl Pending {
    async fn mark_started(&self) -> bool {
        let journal = Arc::clone(&self.journal);
        let authority_id = self.authority_id.clone();
        let request = self.request.clone();
        match tokio::task::spawn_blocking(move || journal.mark_started(&authority_id, &request)).await {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                error!(error = format!("{error:#}"), "Cannot record package operation start");
                false
            }
            Err(error) => {
                error!(%error, "Recording the package operation start was interrupted");
                false
            }
        }
    }

    /// Records the end of the operation; a record that cannot be written leaves the unknown outcome to later deliveries.
    async fn finish(self, outcome: Outcome, started: bool) -> Settled {
        self.finish_with_durability(outcome, started).await.settled
    }

    async fn finish_with_durability(mut self, outcome: Outcome, started: bool) -> Completion {
        let recorded = outcome.clone();
        let written = tokio::task::spawn_blocking(move || {
            let start_recorded = if started {
                self.journal.mark_started(&self.authority_id, &self.request)
            } else {
                Ok(())
            };
            let recorded = if start_recorded.is_ok() {
                recorded
            } else {
                Outcome::Unknown
            };
            let result = self
                .journal
                .complete_with_started(&self.authority_id, &self.request, recorded, started);
            self.armed = false;
            (start_recorded, result)
        })
        .await;
        match written {
            Ok((start_recorded, result)) => {
                let durably_recorded = result.is_ok();
                if let Err(error) = &start_recorded {
                    error!(error = format!("{error:#}"), "Cannot record package operation start");
                }
                if let Err(error) = &result {
                    error!(error = format!("{error:#}"), "Cannot record package operation outcome");
                }
                let settled = if start_recorded.is_ok() && durably_recorded {
                    Settled {
                        outcome,
                        execution_started: started.then_some(true),
                    }
                } else {
                    unknown(started)
                };
                Completion {
                    settled,
                    durably_recorded,
                }
            }
            Err(error) => {
                error!(%error, "Recording the package operation outcome was interrupted");
                Completion {
                    settled: unknown(started),
                    durably_recorded: false,
                }
            }
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = self
                .journal
                .complete(&self.authority_id, &self.request, Outcome::Unknown)
        {
            error!(
                error = format!("{error:#}"),
                "Cannot record an interrupted package operation"
            );
        }
    }
}

async fn execute(context: DeviceManagementContext, pending: Pending) -> Settled {
    // Nothing is delivered before the grant request below, so earlier failures are definite.
    if !context.remote_writes_enabled() {
        return pending
            .finish(failure("remote package writes are disabled"), false)
            .await;
    }
    let plan = match Plan::parse(&pending.request) {
        Ok(plan) => plan,
        Err(reason) => return pending.finish(failure(reason), false).await,
    };
    let Some(broker) = context.broker().cloned() else {
        return pending.finish(failure("package broker is unavailable"), false).await;
    };
    let endpoint = match super::resolve_target(
        &context,
        &pending.request.target_user_uuid,
        &pending.request.registry_epoch,
    )
    .await
    {
        Ok(endpoint) => endpoint,
        Err(error) => {
            debug!(error = format!("{error:#}"), "Package operation target is unavailable");
            return pending.finish(failure("target user is unavailable"), false).await;
        }
    };
    let issued = match broker.remote_grants.issue(plan.grant_spec(endpoint.user_sid().clone())) {
        Ok(issued) => issued,
        Err(error) => {
            debug!(%error, "Cannot issue a package operation grant");
            return pending.finish(failure("cannot authorize the operation"), false).await;
        }
    };

    // From here the grant may reach UniGetUI, so only the Broker's record can say more than unknown.
    let arguments = plan.arguments(
        &pending.request.operation_id,
        &issued.request_id,
        issued.grant.expose_secret(),
    );
    // UNTESTED: Each operation ID reaches at most one endpoint, even on duplicate requests or delivery errors.
    // This prevents duplicate side effects; count dispatches for duplicates and failed delivery when changing this path.
    let mut may_have_been_sent = false;
    let completion = finish_sent(
        pending,
        &broker.remote_grants,
        &issued,
        context.shutdown(),
        track_delivery(
            &mut may_have_been_sent,
            endpoint.request("ExecutePackageOperation", arguments),
        ),
    )
    .await;
    if completion.durably_recorded && may_have_been_sent {
        // UNTESTED: This is the post-journal refresh seam for the selected operation endpoint.
        // A refresh must not target another user or run after a failed journal write.
        // Check the endpoint and both conditions when adding it.
        let _endpoint = &endpoint;
    }
    completion.settled
}

async fn track_delivery(
    may_have_been_sent: &mut bool,
    delivery: impl Future<Output = anyhow::Result<serde_json::Value>>,
) -> anyhow::Result<serde_json::Value> {
    *may_have_been_sent = true;
    let response = delivery.await;
    if let Err(error) = &response
        && let Some(error) = error.downcast_ref::<RequestError>()
    {
        *may_have_been_sent = error.may_have_been_sent();
    }
    response
}

async fn finish_sent(
    pending: Pending,
    grants: &RemoteGrantStore,
    issued: &IssuedGrant,
    shutdown: Option<ShutdownSignal>,
    delivery: impl Future<Output = anyhow::Result<serde_json::Value>>,
) -> Completion {
    let dispatched_at = Instant::now();
    finish_sent_until(
        pending,
        grants,
        issued,
        shutdown,
        delivery,
        WaitLimits {
            start_deadline: dispatched_at + START_WAIT,
            operation_deadline: dispatched_at + OPERATION_WAIT,
            consumed_grace: START_WAIT,
        },
    )
    .await
}

struct WaitLimits {
    start_deadline: Instant,
    operation_deadline: Instant,
    consumed_grace: Duration,
}

async fn finish_sent_until(
    pending: Pending,
    grants: &RemoteGrantStore,
    issued: &IssuedGrant,
    mut shutdown: Option<ShutdownSignal>,
    delivery: impl Future<Output = anyhow::Result<serde_json::Value>>,
    limits: WaitLimits,
) -> Completion {
    let WaitLimits {
        mut start_deadline,
        operation_deadline,
        consumed_grace,
    } = limits;
    let mut delivery = Box::pin(delivery);
    let mut delivery_done = false;
    let mut saw_record = false;
    let mut started = false;
    let mut stopping = false;
    let mut outcome = Outcome::Unknown;

    loop {
        match grants.outcome(&issued.grant, &issued.request_id) {
            OutcomeSummary::Unknown if saw_record => break,
            OutcomeSummary::Unknown => {}
            OutcomeSummary::Consumed if !saw_record => {
                saw_record = true;
                let observed_at = Instant::now();
                if observed_at < start_deadline {
                    start_deadline = (observed_at + consumed_grace).min(operation_deadline);
                }
            }
            OutcomeSummary::Consumed => {}
            OutcomeSummary::Started | OutcomeSummary::Exited { .. } if !started => {
                saw_record = true;
                started = true;
                if !pending.mark_started().await {
                    break;
                }
                continue;
            }
            OutcomeSummary::Started => {}
            OutcomeSummary::Exited { exit_code } => {
                outcome = outcome_for_exit(&pending.request.manager, exit_code);
                break;
            }
        }

        let deadline = if started {
            operation_deadline
        } else {
            start_deadline.min(operation_deadline)
        };
        if stopping || deadline <= Instant::now() {
            break;
        }

        tokio::select! {
            response = &mut delivery, if !delivery_done => {
                delivery_done = true;
                if response.is_err() {
                    debug!("ExecutePackageOperation produced no usable response");
                }
            }
            () = tokio::time::sleep_until((Instant::now() + OUTCOME_POLL_INTERVAL).min(deadline)) => {}
            () = async {
                match &mut shutdown {
                    Some(signal) => signal.wait().await,
                    None => std::future::pending().await,
                }
            } => stopping = true,
        }
    }

    let completion = pending.finish_with_durability(outcome, started).await;
    drop(shutdown);
    completion
}

fn outcome_for_exit(_manager: &str, _exit_code: i32) -> Outcome {
    Outcome::Unknown
}

fn failure(error: &str) -> Outcome {
    Outcome::Failed {
        error: error.to_owned(),
    }
}

fn result(operation_id: String, settled: Settled) -> PackageOperationResult {
    let (success, error, status) = match settled.outcome {
        Outcome::Succeeded => (true, String::new(), PackageOperationStatus::Unspecified),
        Outcome::Failed { error } => (false, error, PackageOperationStatus::Unspecified),
        Outcome::Unknown => (false, String::new(), PackageOperationStatus::Unknown),
    };
    PackageOperationResult {
        operation_id,
        success,
        error,
        status: status.into(),
        execution_started: settled.execution_started,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use now_package_broker::remote_grant::{ExecutionRecord, VerifiedCaller};
    use now_policy_api as api;

    use super::*;

    fn request(operation: PackageOperationType, manager: &str, source: &str, scope: &str) -> PackageOperationRequest {
        PackageOperationRequest {
            operation_id: "op-1".to_owned(),
            r#type: operation.into(),
            manager: manager.to_owned(),
            source: source.to_owned(),
            package_id: "Contoso.App".to_owned(),
            scope: scope.to_owned(),
            reported_scope: (operation != PackageOperationType::Install).then(String::new),
            ..Default::default()
        }
    }

    struct SentOperation {
        journal: Arc<OperationJournal>,
        pending: Pending,
        grants: RemoteGrantStore,
        issued: IssuedGrant,
        record: ExecutionRecord,
        _root: tempfile::TempDir,
    }

    struct IssuedOperation {
        journal: Arc<OperationJournal>,
        pending: Pending,
        grants: RemoteGrantStore,
        issued: IssuedGrant,
        caller: VerifiedCaller,
        broker_request: api::PackageRequest,
        _root: tempfile::TempDir,
    }

    fn issued_operation() -> anyhow::Result<IssuedOperation> {
        let root = tempfile::Builder::new().prefix("operation-").tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let journal = Arc::new(OperationJournal::open(data)?);
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        let pending = Pending {
            journal: Arc::clone(&journal),
            authority_id: "authority".to_owned(),
            request: request.clone(),
            armed: true,
        };
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        let plan = Plan::parse(&request).expect("request is valid");
        let spec = plan.grant_spec(sid.clone());
        let grants = RemoteGrantStore::new();
        let issued = grants.issue(spec.clone())?;
        let broker_request = api::PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: api::API_VERSION_STR.into(),
            request_id: api::ResourceId::from(issued.request_id.to_string().as_str()),
            created_at: "2026-01-01T00:00:00Z".parse().expect("timestamp is valid"),
            operation: spec.operation,
            manager: spec.manager,
            source: api::RequestSource {
                name: spec.source_name,
                url: spec.source_url,
            },
            package: api::RequestPackage {
                id: spec.package_id,
                version: spec.version,
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
                transport: api::Transport::HttpNamedPipe,
                requested_elevation: spec.requested_elevation,
                effective_user: String::new(),
                client_executable_path: String::new(),
                client_version: String::new(),
            },
            include_command_preview: false,
            capture_output: true,
        };
        Ok(IssuedOperation {
            journal,
            pending,
            grants,
            issued,
            caller: VerifiedCaller::new(sid),
            broker_request,
            _root: root,
        })
    }

    fn sent_operation() -> anyhow::Result<SentOperation> {
        let IssuedOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            caller,
            broker_request,
        } = issued_operation()?;
        let record = grants.consume(issued.grant.expose_secret(), &caller, &broker_request)?;
        Ok(SentOperation {
            journal,
            pending,
            grants,
            issued,
            record,
            _root,
        })
    }

    // oracle: mutant fixture cleanup runs while the journal directory is still pinned
    #[test]
    fn operation_fixtures_remove_their_roots_on_drop() -> anyhow::Result<()> {
        let issued = issued_operation()?;
        let issued_root = issued._root.path().to_owned();
        drop(issued);
        assert!(!issued_root.exists(), "issued fixture retained {issued_root:?}");

        let sent = sent_operation()?;
        let sent_root = sent._root.path().to_owned();
        drop(sent);
        assert!(!sent_root.exists(), "sent fixture retained {sent_root:?}");
        Ok(())
    }

    async fn tracked_delivery_result(
        delivery: impl Future<Output = anyhow::Result<serde_json::Value>>,
    ) -> anyhow::Result<(Settled, bool)> {
        let SentOperation {
            _root,
            pending,
            grants,
            issued,
            ..
        } = sent_operation()?;
        let mut may_have_been_sent = false;
        let now = Instant::now();
        let settled = finish_sent_until(
            pending,
            &grants,
            &issued,
            None,
            track_delivery(&mut may_have_been_sent, delivery),
            WaitLimits {
                start_deadline: now + Duration::from_secs(2),
                operation_deadline: now + Duration::from_secs(3),
                consumed_grace: Duration::from_millis(500),
            },
        )
        .await;
        Ok((settled.settled, may_have_been_sent))
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn started_operation_waits_for_broker_exit() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        assert!(record.mark_started());
        let (delivered, response) = tokio::sync::oneshot::channel();
        let mut operation = tokio::spawn(async move {
            finish_sent(pending, &grants, &issued, None, async {
                delivered.send(()).expect("delivery observer is alive");
                std::future::pending().await
            })
            .await
        });
        response.await.expect("request is delivered");

        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut operation)
                .await
                .is_err(),
            "operation settled before the Broker process exited"
        );
        assert!(record.mark_exited(0));
        let settled = tokio::time::timeout(Duration::from_secs(5), operation).await??.settled;
        assert_eq!(settled.execution_started, Some(true));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn started_operation_stops_at_operation_deadline() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        assert!(record.mark_started());
        let now = Instant::now();
        let operation_deadline = now + Duration::from_secs(2);
        let completion = tokio::time::timeout_at(
            operation_deadline + Duration::from_secs(3),
            finish_sent_until(
                pending,
                &grants,
                &issued,
                None,
                std::future::pending(),
                WaitLimits {
                    start_deadline: now + Duration::from_millis(100),
                    operation_deadline,
                    consumed_grace: Duration::from_secs(1),
                },
            ),
        )
        .await?;

        assert!(operation_deadline <= Instant::now());
        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: Some(true),
        };
        assert_eq!(completion.settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn consumed_operation_waits_for_broker_start_and_exit() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let (delivered, response) = tokio::sync::oneshot::channel();
        let mut operation = tokio::spawn(async move {
            finish_sent(pending, &grants, &issued, None, async {
                delivered.send(()).expect("delivery observer is alive");
                Ok(serde_json::json!({"status": "Unknown"}))
            })
            .await
        });
        response.await.expect("request is delivered");

        assert!(
            tokio::time::timeout(Duration::from_millis(750), &mut operation)
                .await
                .is_err(),
            "operation settled while the Broker record was consumed"
        );
        assert!(record.mark_started());
        assert!(record.mark_exited(0));
        let settled = tokio::time::timeout(Duration::from_secs(5), operation).await??.settled;
        assert_eq!(settled.execution_started, Some(true));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn late_consumed_sample_gets_a_fresh_start_grace() -> anyhow::Result<()> {
        let IssuedOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            caller,
            broker_request,
        } = issued_operation()?;
        let request = pending.request.clone();
        let grant = issued.grant.expose_secret().to_owned();
        assert_eq!(
            grants.outcome(&issued.grant, &issued.request_id),
            OutcomeSummary::Unknown
        );
        let operation_grants = grants.clone();
        let dispatched_at = Instant::now();
        let start_deadline = dispatched_at + Duration::from_secs(2);
        let (sampled, response) = tokio::sync::oneshot::channel();
        let mut operation = tokio::spawn(async move {
            finish_sent_until(
                pending,
                &operation_grants,
                &issued,
                None,
                async {
                    sampled.send(()).expect("sample observer is alive");
                    std::future::pending().await
                },
                WaitLimits {
                    start_deadline,
                    operation_deadline: dispatched_at + Duration::from_secs(10),
                    consumed_grace: Duration::from_secs(2),
                },
            )
            .await
        });
        response.await.expect("the initial record was sampled");
        tokio::time::sleep_until(dispatched_at + Duration::from_millis(1200)).await;
        let record = grants.consume(&grant, &caller, &broker_request)?;
        tokio::time::sleep_until(start_deadline + Duration::from_millis(300)).await;
        assert!(
            !operation.is_finished(),
            "the original start deadline ended the consumed wait"
        );
        assert!(record.mark_started());
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut operation)
                .await
                .is_err(),
            "the operation must wait for exit after the late start"
        );
        assert!(record.mark_exited(0));
        let settled = tokio::time::timeout(Duration::from_secs(5), &mut operation)
            .await??
            .settled;
        assert_eq!(settled, unknown(true));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn operation_deadline_clips_late_consumed_grace() -> anyhow::Result<()> {
        let IssuedOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            caller,
            broker_request,
        } = issued_operation()?;
        let request = pending.request.clone();
        let grant = issued.grant.expose_secret().to_owned();
        let operation_grants = grants.clone();
        let dispatched_at = Instant::now();
        let operation_deadline = dispatched_at + Duration::from_secs(3);
        let (sampled, response) = tokio::sync::oneshot::channel();
        let operation = tokio::spawn(async move {
            let completion = finish_sent_until(
                pending,
                &operation_grants,
                &issued,
                None,
                async {
                    sampled.send(()).expect("sample observer is alive");
                    std::future::pending().await
                },
                WaitLimits {
                    start_deadline: dispatched_at + Duration::from_secs(2),
                    operation_deadline,
                    consumed_grace: Duration::from_secs(10),
                },
            )
            .await;
            (Instant::now(), completion)
        });
        response.await.expect("the initial record was sampled");
        tokio::time::sleep_until(dispatched_at + Duration::from_millis(1200)).await;
        let _record = grants.consume(&grant, &caller, &broker_request)?;
        let (completed_at, completion) =
            tokio::time::timeout_at(operation_deadline + Duration::from_secs(3), operation).await??;

        assert!(operation_deadline <= completed_at);
        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: None,
        };
        assert_eq!(completion.settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn repeated_consumed_samples_do_not_extend_the_grace() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record: _record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let now = Instant::now();
        let settled = tokio::time::timeout(
            Duration::from_secs(3),
            finish_sent_until(
                pending,
                &grants,
                &issued,
                None,
                std::future::pending(),
                WaitLimits {
                    start_deadline: now + Duration::from_secs(1),
                    operation_deadline: now + Duration::from_secs(10),
                    consumed_grace: Duration::from_millis(650),
                },
            ),
        )
        .await?
        .settled;

        assert_eq!(settled, unknown(false));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn missing_broker_record_has_a_bounded_wait() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued: _issued,
            record: _record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        let issued = grants.issue(Plan::parse(&request).expect("request is valid").grant_spec(sid))?;
        let now = Instant::now();
        let settled = tokio::time::timeout(
            Duration::from_secs(3),
            finish_sent_until(
                pending,
                &grants,
                &issued,
                None,
                std::future::pending(),
                WaitLimits {
                    start_deadline: now + Duration::from_millis(500),
                    operation_deadline: now + Duration::from_secs(10),
                    consumed_grace: Duration::from_secs(10),
                },
            ),
        )
        .await?
        .settled;

        assert_eq!(settled, unknown(false));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        Ok(())
    }

    // oracle: mutant a pending delivery is mistaken for a request that was never sent
    #[tokio::test]
    async fn pending_delivery_retains_possible_send_evidence() -> anyhow::Result<()> {
        let (settled, may_have_been_sent) = tracked_delivery_result(std::future::pending()).await?;
        assert_eq!(settled, unknown(false));
        assert!(may_have_been_sent);
        Ok(())
    }

    // oracle: mutant NotSent and Unanswered are treated as the same delivery certainty
    #[rstest::rstest]
    #[case::not_sent(RequestError::NotSent("not sent").into(), false)]
    #[case::unanswered(RequestError::Unanswered("unanswered").into(), true)]
    #[case::unclassified(anyhow::anyhow!("unclassified transport error"), true)]
    #[tokio::test]
    async fn delivery_error_preserves_send_evidence(
        #[case] error: anyhow::Error,
        #[case] expected: bool,
    ) -> anyhow::Result<()> {
        let (settled, may_have_been_sent) = tracked_delivery_result(async move {
            tokio::task::yield_now().await;
            Err(error)
        })
        .await?;
        assert_eq!(settled, unknown(false));
        assert_eq!(may_have_been_sent, expected);
        Ok(())
    }

    // oracle: mutant a failed completion exposes the refresh seam
    #[tokio::test]
    async fn failed_completion_does_not_authorize_refresh() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            ..
        } = sent_operation()?;
        let request = pending.request.clone();
        journal.fail_completion_writes(1);
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let mut may_have_been_sent = false;
        let completion = tokio::time::timeout(
            Duration::from_secs(5),
            finish_sent(
                pending,
                &grants,
                &issued,
                Some(signal),
                track_delivery(&mut may_have_been_sent, async move {
                    shutdown.signal();
                    std::future::pending().await
                }),
            ),
        )
        .await?;

        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(completion.settled, unknown(false));
        assert!(may_have_been_sent);
        assert!(!completion.durably_recorded);
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(unknown(false))
        );
        Ok(())
    }

    // oracle: mutant shutdown reports an unpolled delivery as sent or a pending one as unsent
    #[tokio::test]
    async fn shutdown_retains_the_delivery_poll_evidence() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            pending,
            grants,
            issued,
            ..
        } = sent_operation()?;
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        shutdown.signal();
        let polled = std::cell::Cell::new(false);
        let delivery = std::future::poll_fn(|_| {
            polled.set(true);
            std::task::Poll::Pending
        });
        let mut may_have_been_sent = false;
        let now = Instant::now();
        let settled = finish_sent_until(
            pending,
            &grants,
            &issued,
            Some(signal),
            track_delivery(&mut may_have_been_sent, delivery),
            WaitLimits {
                start_deadline: now + Duration::from_secs(5),
                operation_deadline: now + Duration::from_secs(10),
                consumed_grace: Duration::from_secs(5),
            },
        )
        .await
        .settled;

        assert_eq!(settled, unknown(false));
        assert_eq!(may_have_been_sent, polled.get());
        Ok(())
    }

    // oracle: mutant a delivery that was never polled is mistaken for a possible send
    #[tokio::test]
    async fn unpolled_delivery_has_no_send_evidence() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            pending,
            grants,
            issued: _issued,
            record: _record,
            ..
        } = sent_operation()?;
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        let issued = grants.issue(Plan::parse(&pending.request).expect("request is valid").grant_spec(sid))?;
        let mut may_have_been_sent = false;
        let now = Instant::now();
        let settled = finish_sent_until(
            pending,
            &grants,
            &issued,
            None,
            track_delivery(&mut may_have_been_sent, async {
                panic!("an expired wait must not poll its delivery")
            }),
            WaitLimits {
                start_deadline: now,
                operation_deadline: now + Duration::from_secs(5),
                consumed_grace: Duration::from_secs(5),
            },
        )
        .await
        .settled;
        assert_eq!(settled, unknown(false));
        assert!(!may_have_been_sent);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn shutdown_records_unknown_with_broker_start_evidence() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let (delivered, response) = tokio::sync::oneshot::channel();
        assert!(record.mark_started());
        let operation = tokio::spawn(async move {
            finish_sent(pending, &grants, &issued, Some(signal), async {
                delivered.send(()).expect("delivery observer is alive");
                Ok(serde_json::json!({"status": "Unknown"}))
            })
            .await
        });
        response.await.expect("request is delivered");

        shutdown.signal();
        let settled = tokio::time::timeout(Duration::from_secs(5), operation).await??.settled;
        assert_eq!(settled, unknown(true));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        tokio::time::timeout(Duration::from_secs(5), shutdown.all_closed()).await?;
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn shutdown_final_sample_records_first_start_evidence() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let completion = tokio::time::timeout(
            Duration::from_secs(5),
            finish_sent(pending, &grants, &issued, Some(signal), async {
                shutdown.signal();
                assert!(record.mark_started());
                std::future::pending().await
            }),
        )
        .await?;

        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: Some(true),
        };
        assert_eq!(completion.settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        tokio::time::timeout(Duration::from_secs(5), shutdown.all_closed()).await?;
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn evicted_started_record_retains_start_evidence() -> anyhow::Result<()> {
        let IssuedOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            caller,
            mut broker_request,
        } = issued_operation()?;
        let request = pending.request.clone();
        let record = grants.consume(issued.grant.expose_secret(), &caller, &broker_request)?;
        assert!(record.mark_started());
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        let spec = Plan::parse(&request).expect("request is valid").grant_spec(sid);
        let (sampled, response) = tokio::sync::oneshot::channel();
        let now = Instant::now();
        let wait = async {
            Ok::<_, anyhow::Error>(
                finish_sent_until(
                    pending,
                    &grants,
                    &issued,
                    None,
                    async {
                        sampled.send(()).expect("sample observer is alive");
                        std::future::pending().await
                    },
                    WaitLimits {
                        start_deadline: now + Duration::from_secs(5),
                        operation_deadline: now + Duration::from_secs(30),
                        consumed_grace: Duration::from_secs(5),
                    },
                )
                .await,
            )
        };
        let evict = async {
            response.await.expect("start evidence was sampled");
            for _ in 0..10_000 {
                let replacement = grants.issue(spec.clone())?;
                broker_request.request_id = api::ResourceId::from(replacement.request_id.to_string().as_str());
                grants.consume(replacement.grant.expose_secret(), &caller, &broker_request)?;
                if grants.outcome(&issued.grant, &issued.request_id) == OutcomeSummary::Unknown {
                    return Ok::<_, anyhow::Error>(());
                }
            }
            anyhow::bail!("could not evict the started Broker record")
        };
        let (completion, ()) =
            tokio::time::timeout(Duration::from_secs(10), async { tokio::try_join!(wait, evict) }).await??;

        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: Some(true),
        };
        assert_eq!(completion.settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn start_evidence_survives_interrupted_wait() -> anyhow::Result<()> {
        let SentOperation {
            _root: root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let (delivered, response) = tokio::sync::oneshot::channel();
        assert!(record.mark_started());
        let operation = tokio::spawn(async move {
            finish_sent(pending, &grants, &issued, None, async {
                delivered.send(()).expect("delivery observer is alive");
                Ok(serde_json::json!({"status": "Unknown"}))
            })
            .await
        });
        response.await.expect("request is delivered");

        operation.abort();
        assert!(operation.await.expect_err("wait is interrupted").is_cancelled());
        drop(journal);
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        assert_eq!(
            reopened.admit("authority", &request)?,
            Admission::Recorded(unknown(true))
        );
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn final_unknown_retains_observed_start_after_start_writes_fail() -> anyhow::Result<()> {
        let SentOperation {
            _root: root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        assert!(record.mark_started());
        journal.fail_start_writes(2);

        let completion = finish_sent(pending, &grants, &issued, None, std::future::pending()).await;

        // oracle: mutant a completed journal write is mistaken for failure after a start-write error
        assert!(completion.durably_recorded);
        assert_eq!(completion.settled, unknown(true));
        drop(journal);
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        assert_eq!(
            reopened.admit("authority", &request)?,
            Admission::Recorded(completion.settled)
        );
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn consumed_operation_without_start_times_out_unknown() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record: _record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let (delivered, response) = tokio::sync::oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut operation = tokio::spawn(async move {
            finish_sent_until(
                pending,
                &grants,
                &issued,
                None,
                async {
                    delivered.send(()).expect("delivery observer is alive");
                    Ok(serde_json::json!({"status": "Succeeded"}))
                },
                WaitLimits {
                    start_deadline: deadline,
                    operation_deadline: deadline + Duration::from_secs(1),
                    consumed_grace: Duration::from_secs(10),
                },
            )
            .await
        });
        response.await.expect("request is delivered");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut operation)
                .await
                .is_err()
        );
        let settled = tokio::time::timeout(Duration::from_secs(5), operation).await??.settled;
        assert_eq!(settled, unknown(false));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        Ok(())
    }

    #[rstest::rstest]
    #[case::powershell5("winps", ManagerName::PowerShell, "PowerShell")]
    #[case::powershell7("pwsh", ManagerName::PowerShell7, "PowerShell7")]
    #[case::dotnet("dotnet-tool", ManagerName::Dotnet, "Dotnet")]
    #[case::case_insensitive("WINPS", ManagerName::PowerShell, "PowerShell")]
    fn inventory_manager_ids_select_broker_managers(
        #[case] inventory_id: &str,
        #[case] manager: ManagerName,
        #[case] canonical_name: &str,
    ) {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let plan = Plan::parse(&request(PackageOperationType::Install, inventory_id, "source", "user"))
            .expect("inventory manager id is accepted");
        assert_eq!(plan.manager, manager);
        assert_eq!(
            plan.arguments("operation", &Uuid::nil(), "grant")["manager"],
            canonical_name
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn winget_install_binds_no_upgrade_and_elevation_to_scope() {
        let user = Plan::parse(&request(PackageOperationType::Install, "winget", "winget", "USER"))
            .expect("user-scope winget install is accepted");
        assert_eq!(
            (user.manager, user.scope, user.requested_elevation),
            (ManagerName::Winget, Scope::User, Elevation::Standard)
        );
        assert!(user.no_upgrade);

        let machine = Plan::parse(&request(PackageOperationType::Install, "Winget", "winget", "machine"))
            .expect("machine-scope winget install is accepted");
        assert_eq!(
            (machine.scope, machine.requested_elevation),
            (Scope::Machine, Elevation::Elevated)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn no_upgrade_is_set_only_for_winget_install() {
        let update = Plan::parse(&request(PackageOperationType::Update, "Winget", "", "user"))
            .expect("winget update is accepted");
        let other = Plan::parse(&request(PackageOperationType::Install, "Scoop", "main", "user"))
            .expect("scoop install is accepted");
        assert!(!update.no_upgrade && !other.no_upgrade);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn update_requires_and_forwards_the_selected_raw_scope() {
        let mut request = request(PackageOperationType::Update, "Pip", "", "user");
        request.reported_scope = None;
        assert!(Plan::parse(&request).is_err());

        request.reported_scope = Some("Local".to_owned());
        let plan = Plan::parse(&request).expect("update with a scope is accepted");
        let arguments = plan.arguments("op-1", &Uuid::nil(), "secret");
        assert_eq!(arguments["reportedScope"], "Local");

        request.reported_scope = Some(String::new());
        let plan = Plan::parse(&request).expect("update with an empty scope is accepted");
        assert_eq!(plan.arguments("op-1", &Uuid::nil(), "secret")["reportedScope"], "");
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn an_install_omits_the_selected_row_scope() {
        let mut request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let plan = Plan::parse(&request).expect("install without a row scope is accepted");
        assert!(
            plan.arguments("op-1", &Uuid::nil(), "secret")
                .get("reportedScope")
                .is_none()
        );

        request.reported_scope = Some(String::new());
        assert!(Plan::parse(&request).is_err());
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn winget_machine_operations_use_the_administrators_scope() {
        for operation in [PackageOperationType::Update, PackageOperationType::Uninstall] {
            let mut request = request(operation, "Winget", "", "machine");
            request.reported_scope = Some(String::new());
            let plan = Plan::parse(&request).expect("winget machine operation is accepted");
            assert_eq!(plan.scope, Scope::Machine);
            assert_eq!(plan.requested_elevation, Elevation::Elevated);
            let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
            assert_eq!(plan.grant_spec(sid).scope, Some(Scope::Machine));
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn reported_scope_selects_powershell_rows_without_elevating() {
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        for (manager, operation) in [
            ("PowerShell", PackageOperationType::Update),
            ("PowerShell7", PackageOperationType::Update),
            ("PowerShell7", PackageOperationType::Uninstall),
        ] {
            let mut request = request(operation, manager, "", "user");
            request.reported_scope = Some("mAcHiNe".to_owned());
            let plan = Plan::parse(&request).expect("powershell machine row is accepted");
            let spec = plan.grant_spec(sid.clone());
            assert_eq!(spec.scope, Some(Scope::Machine));
            assert_eq!(spec.requested_elevation, Elevation::Standard);

            request.reported_scope = Some("USER".to_owned());
            assert_eq!(
                Plan::parse(&request)
                    .expect("powershell user row is accepted")
                    .grant_spec(sid.clone())
                    .scope,
                Some(Scope::User)
            );

            request.reported_scope = Some(String::new());
            assert_eq!(
                Plan::parse(&request)
                    .expect("powershell empty row scope is accepted")
                    .grant_spec(sid.clone())
                    .scope,
                None
            );

            request.reported_scope = Some("other".to_owned());
            assert!(Plan::parse(&request).is_err());
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn no_selector_uses_user_broker_scope_and_keeps_raw_row_scope() {
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        for manager in ["Pip", "PowerShell"] {
            let mut request = request(PackageOperationType::Uninstall, manager, "", "user");
            request.reported_scope = Some("machine".to_owned());
            let plan = Plan::parse(&request).expect("uninstall without selector is accepted");

            assert_eq!(plan.grant_spec(sid.clone()).scope, Some(Scope::User));
            assert_eq!(
                plan.arguments("op-1", &Uuid::nil(), "secret")["reportedScope"],
                "machine"
            );
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn rejects_requests_the_grant_cannot_bind() {
        let cases = [
            request(PackageOperationType::Install, "winget", "winget", ""),
            request(PackageOperationType::Install, "winget", "winget", "global"),
            request(PackageOperationType::Install, "npm", "npm", "machine"),
            request(PackageOperationType::Install, "Chocolatey", "chocolatey", "user"),
            request(PackageOperationType::Install, "apt", "main", "user"),
            request(PackageOperationType::Install, "winget", "", "user"),
            request(PackageOperationType::Uninstall, "winget", "winget", "user"),
            PackageOperationRequest {
                version: "1.0".to_owned(),
                ..request(PackageOperationType::Uninstall, "winget", "", "user")
            },
            PackageOperationRequest {
                package_id: String::new(),
                ..request(PackageOperationType::Update, "winget", "", "user")
            },
            PackageOperationRequest {
                r#type: 99,
                ..request(PackageOperationType::Update, "winget", "", "user")
            },
        ];
        for case in cases {
            assert!(Plan::parse(&case).is_err(), "{case:?}");
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn preserves_version_and_empty_update_source() {
        let plan = Plan::parse(&PackageOperationRequest {
            version: "1.2.3-beta".to_owned(),
            ..request(PackageOperationType::Update, "Scoop", "", "user")
        })
        .expect("update with a version is accepted");
        assert_eq!(plan.source_name, "");
        let arguments = plan.arguments("op-1", &Uuid::nil(), "secret");
        assert_eq!(arguments["version"], "1.2.3-beta");
        assert_eq!(arguments["operation"], "Update");
        assert_eq!(arguments["manager"], "Scoop");
        assert_eq!(arguments["scope"], "User");
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn results_report_recorded_outcomes() {
        let unknown = result("op".to_owned(), unknown(true));
        assert_eq!(unknown.status, i32::from(PackageOperationStatus::Unknown));
        assert!(!unknown.success);
        assert_eq!(unknown.execution_started, Some(true));

        let failure = result(
            "op".to_owned(),
            Settled {
                outcome: failure("nope"),
                execution_started: None,
            },
        );
        assert_eq!(failure.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(
            (failure.success, failure.error.as_str(), failure.execution_started),
            (false, "nope", None)
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn dropped_guard_ends_the_in_flight_record_as_unknown() {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("op-{}", Uuid::new_v4().simple()));
        let data = camino::Utf8PathBuf::from_path_buf(base.join("data")).expect("data path is UTF-8");
        let journal = Arc::new(OperationJournal::open(&data).expect("journal opens"));
        let request = request(PackageOperationType::Install, "winget", "winget", "user");

        assert_eq!(
            journal.admit("authority", &request).expect("operation is admitted"),
            Admission::Admitted
        );
        drop(Pending {
            journal: Arc::clone(&journal),
            authority_id: "authority".to_owned(),
            request: request.clone(),
            armed: true,
        });

        let settled = journal.wait("authority", &request).expect("outcome is settled");
        assert_eq!(settled.outcome, Outcome::Unknown);
        assert_eq!(
            journal.admit("authority", &request).expect("operation is recorded"),
            Admission::Recorded(settled)
        );

        drop(journal);
        let _ = std::fs::remove_dir_all(base);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn operation_without_a_journal_is_unknown_and_never_dispatched() {
        let result = run(
            &DeviceManagementContext::default(),
            Uuid::nil(),
            request(PackageOperationType::Install, "winget", "winget", "user"),
        )
        .await;
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        assert_eq!(result.execution_started, None);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn outcome_write_failure_reports_unknown() {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("op-{}", Uuid::new_v4().simple()));
        let data = camino::Utf8PathBuf::from_path_buf(base.join("data")).expect("data path is UTF-8");
        let journal = Arc::new(OperationJournal::open(&data).expect("journal opens"));
        let request = request(PackageOperationType::Install, "winget", "winget", "user");
        assert_eq!(
            journal.admit("authority", &request).expect("operation is admitted"),
            Admission::Admitted
        );
        let records = data.join("package-operations").join("records");
        let record = std::fs::read_dir(records)
            .expect("records directory is readable")
            .map(|entry| entry.expect("record entry is readable").path())
            .find(|path| path.file_name().expect("record has a file name") != "journal.json")
            .expect("operation record exists");
        std::fs::remove_file(record).expect("record is removed");
        let pending = Pending {
            journal: Arc::clone(&journal),
            authority_id: "authority".to_owned(),
            request,
            armed: true,
        };

        let settled = pending.finish(failure("not dispatched"), false).await;

        assert_eq!(settled.outcome, Outcome::Unknown);
        drop(journal);
        let _ = std::fs::remove_dir_all(base);
    }
}
