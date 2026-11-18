//! Remote package operations: journaling, grant issuing and delivery to one UniGetUI instance.
//!
//! The Broker's in-process record of the issued grant is the only source of start evidence.
//! Once the grant may have reached UniGetUI, the verdict is unknown whatever UniGetUI answers or fails to answer.

use std::sync::Arc;

use agent_channel_proto::{
    PackageOperationRequest, PackageOperationResult, PackageOperationStatus, PackageOperationType,
};
use now_package_broker::remote_grant::{GrantSpec, OutcomeSummary};
use now_policy_api::{Elevation, ManagerName, Operation, PackageIdentifier, Scope, VersionString};
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
            // UNTESTED: A refused admission must issue no grant and dispatch no request.
            // The context test has no live endpoint; count grants and requests when changing this return.
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

/// An admitted operation whose in-flight record must end, even when its task panics or is dropped.
struct Pending {
    journal: Arc<OperationJournal>,
    authority_id: String,
    request: PackageOperationRequest,
    armed: bool,
}

impl Pending {
    /// Records the end of the operation; a record that cannot be written leaves the unknown outcome to later deliveries.
    #[expect(
        unused_assignments,
        reason = "the closure captures all of `self` because `Pending` implements `Drop`, and `drop` reads `armed`"
    )]
    async fn finish(mut self, outcome: Outcome, started: bool) -> Settled {
        let recorded = outcome.clone();
        let written = tokio::task::spawn_blocking(move || {
            let start_recorded = if started {
                self.journal.mark_started(&self.authority_id, &self.request)
            } else {
                Ok(())
            };
            let result = self.journal.complete(&self.authority_id, &self.request, recorded);
            self.armed = false;
            start_recorded.and(result)
        })
        .await;
        match written {
            Ok(Ok(())) => Settled {
                outcome,
                execution_started: started.then_some(true),
            },
            Ok(Err(error)) => {
                error!(error = format!("{error:#}"), "Cannot record package operation outcome");
                unknown(started)
            }
            Err(_) => {
                error!("Recording the package operation outcome was interrupted");
                unknown(started)
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
    if endpoint.request("ExecutePackageOperation", arguments).await.is_err() {
        debug!("ExecutePackageOperation produced no usable response");
    }

    let started = matches!(
        broker.remote_grants.outcome(&issued.grant, &issued.request_id),
        OutcomeSummary::Started | OutcomeSummary::Exited { .. }
    );
    pending.finish(Outcome::Unknown, started).await
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
