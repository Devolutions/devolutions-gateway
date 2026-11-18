//! Remote package operations: journaling, grant issuing and delivery to one UniGetUI instance.
//!
//! The Broker's in-process record of the issued grant is the only source of start evidence.
//! Once the grant may have reached UniGetUI, its response alone cannot establish the outcome.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use agent_channel_proto::{
    PackageOperationRequest, PackageOperationResult, PackageOperationStatus, PackageOperationType,
};
use devolutions_gateway_task::ShutdownSignal;
use futures::FutureExt as _;
use now_package_broker::registration::RequestError;
use now_package_broker::remote_grant::{GrantSpec, IssuedGrant, OutcomeSummary, RemoteGrantStore};
use now_policy_api::{Elevation, ManagerName, Operation, PackageIdentifier, Scope, VersionString};
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;
use win_api_wrappers::identity::sid::Sid;

use super::DeviceManagementContext;
use super::operation_journal::{Admission, DeliveryKey, OperationJournal, Outcome, Settled, record_name};

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
const JOURNAL_WARNING_DELAY: Duration = Duration::from_secs(5);
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

type Reply = Box<dyn FnOnce(PackageOperationResult) + Send>;

pub(super) const JOURNAL_FULL_ERROR: &str = "agent journal full: nothing was started";

struct Delivery {
    authority_id: String,
    key: DeliveryKey,
    reply: Reply,
}

#[derive(Clone, Copy)]
enum Stage {
    Lookup,
    Admission,
    Running,
}

struct Tracked {
    delivery: Delivery,
    stage: Stage,
}

/// Record names awaiting a journal lookup, served one at a time by a single task.
#[derive(Default)]
struct Lookups {
    pending: VecDeque<(Arc<OperationJournal>, String)>,
    draining: bool,
}

/// Coordinates journal lookups and operations without blocking the channel consumer.
pub(super) struct Coordinator {
    workers: Arc<Semaphore>,
    admission: Arc<Semaphore>,
    tracked: Mutex<HashMap<String, Tracked>>,
    lookups: Mutex<Lookups>,
}

impl Default for Coordinator {
    fn default() -> Self {
        Self {
            workers: Arc::new(Semaphore::new(super::MAX_CONCURRENT_REQUESTS)),
            admission: Arc::new(Semaphore::new(1)),
            tracked: Mutex::new(HashMap::new()),
            lookups: Mutex::new(Lookups::default()),
        }
    }
}

impl Coordinator {
    pub(super) fn try_worker(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.workers).try_acquire_owned().ok()
    }

    fn submit<F, Fut>(
        self: &Arc<Self>,
        journal: Arc<OperationJournal>,
        authority_id: String,
        request: PackageOperationRequest,
        reply: Reply,
        execute: F,
    ) where
        F: FnOnce(Pending) -> Fut + Send + 'static,
        Fut: Future<Output = Settled> + Send + 'static,
    {
        let operation_id = request.operation_id.clone();
        let name = record_name(&operation_id);
        let key = DeliveryKey::new(&request);
        let mut tracked = self.tracked.lock();
        if let Some(existing) = tracked.get_mut(&name) {
            if !matches!(existing.stage, Stage::Lookup) && existing.delivery.key != key {
                drop(tracked);
                warn!("Package operation ID was used for a different request");
                reply(result(operation_id, unknown(false)));
                return;
            }
            existing.delivery = Delivery {
                authority_id,
                key,
                reply,
            };
            return;
        }

        if journal.may_contain(&operation_id) {
            // A delivery awaiting its lookup keeps only its key and reply, and adds no task of its own.
            tracked.insert(
                name.clone(),
                Tracked {
                    delivery: Delivery {
                        authority_id,
                        key,
                        reply,
                    },
                    stage: Stage::Lookup,
                },
            );
            drop(tracked);
            let mut lookups = self.lookups.lock();
            lookups.pending.push_back((journal, name));
            if !lookups.draining {
                lookups.draining = true;
                drop(lookups);
                let coordinator = Arc::clone(self);
                tokio::spawn(async move {
                    coordinator.drain_lookups().await;
                });
            }
            return;
        }

        // INVARIANT: The tracked lock stays held from this check through worker acquisition.
        // A queued admission rechecks capacity after acquiring the I/O permit.
        if !journal.has_index_capacity(&name) {
            drop(tracked);
            reply(result(operation_id, journal_full()));
            return;
        }

        let Some(worker) = self.try_worker() else {
            drop(tracked);
            reply(result(
                operation_id,
                Settled {
                    outcome: failure("agent busy: nothing was started"),
                    execution_started: None,
                },
            ));
            return;
        };
        tracked.insert(
            name,
            Tracked {
                delivery: Delivery {
                    authority_id: authority_id.clone(),
                    key,
                    reply,
                },
                stage: Stage::Admission,
            },
        );
        drop(tracked);
        let coordinator = Arc::clone(self);
        tokio::spawn(async move {
            coordinator.admit(journal, authority_id, request, worker, execute).await;
        });
    }

    async fn drain_lookups(self: Arc<Self>) {
        loop {
            let next = {
                let mut lookups = self.lookups.lock();
                let next = lookups.pending.pop_front();
                lookups.draining = next.is_some();
                next
            };
            let Some((journal, name)) = next else {
                return;
            };
            Arc::clone(&self).lookup(journal, name).await;
        }
    }

    async fn lookup(self: Arc<Self>, journal: Arc<OperationJournal>, name: String) {
        enum Decision {
            Retry,
            Wait,
        }

        loop {
            let admission = Arc::clone(&self.admission)
                .acquire_owned()
                .await
                .expect("admission semaphore stays open");
            let (authority_id, key) = {
                let tracked = self.tracked.lock();
                let delivery = &tracked.get(&name).expect("lookup is tracked").delivery;
                (delivery.authority_id.clone(), delivery.key.clone())
            };
            let lookup = {
                let (journal, authority_id, key) = (Arc::clone(&journal), authority_id.clone(), key.clone());
                journal_io(move || journal.lookup(&authority_id, &key)).await
            };
            let lookup = match lookup {
                Ok(Ok(Some(admission))) => Some(admission),
                Ok(Ok(None)) => {
                    error!("Possibly recorded package operation is absent from the journal");
                    None
                }
                Ok(Err(error)) => {
                    error!(error = format!("{error:#}"), "Package operation journal lookup failed");
                    None
                }
                Err(error) => {
                    error!(%error, "Package operation journal lookup was interrupted");
                    None
                }
            };

            let decision = {
                let mut tracked = self.tracked.lock();
                let current = tracked.get_mut(&name).expect("lookup is tracked");
                if current.delivery.key != key {
                    Decision::Retry
                } else if matches!(lookup, Some(Admission::InFlight)) {
                    current.stage = Stage::Running;
                    Decision::Wait
                } else {
                    let settled = match lookup {
                        Some(Admission::Recorded(settled)) => settled,
                        Some(Admission::PayloadMismatch) => {
                            warn!("Package operation ID was used for a different request");
                            unknown(false)
                        }
                        Some(Admission::Admitted) => {
                            error!("Read-only package operation lookup admitted an operation");
                            unknown(false)
                        }
                        Some(Admission::InFlight) => unreachable!("in-flight lookup is handled above"),
                        None => unknown(false),
                    };
                    let delivery = tracked.remove(&name).expect("lookup is tracked").delivery;
                    drop(tracked);
                    drop(admission);
                    (delivery.reply)(result(delivery.key.operation_id().to_owned(), settled));
                    return;
                }
            };
            drop(admission);
            match decision {
                Decision::Retry => continue,
                Decision::Wait => {
                    // An in-flight operation can run for minutes, so its waiter leaves the lookup queue.
                    // Waiters are bounded by the operations in flight, one tracked entry each.
                    tokio::spawn(async move {
                        let settled = wait(journal, authority_id, key).await;
                        self.finish(name, settled);
                    });
                    return;
                }
            }
        }
    }

    async fn admit<F, Fut>(
        self: Arc<Self>,
        journal: Arc<OperationJournal>,
        authority_id: String,
        request: PackageOperationRequest,
        worker: OwnedSemaphorePermit,
        execute: F,
    ) where
        F: FnOnce(Pending) -> Fut + Send + 'static,
        Fut: Future<Output = Settled> + Send + 'static,
    {
        let name = record_name(&request.operation_id);
        // The operation gives the permit back once its completion write returned.
        // Until then it stays here, so that the cleanup of an interrupted operation still runs with it.
        let worker = WorkerSlot::new(Mutex::new(Some(worker)));
        let admission = Arc::clone(&self.admission)
            .acquire_owned()
            .await
            .expect("admission semaphore stays open");
        // An earlier admission may have used the last index space while this one waited.
        if !journal.has_index_capacity(&name) {
            drop(admission);
            drop(worker);
            self.finish(name, journal_full());
            return;
        }
        let outcome = {
            let (journal, authority_id, request) = (Arc::clone(&journal), authority_id.clone(), request.clone());
            journal_io(move || journal.admit(&authority_id, &request)).await
        };
        let outcome = match outcome {
            Ok(Ok(outcome)) => Some(outcome),
            Ok(Err(error)) => {
                error!(
                    error = format!("{error:#}"),
                    "Package operation journal admission failed"
                );
                None
            }
            Err(error) => {
                error!(%error, "Package operation journal admission was interrupted");
                None
            }
        };
        let settled = match outcome {
            Some(Admission::Admitted) => {
                let pending = Pending {
                    journal: Arc::clone(&journal),
                    authority_id: authority_id.clone(),
                    request: request.clone(),
                    armed: true,
                    worker: Arc::clone(&worker),
                };
                self.running(&name);
                drop(admission);
                match tokio::spawn(execute(pending)).await {
                    Ok(settled) => settled,
                    Err(error) => {
                        error!(%error, "Package operation task was interrupted");
                        let cleanup = {
                            let (journal, authority_id, request) =
                                (Arc::clone(&journal), authority_id.clone(), request.clone());
                            journal_io(move || journal.complete(&authority_id, &request, Outcome::Unknown)).await
                        };
                        match cleanup {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) | Err(error) => {
                                error!(
                                    error = format!("{error:#}"),
                                    "Cannot record an interrupted package operation"
                                );
                            }
                        }
                        wait(journal, authority_id, DeliveryKey::new(&request)).await
                    }
                }
            }
            Some(Admission::InFlight) => {
                self.running(&name);
                drop(admission);
                wait(journal, authority_id, DeliveryKey::new(&request)).await
            }
            Some(Admission::Recorded(settled)) => settled,
            Some(Admission::PayloadMismatch) => {
                warn!("Package operation ID was used for a different request");
                unknown(false)
            }
            None => unknown(false),
        };
        drop(worker);
        self.finish(name, settled);
    }

    fn running(&self, name: &str) {
        self.tracked.lock().get_mut(name).expect("operation is tracked").stage = Stage::Running;
    }

    fn finish(&self, name: String, settled: Settled) {
        let delivery = self
            .tracked
            .lock()
            .remove(&name)
            .expect("operation is tracked")
            .delivery;
        (delivery.reply)(result(delivery.key.operation_id().to_owned(), settled));
    }
}

async fn journal_io<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> anyhow::Result<T> {
    let mut task = tokio::task::spawn_blocking(work);
    let result = tokio::select! {
        biased;
        result = &mut task => result,
        () = tokio::time::sleep(JOURNAL_WARNING_DELAY) => {
            warn!(
                elapsed_secs = JOURNAL_WARNING_DELAY.as_secs(),
                "Package operation journal access is stalled"
            );
            task.await
        }
    };
    Ok(result?)
}

pub(super) fn submit(
    context: DeviceManagementContext,
    authority_id: Uuid,
    request: PackageOperationRequest,
    reply: Reply,
) {
    let Some(journal) = context.journal().cloned() else {
        reply(result(request.operation_id, unknown(false)));
        return;
    };
    let coordinator = Arc::clone(context.operations());
    coordinator.submit(journal, authority_id.to_string(), request, reply, move |pending| {
        execute(context, pending)
    });
}

async fn wait(journal: Arc<OperationJournal>, authority_id: String, key: DeliveryKey) -> Settled {
    match tokio::task::spawn_blocking(move || journal.wait(&authority_id, &key)).await {
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

/// The worker permit of an admitted operation, shared by its admission and its task.
type WorkerSlot = Arc<Mutex<Option<OwnedSemaphorePermit>>>;

/// An admitted operation whose in-flight record must end, even when its task panics or is dropped.
struct Pending {
    journal: Arc<OperationJournal>,
    authority_id: String,
    request: PackageOperationRequest,
    armed: bool,
    /// Emptied once the completion write returned, so that what follows the record holds no operation worker.
    worker: WorkerSlot,
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

    /// Records the end of the operation.
    /// A failed write reports an unknown outcome for this delivery.
    async fn finish(self, outcome: Outcome, started: bool) -> Settled {
        self.finish_with_durability(outcome, started).await.settled
    }

    #[expect(
        unused_assignments,
        reason = "the closure captures all of `self` because `Pending` implements `Drop`, and `drop` reads `armed`"
    )]
    async fn finish_with_durability(mut self, outcome: Outcome, started: bool) -> Completion {
        let recorded = outcome.clone();
        let worker = Arc::clone(&self.worker);
        let written = tokio::task::spawn_blocking(move || {
            let start_recorded = if started {
                self.journal.mark_started(&self.authority_id, &self.request)
            } else {
                Ok(())
            };
            // UNTESTED: A failed start write can already have installed start evidence.
            // A successful completion must retain the observed outcome; inject a post-install failure when changing this.
            let result = self
                .journal
                .complete_with_started(&self.authority_id, &self.request, recorded, started);
            self.armed = false;
            (start_recorded, result)
        })
        .await;
        // INVARIANT: An operation task without its worker permit holds a waiting-rescan permit or awaits nothing until it returns.
        // The permit is given back only here, once the completion write returned, and the rescan wait, the only thing awaited afterwards, takes its permit first.
        // UNTESTED: An operation task cancelled after this point, as when the runtime shuts down during the rescan wait, leaves its admission to clean up without a worker permit.
        // The cleanup write then finds the recorded outcome, and the journal wait returns it.
        // No permit bounds that journal I/O, which is acceptable only at shutdown, and the recorded result must not be replaced by an unknown one.
        // The tests interrupt a recorded operation only with a panic.
        // Check that a cancellation still reports the recorded result, and that nothing else cancels the task while the Agent keeps running, when changing this.
        drop(worker.lock().take());
        match written {
            Ok((start_recorded, result)) => {
                let durably_recorded = result.is_ok();
                if let Err(error) = &start_recorded {
                    error!(error = format!("{error:#}"), "Cannot record package operation start");
                }
                if let Err(error) = &result {
                    error!(error = format!("{error:#}"), "Cannot record package operation outcome");
                }
                let settled = if durably_recorded {
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
        if self.armed {
            let journal = Arc::clone(&self.journal);
            let authority_id = self.authority_id.clone();
            let request = self.request.clone();
            // UNTESTED: A detached cleanup must not delay service stop if journal I/O never returns.
            // Check service shutdown with stalled journal I/O when changing this path.
            if let Err(error) = std::thread::Builder::new()
                .name("package-operation-cleanup".to_owned())
                .spawn(move || {
                    if let Err(error) = journal.complete(&authority_id, &request, Outcome::Unknown) {
                        error!(
                            error = format!("{error:#}"),
                            "Cannot record an interrupted package operation"
                        );
                    }
                })
            {
                error!(%error, "Cannot start interrupted package operation cleanup");
            }
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
    // UNTESTED: The rescan is asked of the endpoint that carried the request, only while remote inventory is enabled, with the limits of the one dispatch instant.
    // Another endpoint would rescan another user's instance, a disabled inventory must cause no scan, and a second clock would hold the result past its deadline.
    // The tests cannot build a registered endpoint, so none runs this function.
    // Check that the request and the rescan name the same `endpoint`, that `enabled` is the context's remote-inventory setting, and that the instant is taken once, right before the request.
    finish_dispatched(
        pending,
        &broker.remote_grants,
        &issued,
        context.shutdown(),
        endpoint.request("ExecutePackageOperation", arguments),
        WaitLimits::after_dispatch(Instant::now()),
        RescanAfter {
            enabled: context.remote_inventory_enabled(),
            endpoint: &endpoint,
            waiting: super::rescan::waiting_rescans(),
        },
    )
    .await
}

/// Whether and where the rescan that follows a dispatched operation is requested.
struct RescanAfter<'a, E> {
    /// Tells whether remote inventory is enabled, without which no rescan is requested.
    enabled: bool,
    /// The connection that carried the operation.
    endpoint: &'a E,
    /// The permits of the operations that wait for a rescan.
    waiting: &'a Semaphore,
}

/// Settles an operation whose request `delivery` dispatches, then waits for UniGetUI to rescan.
///
/// The rescan is requested only once the journal holds the final result, and only when the request may have been written.
/// Its outcome never changes the result, which is returned as recorded.
/// The wait holds no operation worker, because `pending` gives its permit back once the result is recorded.
async fn finish_dispatched<E: super::rescan::RescanEndpoint>(
    pending: Pending,
    grants: &RemoteGrantStore,
    issued: &IssuedGrant,
    shutdown: Option<ShutdownSignal>,
    delivery: impl Future<Output = anyhow::Result<serde_json::Value>>,
    limits: WaitLimits,
    rescan: RescanAfter<'_, E>,
) -> Settled {
    // The rescan wait ends at the operation's own deadline, so both are measured from the one dispatch instant.
    let rescan_deadline = limits.operation_deadline;
    let mut may_have_been_sent = false;
    // The outcome wait consumes its own signal, so a shutdown that ended it is still seen below.
    let completion = finish_sent_until(
        pending,
        grants,
        issued,
        shutdown.clone(),
        track_delivery(&mut may_have_been_sent, delivery),
        limits,
    )
    .await;
    if completion.durably_recorded && may_have_been_sent && rescan.enabled {
        let stopping = async {
            match shutdown {
                Some(mut signal) => signal.wait().await,
                None => std::future::pending().await,
            }
        };
        let wait = super::rescan::after_operation(rescan.waiting, rescan.endpoint, rescan_deadline, stopping);
        // The result is recorded, so a panic in the wait must not interrupt the operation's task.
        // Its admission would otherwise clean up after it, with journal I/O that no permit bounds, and log a recorded operation as interrupted.
        if std::panic::AssertUnwindSafe(wait).catch_unwind().await.is_err() {
            error!("Waiting for the UniGetUI rescan panicked");
        }
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

struct WaitLimits {
    start_deadline: Instant,
    operation_deadline: Instant,
    consumed_grace: Duration,
}

impl WaitLimits {
    /// Returns the limits of an operation whose request is dispatched at `dispatched_at`.
    fn after_dispatch(dispatched_at: Instant) -> Self {
        Self {
            start_deadline: dispatched_at + START_WAIT,
            operation_deadline: dispatched_at + OPERATION_WAIT,
            consumed_grace: START_WAIT,
        }
    }
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
            OutcomeSummary::Started if !started => {
                saw_record = true;
                started = true;
                if !pending.mark_started().await {
                    break;
                }
                continue;
            }
            OutcomeSummary::Started => {}
            OutcomeSummary::Exited { exit_code } => {
                started = true;
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

fn outcome_for_exit(manager: &str, exit_code: i32) -> Outcome {
    match exit_code {
        0 => Outcome::Succeeded,
        // Windows exit codes are DWORDs; the Authority parses the unsigned decimal value.
        _ => Outcome::Failed {
            error: format!("{manager} exited with code {}", exit_code.cast_unsigned()),
        },
    }
}

fn journal_full() -> Settled {
    Settled {
        outcome: failure(JOURNAL_FULL_ERROR),
        execution_started: None,
    }
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
pub(super) async fn run(
    context: &DeviceManagementContext,
    authority_id: Uuid,
    request: PackageOperationRequest,
) -> PackageOperationResult {
    let operation_id = request.operation_id.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    submit(
        context.clone(),
        authority_id,
        request,
        Box::new(move |result| {
            let _ = send.send(result);
        }),
    );
    receive.await.unwrap_or_else(|_| result(operation_id, unknown(false)))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use now_package_broker::remote_grant::{ExecutionRecord, VerifiedCaller};
    use now_policy_api as api;

    use super::super::rescan::RescanEndpoint;
    use super::super::test_tempdir;
    use super::*;

    /// Bounds a wait that must end, generously enough to absorb slow journal I/O.
    const SETTLE_GUARD: Duration = Duration::from_secs(30);

    fn request(operation: PackageOperationType, manager: &str, source: &str, scope: &str) -> PackageOperationRequest {
        PackageOperationRequest {
            operation_id: "11111111-2222-4333-8444-555555555555".to_owned(),
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
        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let journal = Arc::new(OperationJournal::open(data)?);
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        assert_eq!(journal.admit("authority", &request)?, Admission::Admitted);
        let pending = Pending {
            journal: Arc::clone(&journal),
            authority_id: "authority".to_owned(),
            request: request.clone(),
            armed: true,
            worker: WorkerSlot::default(),
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

    async fn wait_for_detached_cleanup(
        journal: Arc<OperationJournal>,
        request: &PackageOperationRequest,
    ) -> anyhow::Result<()> {
        let closed = Arc::downgrade(&journal);
        let key = DeliveryKey::new(request);
        tokio::time::timeout(
            SETTLE_GUARD,
            tokio::task::spawn_blocking(move || journal.wait("authority", &key)),
        )
        .await???;
        tokio::time::timeout(SETTLE_GUARD, async {
            while closed.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    // oracle: mutant fixture cleanup runs while the journal directory is still pinned
    #[tokio::test]
    async fn operation_fixtures_remove_their_roots_after_cleanup() -> anyhow::Result<()> {
        let IssuedOperation {
            _root: root,
            journal,
            pending,
            ..
        } = issued_operation()?;
        let issued_root = root.path().to_owned();
        let request = pending.request.clone();
        drop(pending);
        wait_for_detached_cleanup(journal, &request).await?;
        drop(root);
        assert!(!issued_root.exists(), "issued fixture retained {issued_root:?}");

        let SentOperation {
            _root: root,
            journal,
            pending,
            ..
        } = sent_operation()?;
        let sent_root = root.path().to_owned();
        let request = pending.request.clone();
        drop(pending);
        wait_for_detached_cleanup(journal, &request).await?;
        drop(root);
        assert!(!sent_root.exists(), "sent fixture retained {sent_root:?}");
        Ok(())
    }

    /// Settles a sent operation with the limits of a request dispatched now.
    async fn finish_sent(
        pending: Pending,
        grants: &RemoteGrantStore,
        issued: &IssuedGrant,
        shutdown: Option<ShutdownSignal>,
        delivery: impl Future<Output = anyhow::Result<serde_json::Value>>,
    ) -> Completion {
        finish_sent_until(
            pending,
            grants,
            issued,
            shutdown,
            delivery,
            WaitLimits::after_dispatch(Instant::now()),
        )
        .await
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
        let settled = tokio::time::timeout(SETTLE_GUARD, operation).await??.settled;
        let expected = Settled {
            outcome: Outcome::Succeeded,
            execution_started: Some(true),
        };
        assert_eq!(settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn nonzero_broker_exit_is_a_known_failure_with_the_unsigned_code() -> anyhow::Result<()> {
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
        assert!(record.mark_exited(0x8A15_0010u32.cast_signed()));
        let settled = finish_sent(pending, &grants, &issued, None, std::future::pending())
            .await
            .settled;

        let expected = Settled {
            outcome: Outcome::Failed {
                error: "Winget exited with code 2316632080".to_owned(),
            },
            execution_started: Some(true),
        };
        assert_eq!(settled, expected);
        assert_eq!(
            journal.admit("authority", &request)?,
            Admission::Recorded(expected.clone())
        );
        let reported = result("op-1".to_owned(), expected);
        assert!(!reported.success);
        assert_eq!(reported.error, "Winget exited with code 2316632080");
        assert_eq!(reported.status, i32::from(PackageOperationStatus::Unspecified));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn first_observed_exit_survives_start_write_failure() -> anyhow::Result<()> {
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
        assert!(record.mark_exited(0));
        journal.fail_start_writes(1);

        let completion = finish_sent(pending, &grants, &issued, None, std::future::pending()).await;
        assert!(completion.durably_recorded);
        let expected = Settled {
            outcome: Outcome::Succeeded,
            execution_started: Some(true),
        };
        assert_eq!(completion.settled, expected);

        drop(journal);
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        assert_eq!(reopened.admit("authority", &request)?, Admission::Recorded(expected));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn first_observed_exit_is_unknown_when_completion_write_fails() -> anyhow::Result<()> {
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
        assert!(record.mark_exited(0));
        journal.fail_start_writes(1);
        journal.fail_completion_writes(1);

        let completion = finish_sent(pending, &grants, &issued, None, std::future::pending()).await;
        assert!(!completion.durably_recorded);
        assert_eq!(
            completion.settled,
            Settled {
                outcome: Outcome::Unknown,
                execution_started: Some(true),
            }
        );

        drop(journal);
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        let Admission::Recorded(replayed) = reopened.admit("authority", &request)? else {
            anyhow::bail!("operation replay was not recorded");
        };
        assert!(matches!(replayed.outcome, Outcome::Unknown | Outcome::Succeeded));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn start_evidence_survives_a_failed_completion_write() -> anyhow::Result<()> {
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
        assert!(record.mark_exited(0));
        journal.fail_completion_writes(1);

        let completion = finish_sent(pending, &grants, &issued, None, std::future::pending()).await;
        assert_eq!(
            completion.settled,
            Settled {
                outcome: Outcome::Unknown,
                execution_started: Some(true),
            }
        );

        drop(journal);
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        assert_eq!(
            reopened.admit("authority", &request)?,
            Admission::Recorded(Settled {
                outcome: Outcome::Unknown,
                execution_started: Some(true),
            })
        );
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn installed_outcome_survives_completion_write_failure() -> anyhow::Result<()> {
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
        assert!(record.mark_exited(0));
        journal.fail_start_writes(1);
        journal.fail_completion_writes_after_install(1);

        let completion = finish_sent(pending, &grants, &issued, None, std::future::pending()).await;
        assert!(!completion.durably_recorded);
        assert_eq!(
            completion.settled,
            Settled {
                outcome: Outcome::Unknown,
                execution_started: Some(true),
            }
        );

        drop(journal);
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        assert_eq!(
            reopened.admit("authority", &request)?,
            Admission::Recorded(Settled {
                outcome: Outcome::Succeeded,
                execution_started: Some(true),
            })
        );
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn observed_exit_survives_eviction_during_journal_write() -> anyhow::Result<()> {
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
        assert!(record.mark_exited(0x8A15_0010u32.cast_signed()));
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        let spec = Plan::parse(&request).expect("request is valid").grant_spec(sid);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()?;

        runtime.block_on(async {
            let (entered, waiting) = tokio::sync::oneshot::channel();
            let (release, resume) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).expect("blocking-thread observer is alive");
                resume.recv()
            });
            waiting.await?;

            let completion = finish_sent(pending, &grants, &issued, None, std::future::pending());
            tokio::pin!(completion);
            assert!(futures::poll!(completion.as_mut()).is_pending());

            // Hold the first journal write until the observed Broker record has been evicted.
            for _ in 0..10_000 {
                let replacement = grants.issue(spec.clone())?;
                broker_request.request_id = api::ResourceId::from(replacement.request_id.to_string().as_str());
                grants.consume(replacement.grant.expose_secret(), &caller, &broker_request)?;
                if grants.outcome(&issued.grant, &issued.request_id) == OutcomeSummary::Unknown {
                    break;
                }
            }
            assert_eq!(
                grants.outcome(&issued.grant, &issued.request_id),
                OutcomeSummary::Unknown
            );
            release.send(())?;
            blocker.await??;
            let completion = tokio::time::timeout(SETTLE_GUARD, completion).await?;

            let expected = Settled {
                outcome: Outcome::Failed {
                    error: "Winget exited with code 2316632080".to_owned(),
                },
                execution_started: Some(true),
            };
            assert_eq!(completion.settled, expected);
            assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
            Ok(())
        })
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn exit_code_maps_to_known_outcome_with_manager_unchanged() {
        assert_eq!(outcome_for_exit("WinGet", 0), Outcome::Succeeded);
        assert_eq!(
            outcome_for_exit("WinGet", 1),
            Outcome::Failed {
                error: "WinGet exited with code 1".to_owned()
            }
        );
        assert_eq!(
            outcome_for_exit(".NET Tool", -1),
            Outcome::Failed {
                error: ".NET Tool exited with code 4294967295".to_owned()
            }
        );
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
            operation_deadline + SETTLE_GUARD,
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
        let settled = tokio::time::timeout(SETTLE_GUARD, operation).await??.settled;
        let expected = Settled {
            outcome: Outcome::Succeeded,
            execution_started: Some(true),
        };
        assert_eq!(settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
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
        let settled = tokio::time::timeout(SETTLE_GUARD, &mut operation).await??.settled;
        let expected = Settled {
            outcome: Outcome::Succeeded,
            execution_started: Some(true),
        };
        assert_eq!(settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
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
                    consumed_grace: 4 * SETTLE_GUARD,
                },
            )
            .await;
            (Instant::now(), completion)
        });
        response.await.expect("the initial record was sampled");
        tokio::time::sleep_until(dispatched_at + Duration::from_millis(1200)).await;
        let _record = grants.consume(&grant, &caller, &broker_request)?;
        // An unclipped grace would run past this timeout.
        let (completed_at, completion) =
            tokio::time::timeout_at(operation_deadline + SETTLE_GUARD, operation).await??;

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
            SETTLE_GUARD,
            finish_sent_until(
                pending,
                &grants,
                &issued,
                None,
                std::future::pending(),
                WaitLimits {
                    start_deadline: now + Duration::from_secs(1),
                    operation_deadline: now + 4 * SETTLE_GUARD,
                    consumed_grace: Duration::from_millis(650),
                },
            ),
        )
        .await?
        .settled;

        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: None,
        };
        assert_eq!(settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
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
            SETTLE_GUARD,
            finish_sent_until(
                pending,
                &grants,
                &issued,
                None,
                std::future::pending(),
                WaitLimits {
                    start_deadline: now + Duration::from_millis(500),
                    operation_deadline: now + 4 * SETTLE_GUARD,
                    consumed_grace: 4 * SETTLE_GUARD,
                },
            ),
        )
        .await?
        .settled;

        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: None,
        };
        assert_eq!(settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        Ok(())
    }

    // oracle: mutant a pending delivery is mistaken for a request that was never sent
    #[tokio::test]
    async fn pending_delivery_retains_possible_send_evidence() -> anyhow::Result<()> {
        let (settled, may_have_been_sent) = tracked_delivery_result(std::future::pending()).await?;
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(
            settled,
            Settled {
                outcome: Outcome::Unknown,
                execution_started: None,
            }
        );
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
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(
            settled,
            Settled {
                outcome: Outcome::Unknown,
                execution_started: None,
            }
        );
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
            SETTLE_GUARD,
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
        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: None,
        };
        assert_eq!(completion.settled, expected);
        assert!(may_have_been_sent);
        assert!(!completion.durably_recorded);
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
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

        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(
            settled,
            Settled {
                outcome: Outcome::Unknown,
                execution_started: None,
            }
        );
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
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        assert_eq!(
            settled,
            Settled {
                outcome: Outcome::Unknown,
                execution_started: None,
            }
        );
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
        let settled = tokio::time::timeout(SETTLE_GUARD, operation).await??.settled;
        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: Some(true),
        };
        assert_eq!(settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        tokio::time::timeout(SETTLE_GUARD, shutdown.all_closed()).await?;
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
            SETTLE_GUARD,
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
        tokio::time::timeout(SETTLE_GUARD, shutdown.all_closed()).await?;
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
                        operation_deadline: now + 4 * SETTLE_GUARD,
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
        let (completion, ()) = tokio::time::timeout(SETTLE_GUARD, async { tokio::try_join!(wait, evict) }).await??;

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
        wait_for_detached_cleanup(journal, &request).await?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        assert_eq!(
            reopened.admit("authority", &request)?,
            Admission::Recorded(Settled {
                outcome: Outcome::Unknown,
                execution_started: Some(true),
            })
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
        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: Some(true),
        };
        assert_eq!(completion.settled, expected);
        drop(journal);
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let reopened = OperationJournal::open(data)?;
        assert_eq!(reopened.admit("authority", &request)?, Admission::Recorded(expected));
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
        let settled = tokio::time::timeout(SETTLE_GUARD, operation).await??.settled;
        let expected = Settled {
            outcome: Outcome::Unknown,
            execution_started: None,
        };
        assert_eq!(settled, expected);
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(expected));
        Ok(())
    }

    fn test_journal() -> anyhow::Result<(tempfile::TempDir, Arc<OperationJournal>)> {
        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let journal = Arc::new(OperationJournal::open(data)?);
        Ok((root, journal))
    }

    fn response() -> (Reply, tokio::sync::oneshot::Receiver<PackageOperationResult>) {
        let (send, receive) = tokio::sync::oneshot::channel();
        (
            Box::new(move |result| {
                let _ = send.send(result);
            }),
            receive,
        )
    }

    // oracle: mutant a Broker wait releases its operation worker before settlement
    // oracle: mutant a settled operation retains its worker
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn waiting_for_the_broker_retains_an_operation_worker() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let sid = Sid::from_well_known(windows::Win32::Security::WinWorldSid, None).expect("well-known SID exists");
        let grants = RemoteGrantStore::new();
        let issued = grants.issue(Plan::parse(&request).expect("request is valid").grant_spec(sid))?;
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let (delivered, waiting) = tokio::sync::oneshot::channel();
        let (reply, result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            reply,
            move |pending| async move {
                finish_sent(pending, &grants, &issued, Some(signal), async move {
                    delivered.send(()).expect("delivery observer is alive");
                    std::future::pending().await
                })
                .await
                .settled
            },
        );
        tokio::time::timeout(SETTLE_GUARD, waiting).await??;

        let mut other_workers = Vec::new();
        while let Some(permit) = coordinator.try_worker() {
            other_workers.push(permit);
        }
        assert_eq!(other_workers.len() + 1, super::super::MAX_CONCURRENT_REQUESTS);

        let (busy_reply, busy_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            PackageOperationRequest {
                operation_id: Uuid::new_v4().to_string(),
                ..request
            },
            busy_reply,
            |_| async { panic!("an overloaded operation must not execute") },
        );
        let busy = tokio::time::timeout(SETTLE_GUARD, busy_result).await??;
        assert_eq!(busy.error, "agent busy: nothing was started");

        shutdown.signal();
        let result = tokio::time::timeout(SETTLE_GUARD, result).await??;
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        other_workers.clear();
        while let Some(permit) = coordinator.try_worker() {
            other_workers.push(permit);
        }
        assert_eq!(other_workers.len(), super::super::MAX_CONCURRENT_REQUESTS);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn attached_delivery_is_unknown_before_an_installed_result_is_replayed() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        journal.fail_completion_writes_after_install(1);
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (first_reply, first_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            first_reply,
            move |pending| async move {
                entered.send(()).expect("operation observer is alive");
                released.await.expect("release sender is alive");
                pending.finish_with_durability(Outcome::Succeeded, true).await.settled
            },
        );
        tokio::time::timeout(SETTLE_GUARD, waiting).await??;

        let (attached_reply, attached_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            attached_reply,
            |_| async { panic!("an attached delivery must not execute") },
        );
        assert!(tokio::time::timeout(SETTLE_GUARD, first_result).await?.is_err());
        release.send(()).expect("operation is waiting");
        let original = tokio::time::timeout(SETTLE_GUARD, attached_result).await??;
        assert_eq!(original.status, i32::from(PackageOperationStatus::Unknown));
        assert_eq!(original.execution_started, Some(true));

        let (replay_reply, replay_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            replay_reply,
            |_| async { panic!("a recorded operation must not execute again") },
        );
        let replay = tokio::time::timeout(SETTLE_GUARD, replay_result).await??;
        assert!(replay.success);
        assert_eq!(replay.execution_started, Some(true));
        drop(coordinator);
        wait_for_detached_cleanup(journal, &request).await?;
        Ok(())
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn in_flight_redelivery_receives_the_original_result_at_capacity() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (first_reply, first_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "first-authority".to_owned(),
            request.clone(),
            first_reply,
            move |pending| async move {
                started.send(()).expect("start receiver is alive");
                released.await.expect("release sender is alive");
                pending.finish(Outcome::Succeeded, false).await
            },
        );
        tokio::time::timeout(Duration::from_secs(10), running).await??;

        let mut other_workers = Vec::new();
        while let Some(permit) = coordinator.try_worker() {
            other_workers.push(permit);
        }
        let (latest_reply, mut latest_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "second-authority".to_owned(),
            request.clone(),
            latest_reply,
            |_| async { panic!("a redelivery must not execute again") },
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(10), first_result)
                .await?
                .is_err()
        );
        assert!(matches!(
            latest_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        release.send(()).expect("operation is waiting");
        let result = tokio::time::timeout(Duration::from_secs(10), latest_result).await??;
        assert!(result.success);
        assert_eq!(result.error, "");
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(result.execution_started, None);
        assert_eq!(
            journal.admit("second-authority", &request)?,
            Admission::Recorded(Settled {
                outcome: Outcome::Succeeded,
                execution_started: None,
            })
        );
        drop(other_workers);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn recorded_redeliveries_wait_without_blocking_a_busy_answer_at_worker_capacity() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let recorded = PackageOperationRequest {
            operation_id: "legacy-id".to_owned(),
            ..request(PackageOperationType::Install, "Winget", "winget", "user")
        };
        assert_eq!(journal.admit("first-authority", &recorded)?, Admission::Admitted);
        journal.complete("first-authority", &recorded, Outcome::Succeeded)?;
        let admission = Arc::clone(&coordinator.admission).acquire_owned().await?;

        let (old_reply, old_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "first-authority".to_owned(),
            recorded.clone(),
            old_reply,
            |_| async { panic!("a recorded operation must not execute again") },
        );
        let (latest_reply, mut latest_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "second-authority".to_owned(),
            recorded,
            latest_reply,
            |_| async { panic!("a recorded operation must not execute again") },
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(10), old_result)
                .await?
                .is_err()
        );
        assert!(matches!(
            latest_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        let new = PackageOperationRequest {
            operation_id: "11111111-2222-4333-8444-555555555556".to_owned(),
            ..request(PackageOperationType::Install, "Winget", "winget", "user")
        };
        let mut workers = Vec::new();
        while let Some(permit) = coordinator.try_worker() {
            workers.push(permit);
        }
        let (busy_reply, busy_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "first-authority".to_owned(),
            new.clone(),
            busy_reply,
            |_| async { panic!("an overloaded operation must not execute") },
        );
        let busy = tokio::time::timeout(Duration::from_secs(10), busy_result).await??;
        assert!(!busy.success);
        assert_eq!(busy.error, "agent busy: nothing was started");
        assert_eq!(busy.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(busy.execution_started, None);

        drop(workers);
        drop(admission);
        let replay = tokio::time::timeout(Duration::from_secs(10), latest_result).await??;
        assert!(replay.success);

        let (later_reply, later_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "first-authority".to_owned(),
            new.clone(),
            later_reply,
            |pending| async move { pending.finish(Outcome::Unknown, true).await },
        );
        let later = tokio::time::timeout(Duration::from_secs(10), later_result).await??;
        assert_eq!(later.status, i32::from(PackageOperationStatus::Unknown));
        assert_eq!(later.execution_started, Some(true));
        assert_eq!(
            journal.lookup("first-authority", &DeliveryKey::new(&new))?,
            Some(Admission::Recorded(Settled {
                outcome: Outcome::Unknown,
                execution_started: Some(true),
            }))
        );
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_different_payload_cannot_replace_an_in_flight_operation() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let original = request(PackageOperationType::Install, "Winget", "winget", "user");
        let changed = PackageOperationRequest {
            package_id: "different".to_owned(),
            ..original.clone()
        };
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (original_reply, original_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "first-authority".to_owned(),
            original,
            original_reply,
            move |pending| async move {
                started.send(()).expect("start receiver is alive");
                released.await.expect("release sender is alive");
                pending.finish(Outcome::Succeeded, false).await
            },
        );
        tokio::time::timeout(Duration::from_secs(10), running).await??;
        let (changed_reply, changed_result) = response();
        coordinator.submit(
            journal,
            "second-authority".to_owned(),
            changed,
            changed_reply,
            |_| async { panic!("a different payload must not execute") },
        );
        let changed = tokio::time::timeout(Duration::from_secs(10), changed_result).await??;
        assert!(!changed.success);
        assert_eq!(changed.status, i32::from(PackageOperationStatus::Unknown));

        release.send(()).expect("operation is waiting");
        assert!(
            tokio::time::timeout(Duration::from_secs(10), original_result)
                .await??
                .success
        );
        Ok(())
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn redelivery_attaches_before_and_during_stalled_admission() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        let (entered, resume) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let executions = Arc::new(AtomicUsize::new(0));
        let (first_reply, mut first_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            first_reply,
            {
                let executions = Arc::clone(&executions);
                move |pending| async move {
                    executions.fetch_add(1, Ordering::SeqCst);
                    pending.finish(Outcome::Succeeded, false).await
                }
            },
        );
        assert!(!journal.may_contain(&request.operation_id));

        let (second_reply, mut second_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            second_reply,
            |_| async { panic!("a redelivery must not execute again") },
        );
        assert!(matches!(
            first_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));

        let new = PackageOperationRequest {
            operation_id: "11111111-2222-4333-8444-555555555556".to_owned(),
            ..request.clone()
        };
        let (new_reply, mut new_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            new,
            new_reply,
            |pending| async move { pending.finish(Outcome::Succeeded, false).await },
        );
        assert!(matches!(
            new_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        tokio::time::timeout(
            Duration::from_secs(12),
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(10))),
        )
        .await???;
        let changed = PackageOperationRequest {
            package_id: "different".to_owned(),
            ..request.clone()
        };
        let (changed_reply, mut changed_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            changed,
            changed_reply,
            |_| async { panic!("a changed payload must not execute") },
        );
        assert_eq!(
            changed_result.try_recv()?.status,
            i32::from(PackageOperationStatus::Unknown)
        );

        let (latest_reply, latest_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "another-authority".to_owned(),
            request,
            latest_reply,
            |_| async { panic!("a redelivery must not execute again") },
        );
        assert!(matches!(
            second_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        resume.send(())?;
        assert!(
            tokio::time::timeout(Duration::from_secs(10), latest_result)
                .await??
                .success
        );
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(10), new_result)
                .await??
                .success
        );
        Ok(())
    }

    fn request_with_id(id: &str) -> PackageOperationRequest {
        PackageOperationRequest {
            operation_id: id.to_owned(),
            ..request(PackageOperationType::Install, "Winget", "winget", "user")
        }
    }

    fn numbered_id(n: usize) -> String {
        format!("11111111-2222-4333-8444-5555555555{n:02}")
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn recorded_redeliveries_share_one_lookup_task_while_lookups_are_held() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let recorded: Vec<_> = (0..16).map(|n| request_with_id(&numbered_id(n))).collect();
        for request in &recorded {
            assert_eq!(journal.admit("authority", request)?, Admission::Admitted);
            journal.complete("authority", request, Outcome::Succeeded)?;
        }
        let admission = Arc::clone(&coordinator.admission).acquire_owned().await?;
        let metrics = tokio::runtime::Handle::current().metrics();
        let tasks_before = metrics.num_alive_tasks();

        let mut results = Vec::new();
        for request in recorded {
            let (reply, result) = response();
            coordinator.submit(
                Arc::clone(&journal),
                "authority".to_owned(),
                request,
                reply,
                |_| async { panic!("a recorded operation must not execute again") },
            );
            results.push(result);
        }
        tokio::task::yield_now().await;
        assert_eq!(metrics.num_alive_tasks(), tasks_before + 1);

        drop(admission);
        for result in results {
            assert!(tokio::time::timeout(Duration::from_secs(10), result).await??.success);
        }
        Ok(())
    }

    async fn wait_for_stall(entered: std::sync::mpsc::Receiver<()>) -> anyhow::Result<()> {
        tokio::time::timeout(
            Duration::from_secs(12),
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(10))),
        )
        .await???;
        Ok(())
    }

    // oracle: reference Devolutions/devolutions-gateway@da3890c85816:devolutions-agent/src/device_management/mod.rs
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn new_operations_queue_behind_a_stalled_journal_write_until_eight_are_in_flight() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        let (entered, resume) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let coordinator = Arc::new(Coordinator::default());
        let executions = Arc::new(AtomicUsize::new(0));
        let mut results = Vec::new();
        let mut submit_new = |n: usize| {
            let (reply, result) = response();
            let executions = Arc::clone(&executions);
            coordinator.submit(
                Arc::clone(&journal),
                "authority".to_owned(),
                request_with_id(&numbered_id(n)),
                reply,
                move |pending| async move {
                    executions.fetch_add(1, Ordering::SeqCst);
                    pending.finish(Outcome::Succeeded, false).await
                },
            );
            results.push(result);
        };

        submit_new(0);
        wait_for_stall(entered).await?;
        for n in 1..8 {
            submit_new(n);
        }
        for result in &mut results {
            assert!(matches!(
                result.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ));
        }

        let (busy_reply, mut busy_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request_with_id(&numbered_id(8)),
            busy_reply,
            |_| async { panic!("an operation beyond capacity must not execute") },
        );
        let busy = busy_result
            .try_recv()
            .expect("a ninth operation is answered immediately");
        assert!(!busy.success);
        assert_eq!(busy.error, "agent busy: nothing was started");
        assert_eq!(busy.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(busy.execution_started, None);

        resume.send(())?;
        for result in results {
            assert!(tokio::time::timeout(Duration::from_secs(10), result).await??.success);
        }
        assert_eq!(executions.load(Ordering::SeqCst), 8);
        assert!(!journal.may_contain(&numbered_id(8)));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_queued_operation_redelivered_before_admission_runs_once_and_answers_the_latest_delivery()
    -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        let (entered, resume) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let coordinator = Arc::new(Coordinator::default());
        let (stalled_reply, stalled_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request_with_id(&numbered_id(0)),
            stalled_reply,
            |pending| async move { pending.finish(Outcome::Succeeded, false).await },
        );
        wait_for_stall(entered).await?;

        let queued = request_with_id(&numbered_id(1));
        let executions = Arc::new(AtomicUsize::new(0));
        let (first_reply, mut first_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            queued.clone(),
            first_reply,
            {
                let executions = Arc::clone(&executions);
                move |pending| async move {
                    executions.fetch_add(1, Ordering::SeqCst);
                    pending.finish(Outcome::Succeeded, false).await
                }
            },
        );
        let (latest_reply, latest_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "another-authority".to_owned(),
            queued,
            latest_reply,
            |_| async { panic!("a redelivery must not execute again") },
        );
        assert!(matches!(
            first_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));

        resume.send(())?;
        assert!(
            tokio::time::timeout(Duration::from_secs(10), stalled_result)
                .await??
                .success
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(10), latest_result)
                .await??
                .success
        );
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_queued_operation_is_journal_full_if_an_earlier_one_takes_the_last_index_space() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        journal.limit_index_room_for_test(1);
        let (entered, resume) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let coordinator = Arc::new(Coordinator::default());
        let executions = Arc::new(AtomicUsize::new(0));
        let mut results = Vec::new();
        for n in 0..2 {
            let (reply, result) = response();
            let executions = Arc::clone(&executions);
            coordinator.submit(
                Arc::clone(&journal),
                "authority".to_owned(),
                request_with_id(&numbered_id(n)),
                reply,
                move |pending| async move {
                    executions.fetch_add(1, Ordering::SeqCst);
                    pending.finish(Outcome::Succeeded, false).await
                },
            );
            results.push(result);
        }
        wait_for_stall(entered).await?;
        resume.send(())?;

        let mut settled = Vec::new();
        for result in results {
            settled.push(tokio::time::timeout(Duration::from_secs(10), result).await??);
        }
        let (full, succeeded): (Vec<_>, Vec<_>) = settled.into_iter().partition(|result| !result.success);
        let [full] = full.as_slice() else {
            panic!("exactly one operation must be refused");
        };
        let [succeeded] = succeeded.as_slice() else {
            panic!("exactly one operation must succeed");
        };
        assert_eq!(succeeded.error, "");
        assert_eq!(full.error, "agent journal full: nothing was started");
        assert_eq!(full.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(full.execution_started, None);
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert!(!journal.may_contain(&full.operation_id));
        assert_eq!(
            journal.lookup("authority", &DeliveryKey::new(&request_with_id(&full.operation_id)))?,
            None
        );
        assert!(journal.may_contain(&succeeded.operation_id));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_recorded_id_with_a_different_payload_is_unknown_at_capacity() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let original = request(PackageOperationType::Install, "Winget", "winget", "user");
        assert_eq!(journal.admit("authority", &original)?, Admission::Admitted);
        journal.complete("authority", &original, Outcome::Succeeded)?;
        let mut permits = Vec::new();
        while let Some(permit) = coordinator.try_worker() {
            permits.push(permit);
        }

        let changed = PackageOperationRequest {
            package_id: "different".to_owned(),
            ..original.clone()
        };
        let (reply, result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            changed,
            reply,
            |_| async { panic!("a changed payload must not execute") },
        );
        let result = tokio::time::timeout(Duration::from_secs(10), result).await??;
        assert_eq!(result.operation_id, original.operation_id);
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        assert_eq!(
            journal.lookup("authority", &DeliveryKey::new(&original))?,
            Some(Admission::Recorded(Settled {
                outcome: Outcome::Succeeded,
                execution_started: None,
            }))
        );
        drop(permits);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_changed_redelivery_during_lookup_receives_unknown() -> anyhow::Result<()> {
        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        let recorded = request(PackageOperationType::Install, "Winget", "winget", "user");
        journal.admit("authority", &recorded)?;
        journal.complete("authority", &recorded, Outcome::Succeeded)?;
        let (entered, resume) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let other = PackageOperationRequest {
            operation_id: "11111111-2222-4333-8444-555555555556".to_owned(),
            ..recorded.clone()
        };
        let writer = tokio::task::spawn_blocking({
            let journal = Arc::clone(&journal);
            let other = other.clone();
            move || journal.admit("authority", &other)
        });
        tokio::time::timeout(
            Duration::from_secs(12),
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(10))),
        )
        .await???;

        let coordinator = Arc::new(Coordinator::default());
        let (first_reply, mut first_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            recorded.clone(),
            first_reply,
            |_| async { panic!("a recorded operation must not execute again") },
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while coordinator.admission.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let changed = PackageOperationRequest {
            package_id: "different".to_owned(),
            ..recorded
        };
        let (changed_reply, changed_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            changed,
            changed_reply,
            |_| async { panic!("a changed payload must not execute") },
        );
        assert!(matches!(
            first_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
        resume.send(())?;
        assert_eq!(writer.await??, Admission::Admitted);
        let result = tokio::time::timeout(Duration::from_secs(10), changed_result).await??;
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        journal.complete("authority", &other, Outcome::Unknown)?;
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_full_journal_rejects_a_new_operation_without_recording_it() -> anyhow::Result<()> {
        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        journal.exhaust_index_for_test();
        let mut journal = Arc::new(journal);
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let admission = Arc::clone(&coordinator.admission).try_acquire_owned()?;
        let mut permits = Vec::new();
        while let Some(permit) = coordinator.try_worker() {
            permits.push(permit);
        }
        let (reply, result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            reply,
            |_| async { panic!("an operation cannot start when the journal is full") },
        );

        let result = tokio::time::timeout(Duration::from_secs(10), result).await??;
        assert_eq!(result.operation_id, request.operation_id);
        assert!(!result.success);
        assert_eq!(result.error, "agent journal full: nothing was started");
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unspecified));
        assert_eq!(result.execution_started, None);
        assert!(!journal.may_contain(&request.operation_id));

        drop(admission);
        drop(permits);
        Arc::get_mut(&mut journal)
            .expect("the refused operation did not retain the journal")
            .restore_index_limit_for_test();
        let (reply, later) = response();
        coordinator.submit(journal, "authority".to_owned(), request, reply, |pending| async move {
            pending.finish(Outcome::Succeeded, false).await
        });
        assert!(tokio::time::timeout(Duration::from_secs(10), later).await??.success);
        Ok(())
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn a_full_journal_still_replays_recorded_operations_at_worker_capacity() -> anyhow::Result<()> {
        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        let recorded = request(PackageOperationType::Install, "Winget", "winget", "user");
        journal.admit("authority", &recorded)?;
        journal.complete("authority", &recorded, Outcome::Succeeded)?;
        journal.exhaust_index_for_test();
        let journal = Arc::new(journal);
        let coordinator = Arc::new(Coordinator::default());
        let mut permits = Vec::new();
        while let Some(permit) = coordinator.try_worker() {
            permits.push(permit);
        }
        let (sender, replay) = response();
        coordinator.submit(journal, "authority".to_owned(), recorded, sender, |_| async {
            panic!("a recorded operation must not execute again")
        });
        assert!(tokio::time::timeout(Duration::from_secs(10), replay).await??.success);
        drop(permits);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[tokio::test]
    async fn an_interrupted_operation_settles_if_its_cleanup_cannot_start() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let (callback, mut receiver) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            callback,
            |mut pending| async move {
                // Simulate a cleanup thread that could not start.
                pending.armed = false;
                drop(pending);
                panic!("injected interruption without cleanup");
            },
        );

        let outcome = tokio::time::timeout(Duration::from_secs(10), &mut receiver).await;
        if outcome.is_err() {
            journal.complete("authority", &request, Outcome::Unknown)?;
            let _ = tokio::time::timeout(Duration::from_secs(10), receiver).await;
        }
        let result = outcome??;
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));

        let (callback, replayed) = response();
        coordinator.submit(journal, "authority".to_owned(), request, callback, |_| async {
            panic!("an interrupted operation must not execute again");
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), replayed).await??.status,
            i32::from(PackageOperationStatus::Unknown)
        );
        Ok(())
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
    #[tokio::test]
    async fn an_interrupted_operation_preserves_an_already_recorded_result() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let (reply, response) = response();
        coordinator.submit(journal, "authority".to_owned(), request, reply, |pending| async move {
            pending.finish(Outcome::Succeeded, false).await;
            panic!("injected interruption after completion");
        });

        assert!(tokio::time::timeout(Duration::from_secs(10), response).await??.success);
        Ok(())
    }

    // oracle: mutant a stalled journal is not warned, or repeatedly warns
    #[tokio::test]
    async fn a_stalled_journal_admission_warns_once() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tracing::{Metadata, Subscriber, span};

        struct Warnings(Arc<AtomicUsize>);

        impl Subscriber for Warnings {
            fn enabled(&self, metadata: &Metadata<'_>) -> bool {
                *metadata.level() == tracing::Level::WARN
            }

            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }

            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

            fn event(&self, _: &tracing::Event<'_>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn enter(&self, _: &span::Id) {}

            fn exit(&self, _: &span::Id) {}
        }

        let warnings = Arc::new(AtomicUsize::new(0));
        let _subscriber = tracing::subscriber::set_default(Warnings(Arc::clone(&warnings)));
        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        let (entered, resume) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let coordinator = Arc::new(Coordinator::default());
        let (reply, result) = response();
        coordinator.submit(
            journal,
            "authority".to_owned(),
            request(PackageOperationType::Install, "Winget", "winget", "user"),
            reply,
            |pending| async move { pending.finish(Outcome::Succeeded, false).await },
        );
        tokio::time::timeout(
            Duration::from_secs(12),
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(10))),
        )
        .await???;
        tokio::time::sleep(Duration::from_secs(6)).await;
        let first = warnings.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(5)).await;
        let second = warnings.load(Ordering::SeqCst);
        resume.send(())?;
        assert!(tokio::time::timeout(Duration::from_secs(10), result).await??.success);
        assert_eq!((first, second), (1, 1));
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn dropping_an_interrupted_operation_does_not_block_the_runtime_during_a_journal_stall() -> anyhow::Result<()> {
        let root = test_tempdir()?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let mut journal = OperationJournal::open(data)?;
        let interrupted = request(PackageOperationType::Install, "Winget", "winget", "user");
        let interrupted_for_wait = interrupted.clone();
        assert_eq!(journal.admit("authority", &interrupted)?, Admission::Admitted);
        let (entered, resume) = journal.pause_index_write_for_test();
        let journal = Arc::new(journal);
        let writer = {
            let journal = Arc::clone(&journal);
            std::thread::spawn(move || {
                let blocked = PackageOperationRequest {
                    operation_id: "11111111-2222-4333-8444-555555555557".to_owned(),
                    ..Default::default()
                };
                journal.admit("authority", &blocked)
            })
        };
        entered.recv_timeout(Duration::from_secs(10))?;
        let (dropped, drop_finished) = std::sync::mpsc::channel();
        let runtime = {
            let journal = Arc::clone(&journal);
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime starts");
                runtime.block_on(async move {
                    tokio::spawn(async move {
                        drop(Pending {
                            journal,
                            authority_id: "authority".to_owned(),
                            request: interrupted,
                            armed: true,
                            worker: WorkerSlot::default(),
                        });
                        let _ = dropped.send(());
                    })
                    .await
                    .expect("operation task completes");
                });
            })
        };
        let returned_before_resume = drop_finished.recv_timeout(Duration::from_secs(5));
        resume.send(())?;
        writer.join().expect("journal writer thread completed")?;
        runtime.join().expect("test runtime thread completed");
        assert_eq!(
            journal
                .wait("authority", &DeliveryKey::new(&interrupted_for_wait))?
                .outcome,
            Outcome::Unknown
        );

        assert!(returned_before_resume.is_ok());
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
            worker: WorkerSlot::default(),
        });

        let settled = journal
            .wait("authority", &DeliveryKey::new(&request))
            .expect("outcome is settled");
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
        let context = DeviceManagementContext::default();
        let mut permits = Vec::new();
        while let Some(permit) = context.operations().try_worker() {
            permits.push(permit);
        }
        assert!(!permits.is_empty());
        let result = run(
            &context,
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
            worker: WorkerSlot::default(),
        };

        let settled = pending.finish(failure("not dispatched"), false).await;

        assert_eq!(settled.outcome, Outcome::Unknown);
        drop(journal);
        let _ = std::fs::remove_dir_all(base);
    }

    /// A rescan endpoint that runs `on_request` when a rescan is requested, then gives `answer` or never answers.
    struct FakeRescan<F> {
        requests: AtomicU32,
        on_request: F,
        answer: Option<Result<(), &'static str>>,
    }

    impl<F: Fn()> FakeRescan<F> {
        fn new(answer: Option<Result<(), &'static str>>, on_request: F) -> Self {
            Self {
                requests: AtomicU32::new(0),
                on_request,
                answer,
            }
        }

        fn requests(&self) -> u32 {
            self.requests.load(Ordering::SeqCst)
        }
    }

    impl<F: Fn()> RescanEndpoint for FakeRescan<F> {
        async fn rescan(&self) -> anyhow::Result<()> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            (self.on_request)();
            match self.answer {
                Some(answer) => answer.map_err(anyhow::Error::msg),
                None => std::future::pending().await,
            }
        }
    }

    /// The result of an operation whose Broker process exited with code 0.
    fn succeeded() -> Settled {
        Settled {
            outcome: Outcome::Succeeded,
            execution_started: Some(true),
        }
    }

    /// Reports the Broker process exit with `exit_code` once the request is dispatched, then yields `response`.
    async fn exiting_delivery_with(
        record: ExecutionRecord,
        exit_code: i32,
        response: anyhow::Result<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        assert!(record.mark_started());
        assert!(record.mark_exited(exit_code));
        response
    }

    /// Reports a successful Broker process exit once the request is dispatched, then yields `response`.
    async fn exiting_delivery(
        record: ExecutionRecord,
        response: anyhow::Result<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        exiting_delivery_with(record, 0, response).await
    }

    /// Settles a dispatched operation, giving up on a Broker record that does not advance after 300 milliseconds.
    ///
    /// A rescan may hold the result for three minutes, six times the guard, so only an answer or a shutdown ends its wait in time.
    async fn dispatched_result<E: RescanEndpoint>(
        pending: Pending,
        grants: &RemoteGrantStore,
        issued: &IssuedGrant,
        shutdown: Option<ShutdownSignal>,
        delivery: impl Future<Output = anyhow::Result<serde_json::Value>>,
        remote_inventory_enabled: bool,
        endpoint: &E,
    ) -> anyhow::Result<Settled> {
        let now = Instant::now();
        let waiting = Semaphore::new(1);
        let settled = tokio::time::timeout(
            SETTLE_GUARD,
            finish_dispatched(
                pending,
                grants,
                issued,
                shutdown,
                delivery,
                WaitLimits {
                    start_deadline: now + Duration::from_millis(300),
                    operation_deadline: now + Duration::from_secs(30 * 60),
                    consumed_grace: Duration::from_millis(300),
                },
                RescanAfter {
                    enabled: remote_inventory_enabled,
                    endpoint,
                    waiting: &waiting,
                },
            ),
        )
        .await?;
        Ok(settled)
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[rstest::rstest]
    #[case::success_and_rescan_completed(0, Outcome::Succeeded, Ok(()))]
    #[case::success_and_rescan_failed(0, Outcome::Succeeded, Err("rescan failed"))]
    #[case::failure_and_rescan_completed(
        1,
        Outcome::Failed { error: "Winget exited with code 1".to_owned() },
        Ok(())
    )]
    #[tokio::test]
    async fn finalized_operation_requests_one_rescan_after_its_result_is_recorded(
        #[case] exit_code: i32,
        #[case] outcome: Outcome,
        #[case] answer: Result<(), &'static str>,
    ) -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let recorded_at_request = std::cell::RefCell::new(Vec::new());
        let endpoint = FakeRescan::new(Some(answer), || {
            let admission = journal.admit("authority", &request).expect("journal is readable");
            recorded_at_request.borrow_mut().push(admission);
        });

        let delivery = exiting_delivery_with(record, exit_code, Ok(serde_json::json!({"status": "Unknown"})));
        let settled = dispatched_result(pending, &grants, &issued, None, delivery, true, &endpoint).await?;

        let expected = Settled {
            outcome,
            execution_started: Some(true),
        };
        assert_eq!(settled, expected);
        assert_eq!(recorded_at_request.into_inner(), [Admission::Recorded(expected)]);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn operation_that_was_not_sent_requests_no_rescan() -> anyhow::Result<()> {
        let IssuedOperation {
            _root,
            pending,
            grants,
            issued,
            ..
        } = issued_operation()?;
        let endpoint = FakeRescan::new(Some(Ok(())), || {});

        let delivery = async {
            tokio::task::yield_now().await;
            Err(RequestError::NotSent("not sent").into())
        };
        let settled = dispatched_result(pending, &grants, &issued, None, delivery, true, &endpoint).await?;

        assert_eq!(settled, unknown(false));
        assert_eq!(endpoint.requests(), 0);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn operation_whose_result_was_not_recorded_requests_no_rescan() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        journal.fail_completion_writes(1);
        let endpoint = FakeRescan::new(Some(Ok(())), || {});

        let delivery = exiting_delivery(record, Ok(serde_json::json!({"status": "Unknown"})));
        let settled = dispatched_result(pending, &grants, &issued, None, delivery, true, &endpoint).await?;

        assert_eq!(settled, unknown(true));
        assert_eq!(endpoint.requests(), 0);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn operation_requests_no_rescan_while_remote_inventory_is_disabled() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            pending,
            grants,
            issued,
            record,
            ..
        } = sent_operation()?;
        let endpoint = FakeRescan::new(Some(Ok(())), || {});

        let delivery = exiting_delivery(record, Ok(serde_json::json!({"status": "Unknown"})));
        let settled = dispatched_result(pending, &grants, &issued, None, delivery, false, &endpoint).await?;

        assert_eq!(settled, succeeded());
        assert_eq!(endpoint.requests(), 0);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn shutdown_signalled_before_the_rescan_wait_requests_no_rescan() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            pending,
            grants,
            issued,
            record,
            ..
        } = sent_operation()?;
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let endpoint = FakeRescan::new(None, || {});

        let delivery = async {
            let response = exiting_delivery(record, Ok(serde_json::json!({"status": "Unknown"}))).await;
            shutdown.signal();
            response
        };
        let settled = dispatched_result(pending, &grants, &issued, Some(signal), delivery, true, &endpoint).await?;

        assert_eq!(settled, succeeded());
        assert_eq!(endpoint.requests(), 0);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn shutdown_that_ends_the_outcome_wait_also_skips_the_rescan() -> anyhow::Result<()> {
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
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let endpoint = FakeRescan::new(None, || {});

        let delivery = async {
            shutdown.signal();
            std::future::pending().await
        };
        let settled = dispatched_result(pending, &grants, &issued, Some(signal), delivery, true, &endpoint).await?;

        assert_eq!(settled, unknown(true));
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(settled));
        assert_eq!(endpoint.requests(), 0);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn shutdown_during_the_rescan_wait_ends_it_and_returns_the_result() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            pending,
            grants,
            issued,
            record,
            ..
        } = sent_operation()?;
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let endpoint = FakeRescan::new(None, || shutdown.signal());

        let delivery = exiting_delivery(record, Ok(serde_json::json!({"status": "Unknown"})));
        let settled = dispatched_result(pending, &grants, &issued, Some(signal), delivery, true, &endpoint).await?;

        assert_eq!(settled, succeeded());
        assert_eq!(endpoint.requests(), 1);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn rescan_is_not_awaited_past_the_operation_deadline() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            pending,
            grants,
            issued,
            record: _record,
            ..
        } = sent_operation()?;
        let endpoint = FakeRescan::new(None, || {});
        let waiting = Semaphore::new(1);
        let operation_deadline = Instant::now() + Duration::from_millis(300);

        let settled = tokio::time::timeout(
            SETTLE_GUARD,
            finish_dispatched(
                pending,
                &grants,
                &issued,
                None,
                std::future::pending(),
                WaitLimits {
                    start_deadline: operation_deadline,
                    operation_deadline,
                    consumed_grace: Duration::from_millis(300),
                },
                RescanAfter {
                    enabled: true,
                    endpoint: &endpoint,
                    waiting: &waiting,
                },
            ),
        )
        .await?;

        assert_eq!(settled, unknown(false));
        assert!(
            operation_deadline <= Instant::now(),
            "the outcome wait lasts until the deadline"
        );
        assert_eq!(endpoint.requests(), 1);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[test]
    fn operation_deadline_is_thirty_minutes_after_dispatch() {
        let dispatched_at = Instant::now();

        let limits = WaitLimits::after_dispatch(dispatched_at);

        assert_eq!(limits.operation_deadline, dispatched_at + Duration::from_secs(30 * 60));
    }

    // oracle: mutant a panic in the rescan wait interrupts an operation whose result is recorded
    #[tokio::test]
    async fn panic_in_the_rescan_wait_returns_the_recorded_result() -> anyhow::Result<()> {
        let SentOperation {
            _root,
            journal,
            pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        let request = pending.request.clone();
        let endpoint = FakeRescan::new(None, || panic!("injected rescan panic"));
        let waiting = Semaphore::new(1);

        let delivery = exiting_delivery(record, Ok(serde_json::json!({"status": "Unknown"})));
        let settled = tokio::time::timeout(
            SETTLE_GUARD,
            finish_dispatched(
                pending,
                &grants,
                &issued,
                None,
                delivery,
                WaitLimits::after_dispatch(Instant::now()),
                RescanAfter {
                    enabled: true,
                    endpoint: &endpoint,
                    waiting: &waiting,
                },
            ),
        )
        .await?;

        assert_eq!(settled, succeeded());
        assert_eq!(journal.admit("authority", &request)?, Admission::Recorded(succeeded()));
        assert_eq!(endpoint.requests(), 1);
        assert_eq!(waiting.available_permits(), 1);
        Ok(())
    }

    /// A consumed grant and the Broker record of its operation.
    struct ConsumedGrant {
        grants: RemoteGrantStore,
        issued: IssuedGrant,
        record: ExecutionRecord,
    }

    /// Returns a consumed grant for an operation that a coordinator admits into a journal of its own.
    fn consumed_grant() -> anyhow::Result<ConsumedGrant> {
        let SentOperation {
            _root,
            journal,
            mut pending,
            grants,
            issued,
            record,
        } = sent_operation()?;
        // Nothing reads the fixture's own journal entry, so its guard is dropped without the cleanup write.
        pending.armed = false;
        drop(pending);
        drop(journal);
        Ok(ConsumedGrant { grants, issued, record })
    }

    /// Runs an operation whose Broker process exits with code 0 once `exit` resolves and whose rescan is never answered.
    ///
    /// `dispatched` is told when the request is dispatched, and `asked` at each rescan request.
    async fn operation_with_unanswered_rescan(
        pending: Pending,
        grant: ConsumedGrant,
        signal: ShutdownSignal,
        dispatched: tokio::sync::oneshot::Sender<()>,
        exit: tokio::sync::oneshot::Receiver<()>,
        asked: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> Settled {
        let ConsumedGrant { grants, issued, record } = grant;
        let endpoint = FakeRescan::new(None, move || asked.send(()).expect("rescan observer is alive"));
        let waiting = Semaphore::new(1);
        let delivery = async move {
            dispatched.send(()).expect("dispatch observer is alive");
            exit.await.expect("exit sender is alive");
            exiting_delivery(record, Ok(serde_json::json!({"status": "Unknown"}))).await
        };
        finish_dispatched(
            pending,
            &grants,
            &issued,
            Some(signal),
            delivery,
            WaitLimits::after_dispatch(Instant::now()),
            RescanAfter {
                enabled: true,
                endpoint: &endpoint,
                waiting: &waiting,
            },
        )
        .await
    }

    /// Counts the worker permits of `coordinator` that are free.
    fn free_workers(coordinator: &Coordinator) -> usize {
        let mut free = Vec::new();
        while let Some(permit) = coordinator.try_worker() {
            free.push(permit);
        }
        free.len()
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn operation_waiting_for_its_rescan_holds_no_operation_worker() -> anyhow::Result<()> {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let grant = consumed_grant()?;
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let (dispatched, waiting_for_broker) = tokio::sync::oneshot::channel();
        let (exit, exited) = tokio::sync::oneshot::channel();
        let (asked, mut rescans) = tokio::sync::mpsc::unbounded_channel();
        let (reply, result) = response();
        coordinator.submit(
            journal,
            "authority".to_owned(),
            request(PackageOperationType::Install, "Winget", "winget", "user"),
            reply,
            move |pending| operation_with_unanswered_rescan(pending, grant, signal, dispatched, exited, asked),
        );

        tokio::time::timeout(SETTLE_GUARD, waiting_for_broker).await??;
        // oracle: mutant the worker permit is given back before the result is recorded
        assert_eq!(free_workers(&coordinator), super::super::MAX_CONCURRENT_REQUESTS - 1);

        exit.send(()).expect("operation waits for the Broker");
        tokio::time::timeout(SETTLE_GUARD, rescans.recv())
            .await?
            .expect("a rescan is requested");
        assert_eq!(free_workers(&coordinator), super::super::MAX_CONCURRENT_REQUESTS);

        shutdown.signal();
        assert!(tokio::time::timeout(SETTLE_GUARD, result).await??.success);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory-rescan
    #[tokio::test]
    async fn delivery_repeated_during_the_rescan_wait_receives_the_result_without_another_rescan() -> anyhow::Result<()>
    {
        let (_root, journal) = test_journal()?;
        let coordinator = Arc::new(Coordinator::default());
        let request = request(PackageOperationType::Install, "Winget", "winget", "user");
        let grant = consumed_grant()?;
        let (shutdown, signal) = devolutions_gateway_task::ShutdownHandle::new();
        let (dispatched, waiting_for_broker) = tokio::sync::oneshot::channel();
        let (exit, exited) = tokio::sync::oneshot::channel();
        let (asked, mut rescans) = tokio::sync::mpsc::unbounded_channel();
        let (first_reply, _first_result) = response();
        coordinator.submit(
            Arc::clone(&journal),
            "authority".to_owned(),
            request.clone(),
            first_reply,
            move |pending| operation_with_unanswered_rescan(pending, grant, signal, dispatched, exited, asked),
        );
        tokio::time::timeout(SETTLE_GUARD, waiting_for_broker).await??;
        exit.send(()).expect("operation waits for the Broker");
        tokio::time::timeout(SETTLE_GUARD, rescans.recv())
            .await?
            .expect("a rescan is requested");

        let (repeated_reply, mut repeated_result) = response();
        coordinator.submit(journal, "authority".to_owned(), request, repeated_reply, |_| async {
            panic!("a repeated delivery must not execute again")
        });
        assert!(matches!(
            repeated_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        shutdown.signal();
        let result = tokio::time::timeout(SETTLE_GUARD, repeated_result).await??;
        assert!(result.success);
        assert_eq!(result.execution_started, Some(true));
        // The operation dropped its endpoint, so the channel yields every request made of it.
        assert_eq!(tokio::time::timeout(SETTLE_GUARD, rescans.recv()).await?, None);
        Ok(())
    }

    /// Builds a runtime whose blocking tasks, journal writes among them, run one at a time.
    fn runtime_with_one_blocking_thread() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
    }

    /// Occupies the only blocking thread of the runtime until the returned sender is used or dropped.
    async fn occupy_the_blocking_thread() -> std::sync::mpsc::Sender<()> {
        let (entered, occupied) = tokio::sync::oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        tokio::task::spawn_blocking(move || {
            entered.send(()).expect("blocking-thread observer is alive");
            let _ = resume.recv();
        });
        occupied.await.expect("blocking thread starts");
        release
    }

    // oracle: mutant the worker permit is given back before the completion write returned
    #[test]
    fn operation_keeps_its_worker_until_its_completion_write_returned() -> anyhow::Result<()> {
        runtime_with_one_blocking_thread()?.block_on(async {
            let (_root, journal) = test_journal()?;
            let coordinator = Arc::new(Coordinator::default());
            let (stalled, writing) = tokio::sync::oneshot::channel();
            let (reply, result) = response();
            coordinator.submit(
                journal,
                "authority".to_owned(),
                request(PackageOperationType::Install, "Winget", "winget", "user"),
                reply,
                move |pending| async move {
                    let release = occupy_the_blocking_thread().await;
                    stalled.send(release).expect("write observer is alive");
                    pending.finish(Outcome::Succeeded, false).await
                },
            );

            // The runtime has one thread, so the operation is awaiting its queued write once this resolves.
            let release = tokio::time::timeout(SETTLE_GUARD, writing).await??;
            assert_eq!(free_workers(&coordinator), super::super::MAX_CONCURRENT_REQUESTS - 1);

            release.send(())?;
            assert!(tokio::time::timeout(SETTLE_GUARD, result).await??.success);
            assert_eq!(free_workers(&coordinator), super::super::MAX_CONCURRENT_REQUESTS);
            Ok(())
        })
    }

    // oracle: mutant an operation interrupted before its completion write gives its worker permit back before its cleanup ended
    #[test]
    fn interrupted_operation_keeps_its_worker_until_its_cleanup_ended() -> anyhow::Result<()> {
        runtime_with_one_blocking_thread()?.block_on(async {
            let (_root, journal) = test_journal()?;
            let coordinator = Arc::new(Coordinator::default());
            let request = request(PackageOperationType::Install, "Winget", "winget", "user");
            let (interrupted, cleaning_up) = tokio::sync::oneshot::channel();
            let (reply, result) = response();
            coordinator.submit(
                Arc::clone(&journal),
                "authority".to_owned(),
                request.clone(),
                reply,
                move |pending| async move {
                    let release = occupy_the_blocking_thread().await;
                    interrupted.send(release).expect("interruption observer is alive");
                    drop(pending);
                    panic!("injected interruption before the completion write");
                },
            );

            // The cleanup write of the admission is queued behind the occupied thread.
            let release = tokio::time::timeout(SETTLE_GUARD, cleaning_up).await??;
            assert_eq!(free_workers(&coordinator), super::super::MAX_CONCURRENT_REQUESTS - 1);

            release.send(())?;
            let result = tokio::time::timeout(SETTLE_GUARD, result).await??;
            assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
            assert_eq!(free_workers(&coordinator), super::super::MAX_CONCURRENT_REQUESTS);
            drop(coordinator);
            wait_for_detached_cleanup(journal, &request).await?;
            Ok(())
        })
    }
}
