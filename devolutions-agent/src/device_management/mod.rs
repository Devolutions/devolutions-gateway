//! Handles device-management requests for UniGetUI discovery, package inventory and software catalogs.

mod context;
#[cfg(windows)]
mod operation;
#[cfg(any(windows, test))]
mod operation_journal;
#[cfg(any(windows, test))]
mod unigetui;
#[cfg(any(windows, test))]
mod user_registry;

use agent_channel_client::Reporter;
#[cfg(any(windows, test))]
use agent_channel_proto::UniGetUiInstance;
use agent_channel_proto::device_management_report::Report;
use agent_channel_proto::device_management_request::Request;
use agent_channel_proto::{
    CatalogSyncResult, DeviceManagementReport, DeviceManagementRequest, InstalledPackage, InventoryReport,
    InventoryUnavailable, InventoryUnavailableReason, PackageManager, PackageOperationRequest, PackageOperationResult,
    PackageOperationStatus, PackageSource, UniGetUiInstances, UniGetUiInstancesUnavailable,
    UniGetUiInstancesUnavailableReason,
};
use anyhow::Context as _;
pub(crate) use context::DeviceManagementContext;
use prost::Message as _;
use tokio::sync::{Semaphore, SemaphorePermit, watch};
use uuid::Uuid;

/// The Hello capability that tells Devolutions Server that this agent handles device management requests.
pub const CAPABILITY: &str = "device_management";

/// Largest encoded inventory part. The channel rejects an envelope over 64 KiB.
const MAX_INVENTORY_PART_BYTES: usize = 60_000;
const MAX_CHANNEL_ENVELOPE_BYTES: usize = 65_536;

#[derive(Debug)]
struct Snapshot {
    packages: Vec<InstalledPackage>,
    managers: Vec<PackageManager>,
    sources: Vec<PackageSource>,
    scan_completed_at: prost_types::Timestamp,
    update_scan_completed_at: Option<prost_types::Timestamp>,
}

/// Maximum number of concurrent package operation workers.
const MAX_CONCURRENT_OPERATION_REQUESTS: usize = 8;

/// Maximum number of concurrent workers for other device-management requests.
const MAX_CONCURRENT_OTHER_REQUESTS: usize = 8;

/// Serves one device management request, answering the request message `id` through `reporter`.
pub(crate) fn handle(
    context: DeviceManagementContext,
    _identity_id: Uuid,
    authority_id: Uuid,
    id: String,
    request: DeviceManagementRequest,
    reporter: Reporter,
    shutdown: watch::Receiver<bool>,
) {
    let Some(request) = request.request else {
        debug!(%id, "Device management request without content");
        return;
    };

    let worker_id = id.clone();
    let worker_reporter = reporter.clone();
    let _ = spawn_request(
        request,
        shutdown,
        move |request| async move {
            let id = worker_id;
            let reporter = worker_reporter;
            match request {
                Request::SyncInventory(request) => {
                    send_inventory(&context, &id, &request, |correlation_id, report| {
                        reporter.send(correlation_id, report);
                    })
                    .await;
                }
                Request::DiscoverUnigetuiInstances(_) => send_instances(&context, &reporter, &id).await,
                Request::PackageOperation(request) => {
                    let result = run_package_operation(&context, authority_id, request).await;
                    reporter.send(Some(id), package_operation_report(result));
                }
                Request::CatalogSync(request) => {
                    reporter.send(Some(id), catalog_unavailable_report(request.revision));
                }
            }
        },
        |request| {
            warn!(%id, "Device-management request limit reached");
            reject_busy_request(&id, request, |correlation_id, report| {
                reporter.send(correlation_id, report);
            });
        },
    );
}

fn spawn_request<F>(
    request: Request,
    shutdown: watch::Receiver<bool>,
    process: impl FnOnce(Request) -> F + Send + 'static,
    reject: impl FnOnce(Request),
) -> Option<tokio::task::JoinHandle<()>>
where
    F: Future<Output = ()> + Send + 'static,
{
    let Some(permit) = request_permit(&request) else {
        reject(request);
        return None;
    };
    let is_operation = matches!(&request, Request::PackageOperation(_));

    Some(tokio::spawn(async move {
        let _permit = permit;
        if *shutdown.borrow() {
            return;
        }
        finish_request(is_operation, process(request), shutdown).await;
    }))
}

async fn finish_request(is_operation: bool, processing: impl Future<Output = ()>, mut shutdown: watch::Receiver<bool>) {
    if is_operation {
        processing.await;
    } else {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {}
            () = processing => {},
        }
    }
}

fn reject_busy_request(id: &str, request: Request, mut send: impl FnMut(Option<String>, DeviceManagementReport)) {
    let error = "device-management request capacity reached".to_owned();
    let response = match request {
        Request::PackageOperation(request) => Some(package_operation_report(PackageOperationResult {
            operation_id: request.operation_id,
            success: false,
            error,
            status: PackageOperationStatus::Unknown.into(),
            execution_started: None,
        })),
        Request::CatalogSync(request) => Some(report(Report::CatalogSyncResult(CatalogSyncResult {
            revision: request.revision,
            ok: false,
            error,
        }))),
        Request::SyncInventory(request) => {
            send_bounded_report(
                id,
                inventory_unavailable_report(
                    &request.target_user_uuid,
                    &request.registry_epoch,
                    InventoryUnavailableReason::Busy,
                ),
                &mut send,
            );
            return;
        }
        Request::DiscoverUnigetuiInstances(_) => {
            Some(instances_unavailable_report(UniGetUiInstancesUnavailableReason::Busy))
        }
    };
    if let Some(report) = response {
        send(Some(id.to_owned()), report);
    }
}

fn request_permit(request: &Request) -> Option<SemaphorePermit<'static>> {
    static OPERATION_PERMITS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_OPERATION_REQUESTS);
    static OTHER_PERMITS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_OTHER_REQUESTS);
    let permits = match request {
        Request::PackageOperation(_) => &OPERATION_PERMITS,
        Request::SyncInventory(_) | Request::DiscoverUnigetuiInstances(_) | Request::CatalogSync(_) => &OTHER_PERMITS,
    };
    permits.try_acquire().ok()
}

fn report(report: Report) -> DeviceManagementReport {
    DeviceManagementReport { report: Some(report) }
}

fn catalog_unavailable_report(revision: i64) -> DeviceManagementReport {
    report(Report::CatalogSyncResult(CatalogSyncResult {
        revision,
        ok: false,
        error: "software catalog synchronization is unavailable".to_owned(),
    }))
}

fn package_operation_report(result: PackageOperationResult) -> DeviceManagementReport {
    let report = if result.status == i32::from(PackageOperationStatus::Unknown) {
        Report::PackageOperationUnknown(result)
    } else {
        Report::PackageOperationResult(result)
    };
    DeviceManagementReport { report: Some(report) }
}

fn inventory_unavailable_report(
    target_user_uuid: &str,
    registry_epoch: &str,
    reason: InventoryUnavailableReason,
) -> DeviceManagementReport {
    report(Report::InventoryUnavailable(InventoryUnavailable {
        target_user_uuid: target_user_uuid.to_owned(),
        registry_epoch: registry_epoch.to_owned(),
        reason: reason.into(),
    }))
}

fn instances_unavailable_report(reason: UniGetUiInstancesUnavailableReason) -> DeviceManagementReport {
    report(Report::UnigetuiInstancesUnavailable(UniGetUiInstancesUnavailable {
        reason: reason.into(),
    }))
}

/// Sends `report` only when its whole envelope, including the outer ID and correlation, fits the channel limit.
///
/// Returns whether the report was sent.
fn send_bounded_report(
    correlation_id: &str,
    report: DeviceManagementReport,
    send: &mut impl FnMut(Option<String>, DeviceManagementReport),
) -> bool {
    // The reporter assigns a hyphenated UUID, which encodes to the same length as the nil UUID.
    let envelope = agent_channel_proto::AgentMessage {
        id: Uuid::nil().to_string(),
        correlation_id: Some(correlation_id.to_owned()),
        payload: Some(agent_channel_proto::agent_message::Payload::DeviceManagement(
            report.clone(),
        )),
    };
    if MAX_CHANNEL_ENVELOPE_BYTES < envelope.encoded_len() {
        // UNTESTED: The warning explains why the Authority will receive no report.
        // The size tests don't capture logs; retain the warning when changing this path.
        warn!(
            correlation_id,
            "Cannot send device-management report because it exceeds the channel envelope limit"
        );
        return false;
    }
    send(Some(correlation_id.to_owned()), report);
    true
}

/// Sends the inventory in parts that each fit in one channel envelope.
async fn send_inventory(
    context: &DeviceManagementContext,
    correlation_id: &str,
    request: &agent_channel_proto::SyncInventory,
    mut send: impl FnMut(Option<String>, DeviceManagementReport),
) {
    let inventory = match collect_inventory(context, request).await {
        Ok(inventory) => inventory,
        Err(error) => {
            warn!(
                correlation_id,
                error = format!("{error:#}"),
                "UniGetUI inventory is unavailable"
            );
            send_bounded_report(
                correlation_id,
                inventory_unavailable_report(
                    &request.target_user_uuid,
                    &request.registry_epoch,
                    InventoryUnavailableReason::SafeEndpointUnavailable,
                ),
                &mut send,
            );
            return;
        }
    };

    let parts = match inventory_parts(inventory, &request.target_user_uuid, &request.registry_epoch) {
        Ok(parts) => parts,
        Err(error) => {
            warn!(
                correlation_id,
                error = format!("{error:#}"),
                "Failed to paginate UniGetUI inventory"
            );
            send_bounded_report(
                correlation_id,
                inventory_unavailable_report(
                    &request.target_user_uuid,
                    &request.registry_epoch,
                    InventoryUnavailableReason::CollectionFailed,
                ),
                &mut send,
            );
            return;
        }
    };
    for part in parts {
        send_bounded_report(correlation_id, report(Report::Inventory(part)), &mut send);
    }
}

async fn send_instances(context: &DeviceManagementContext, reporter: &Reporter, correlation_id: &str) {
    report_instances(
        correlation_id,
        collect_instances(context).await,
        |correlation_id, report| {
            reporter.send(correlation_id, report);
        },
    );
}

/// Reports a complete discovery as one bounded list, and anything else as unavailable.
fn report_instances(
    correlation_id: &str,
    instances: anyhow::Result<UniGetUiInstances>,
    mut send: impl FnMut(Option<String>, DeviceManagementReport),
) {
    let reason = match instances {
        Ok(instances) => {
            let list = report(Report::UnigetuiInstances(instances));
            if send_bounded_report(correlation_id, list, &mut send) {
                return;
            }
            UniGetUiInstancesUnavailableReason::TooLarge
        }
        Err(error) => {
            warn!(
                correlation_id,
                error = format!("{error:#}"),
                "UniGetUI discovery is unavailable"
            );
            UniGetUiInstancesUnavailableReason::CollectionFailed
        }
    };
    send_bounded_report(correlation_id, instances_unavailable_report(reason), &mut send);
}

fn inventory_parts(
    inventory: Snapshot,
    target_user_uuid: &str,
    registry_epoch: &str,
) -> anyhow::Result<Vec<InventoryReport>> {
    let report_id = Uuid::new_v4().to_string();
    let mut parts = Vec::new();
    // Reserve the largest page header, including the final-page flag, before assigning indexes.
    let mut current = InventoryReport {
        report_id: report_id.clone(),
        last: true,
        packages: Vec::new(),
        managers: inventory.managers,
        sources: inventory.sources,
        target_user_uuid: target_user_uuid.to_owned(),
        registry_epoch: registry_epoch.to_owned(),
        scan_completed_at: Some(inventory.scan_completed_at),
        update_scan_completed_at: inventory.update_scan_completed_at,
        page_index: u32::MAX,
        page_count: u32::MAX,
    };

    if MAX_INVENTORY_PART_BYTES < current.encoded_len() {
        anyhow::bail!("inventory metadata exceeds the channel payload limit");
    }

    for package in inventory.packages {
        // A package within the size limit needs at most four bytes for its tag and length.
        let package_len = package.encoded_len() + 4;
        if MAX_INVENTORY_PART_BYTES < package_len {
            anyhow::bail!("package exceeds the inventory part size limit");
        }
        if MAX_INVENTORY_PART_BYTES < current.encoded_len() + package_len {
            let next = InventoryReport {
                report_id: report_id.clone(),
                last: true,
                packages: Vec::new(),
                managers: Vec::new(),
                sources: Vec::new(),
                target_user_uuid: target_user_uuid.to_owned(),
                registry_epoch: registry_epoch.to_owned(),
                scan_completed_at: current.scan_completed_at,
                update_scan_completed_at: current.update_scan_completed_at,
                page_index: u32::MAX,
                page_count: u32::MAX,
            };
            parts.push(std::mem::replace(&mut current, next));
        }
        current.packages.push(package);
    }

    parts.push(current);
    let page_count = u32::try_from(parts.len()).context("too many inventory pages")?;
    for (page_index, part) in (0..page_count).zip(&mut parts) {
        part.page_index = page_index;
        part.page_count = page_count;
        part.last = page_index + 1 == page_count;
        anyhow::ensure!(
            part.encoded_len() <= MAX_INVENTORY_PART_BYTES,
            "inventory page exceeds the channel payload limit"
        );
    }
    Ok(parts)
}

#[cfg(windows)]
async fn collect_instances(context: &DeviceManagementContext) -> anyhow::Result<UniGetUiInstances> {
    let registration = context
        .registration()
        .cloned()
        .context("UniGetUI registration is unavailable")?;
    let users = context.users().cloned().context("user registry is unavailable")?;
    tokio::task::spawn_blocking(move || {
        let instances = registration
            .snapshot()?
            .into_iter()
            .map(|endpoint| {
                let sid = user_registry::UserSid::parse(&endpoint.user_sid().to_string())?;
                let user_uuid = users.get_or_create(&sid)?.as_uuid().to_string();
                Ok(UniGetUiInstance {
                    user_uuid,
                    session_id: endpoint.session_id(),
                    display_name: endpoint.display_name().unwrap_or_default().to_owned(),
                    signature_verified: true,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(UniGetUiInstances {
            instances,
            registry_epoch: users.epoch().to_string(),
        })
    })
    .await
    .context("UniGetUI discovery worker failed")?
}

#[cfg(not(windows))]
async fn collect_instances(_context: &DeviceManagementContext) -> anyhow::Result<UniGetUiInstances> {
    anyhow::bail!("UniGetUI registration is only supported on Windows")
}

#[cfg(windows)]
async fn resolve_target(
    context: &DeviceManagementContext,
    target_user_uuid: &str,
    registry_epoch: &str,
) -> anyhow::Result<now_package_broker::registration::RegisteredEndpoint> {
    let target = Uuid::parse_str(target_user_uuid).context("invalid target user UUID")?;
    anyhow::ensure!(!target.is_nil(), "target user UUID is nil");
    let epoch = Uuid::parse_str(registry_epoch).context("invalid registry epoch")?;
    let registration = context
        .registration()
        .cloned()
        .context("UniGetUI registration is unavailable")?;
    let users = context.users().cloned().context("user registry is unavailable")?;
    tokio::task::spawn_blocking(move || {
        anyhow::ensure!(epoch == users.epoch(), "registry epoch does not match");
        let sid = users
            .resolve(user_registry::UserId::from_uuid(target))
            .context("unknown target user UUID")?;
        registration
            .snapshot()?
            .into_iter()
            .find(|endpoint| endpoint.user_sid().to_string() == sid.as_str())
            .context("no live UniGetUI instance belongs to the target user")
    })
    .await
    .context("UniGetUI target resolution worker failed")?
}

#[cfg(windows)]
async fn collect_inventory(
    context: &DeviceManagementContext,
    request: &agent_channel_proto::SyncInventory,
) -> anyhow::Result<Snapshot> {
    anyhow::ensure!(context.remote_inventory_enabled(), "remote inventory is disabled");
    let endpoint = resolve_target(context, &request.target_user_uuid, &request.registry_epoch).await?;
    let snapshot = endpoint
        .request("GetInventorySnapshot", serde_json::json!({}))
        .await
        .context("safe UniGetUI inventory snapshot is unavailable")?;
    unigetui::parse_snapshot(snapshot)
}

#[cfg(not(windows))]
async fn collect_inventory(
    _context: &DeviceManagementContext,
    _request: &agent_channel_proto::SyncInventory,
) -> anyhow::Result<Snapshot> {
    anyhow::bail!("UniGetUI inventory is only supported on Windows")
}

#[cfg(windows)]
async fn run_package_operation(
    context: &DeviceManagementContext,
    authority_id: Uuid,
    request: PackageOperationRequest,
) -> PackageOperationResult {
    operation::run(context, authority_id, request).await
}

#[cfg(not(windows))]
async fn run_package_operation(
    _context: &DeviceManagementContext,
    _authority_id: Uuid,
    request: PackageOperationRequest,
) -> PackageOperationResult {
    PackageOperationResult {
        operation_id: request.operation_id,
        success: false,
        error: String::new(),
        status: PackageOperationStatus::Unknown.into(),
        execution_started: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn inventory(
        packages: Vec<InstalledPackage>,
        managers: Vec<PackageManager>,
        sources: Vec<PackageSource>,
    ) -> Snapshot {
        Snapshot {
            packages,
            managers,
            sources,
            scan_completed_at: prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            },
            update_scan_completed_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_210,
                nanos: 0,
            }),
        }
    }

    fn blocked_request(
        request: Request,
        shutdown: watch::Receiver<bool>,
        started: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<Semaphore>,
        reject: impl FnOnce(Request),
    ) -> Option<tokio::task::JoinHandle<()>> {
        spawn_request(
            request,
            shutdown,
            move |_| async move {
                started.send(()).expect("start receiver is alive");
                release.acquire().await.expect("release semaphore is open").forget();
            },
            reject,
        )
    }

    async fn wait_for_workers(started: &mut tokio::sync::mpsc::UnboundedReceiver<()>, count: usize) {
        for _ in 0..count {
            tokio::time::timeout(Duration::from_secs(5), started.recv())
                .await
                .expect("workers start without waiting for capacity")
                .expect("start sender is alive");
        }
    }

    #[tokio::test]
    async fn operations_and_other_requests_have_independent_worker_capacity() {
        // oracle: mutant waiting package operations consume inventory and discovery worker capacity
        let (_shutdown, shutdown) = watch::channel(false);
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let operation_release = Arc::new(Semaphore::new(0));
        let other_release = Arc::new(Semaphore::new(0));
        let operation = |id: &str| {
            Request::PackageOperation(PackageOperationRequest {
                operation_id: id.to_owned(),
                ..Default::default()
            })
        };
        let inventory = || Request::SyncInventory(agent_channel_proto::SyncInventory::default());
        let mut operations = Vec::new();
        for _ in 0..8 {
            operations.push(
                blocked_request(
                    operation("active"),
                    shutdown.clone(),
                    started_tx.clone(),
                    Arc::clone(&operation_release),
                    |_| panic!("unexpected operation rejection"),
                )
                .expect("eight operations fit"),
            );
        }
        wait_for_workers(&mut started_rx, 8).await;

        let mut reports = Vec::new();
        let busy = blocked_request(
            operation("busy"),
            shutdown.clone(),
            started_tx.clone(),
            Arc::clone(&operation_release),
            |request| reject_busy_request("busy-operation", request, |id, report| reports.push((id, report))),
        );
        assert!(busy.is_none(), "the ninth operation is rejected");
        let [
            (
                Some(correlation),
                DeviceManagementReport {
                    report: Some(Report::PackageOperationUnknown(result)),
                },
            ),
        ] = reports.as_slice()
        else {
            panic!("expected an unknown operation report");
        };
        assert_eq!(correlation, "busy-operation");
        assert_eq!(result.operation_id, "busy");
        assert_eq!(result.status, i32::from(PackageOperationStatus::Unknown));
        assert!(!result.success);
        assert_eq!(result.execution_started, None);

        let mut other_workers = Vec::new();
        for index in 0..8 {
            let request = match index {
                0..=3 => inventory(),
                4..=6 => Request::DiscoverUnigetuiInstances(agent_channel_proto::DiscoverUniGetUiInstances {}),
                _ => Request::CatalogSync(agent_channel_proto::CatalogSync::default()),
            };
            other_workers.push(
                blocked_request(
                    request,
                    shutdown.clone(),
                    started_tx.clone(),
                    Arc::clone(&other_release),
                    |_| panic!("unexpected non-operation rejection"),
                )
                .expect("eight other requests fit beside eight operations"),
            );
        }
        wait_for_workers(&mut started_rx, 8).await;

        let mut reports = Vec::new();
        let busy = blocked_request(
            inventory(),
            shutdown.clone(),
            started_tx.clone(),
            Arc::clone(&other_release),
            |request| reject_busy_request("busy-inventory", request, |id, report| reports.push((id, report))),
        );
        assert!(busy.is_none(), "the ninth non-operation request is rejected");
        let [
            (
                Some(correlation),
                DeviceManagementReport {
                    report: Some(Report::InventoryUnavailable(result)),
                },
            ),
        ] = reports.as_slice()
        else {
            panic!("expected an unavailable inventory report");
        };
        assert_eq!(correlation, "busy-inventory");
        assert_eq!(result.reason, i32::from(InventoryUnavailableReason::Busy));

        operation_release.add_permits(8);
        for worker in operations {
            worker.await.expect("operation worker completes");
        }
        let replacement = blocked_request(
            operation("replacement"),
            shutdown,
            started_tx,
            Arc::clone(&operation_release),
            |_| panic!("unexpected replacement rejection"),
        )
        .expect("a completed operation frees its slot even while other workers are busy");
        wait_for_workers(&mut started_rx, 1).await;

        operation_release.add_permits(1);
        other_release.add_permits(8);
        replacement.await.expect("replacement worker completes");
        for worker in other_workers {
            worker.await.expect("other worker completes");
        }
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
    #[tokio::test]
    async fn unavailable_inventory_reports_reason_and_request_correlation() {
        let target_user_uuid = "bb195c19-20e1-4ad9-8eca-d8396c153881";
        let registry_epoch = "e154c84b-c928-40b5-9171-c970d960bd16";
        let request = agent_channel_proto::SyncInventory {
            target_user_uuid: target_user_uuid.to_owned(),
            registry_epoch: registry_epoch.to_owned(),
        };
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let mut sent = Vec::new();

        send_inventory(
            &DeviceManagementContext::default(),
            request_id,
            &request,
            |correlation_id, report| {
                sent.push((correlation_id, report));
            },
        )
        .await;

        let [
            (
                correlation_id,
                DeviceManagementReport {
                    report: Some(Report::InventoryUnavailable(unavailable)),
                },
            ),
        ] = sent.as_slice()
        else {
            panic!("expected an unavailable report");
        };
        assert_eq!(correlation_id.as_deref(), Some(request_id));
        assert_eq!(unavailable.target_user_uuid, target_user_uuid);
        assert_eq!(unavailable.registry_epoch, registry_epoch);
        assert_eq!(unavailable.reason, 1);
        assert_eq!(sent[0].1.encode_to_vec().first(), Some(&0x32));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    #[tokio::test]
    async fn oversized_inventory_target_never_produces_an_oversized_report() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let target_user_uuid = "x".repeat(65_440);
        let sync = agent_channel_proto::SyncInventory {
            target_user_uuid,
            registry_epoch: "e154c84b-c928-40b5-9171-c970d960bd16".to_owned(),
        };
        let mut sent = Vec::new();
        let request = agent_channel_proto::ServerMessage {
            id: request_id.to_owned(),
            correlation_id: None,
            payload: Some(agent_channel_proto::server_message::Payload::DeviceManagement(
                DeviceManagementRequest {
                    request: Some(Request::SyncInventory(sync.clone())),
                },
            )),
        };
        assert!(request.encoded_len() <= 65_536);

        send_inventory(
            &DeviceManagementContext::default(),
            request_id,
            &sync,
            |correlation_id, report| {
                sent.push((correlation_id, report));
            },
        )
        .await;
        reject_busy_request(request_id, Request::SyncInventory(sync), |correlation_id, report| {
            sent.push((correlation_id, report));
        });

        assert!(sent.is_empty());
    }

    // oracle: mutant unavailable catalog synchronization is reported as successful
    #[test]
    fn catalog_sync_is_reported_unavailable() {
        let response = catalog_unavailable_report(42);
        let Some(Report::CatalogSyncResult(result)) = response.report else {
            panic!("expected a catalog synchronization result");
        };
        assert_eq!(result.revision, 42);
        assert!(!result.ok);
        assert!(!result.error.is_empty());
    }

    // oracle: mutant stream shutdown drops an active package operation before it is settled
    #[tokio::test]
    async fn package_operation_continues_after_stream_shutdown() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(finish_request(
            true,
            async move { release_rx.await.expect("release signal is sent") },
            shutdown_rx,
        ));

        shutdown_tx.send(true).expect("shutdown receiver is alive");
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        release_tx.send(()).expect("release receiver is alive");
        task.await.expect("request task completes");
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    #[test]
    fn report_limit_counts_the_outer_id_and_correlation() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let discovery = |name_len: usize| {
            report(Report::UnigetuiInstances(UniGetUiInstances {
                instances: vec![UniGetUiInstance {
                    user_uuid: "bb195c19-20e1-4ad9-8eca-d8396c153881".to_owned(),
                    session_id: 1,
                    display_name: "n".repeat(name_len),
                    signature_verified: true,
                }],
                registry_epoch: "e154c84b-c928-40b5-9171-c970d960bd16".to_owned(),
            }))
        };
        // Measures the envelope the reporter sends: a fresh UUID ID plus the request correlation.
        let envelope_len = |report: DeviceManagementReport| {
            agent_channel_proto::AgentMessage {
                id: Uuid::new_v4().to_string(),
                correlation_id: Some(request_id.to_owned()),
                payload: Some(agent_channel_proto::agent_message::Payload::DeviceManagement(report)),
            }
            .encoded_len()
        };
        let largest = (65_000..65_536)
            .rev()
            .find(|&name_len| envelope_len(discovery(name_len)) == 65_536)
            .expect("a discovery report fills the envelope exactly");
        assert_eq!(envelope_len(discovery(largest + 1)), 65_537);
        // Without the outer fields, the over-limit report would still fit.
        assert!(discovery(largest + 1).encoded_len() < 65_536);

        let mut sent = Vec::new();
        for name_len in [largest, largest + 1] {
            send_bounded_report(request_id, discovery(name_len), &mut |correlation_id, report| {
                sent.push((correlation_id, report));
            });
        }

        let [(correlation_id, report)] = sent.as_slice() else {
            panic!("expected only the report that fits");
        };
        assert_eq!(correlation_id.as_deref(), Some(request_id));
        assert_eq!(report, &discovery(largest));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[test]
    fn busy_discovery_reports_unavailability_with_correlation() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let mut sent = Vec::new();

        reject_busy_request(
            request_id,
            Request::DiscoverUnigetuiInstances(agent_channel_proto::DiscoverUniGetUiInstances {}),
            |correlation_id, report| sent.push((correlation_id, report)),
        );

        assert_eq!(
            sent,
            [(
                Some(request_id.to_owned()),
                instances_unavailable_report(UniGetUiInstancesUnavailableReason::Busy)
            )]
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[test]
    fn incomplete_discovery_reports_unavailability_instead_of_a_list() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let mut sent = Vec::new();

        report_instances(
            request_id,
            Err(anyhow::anyhow!("an endpoint is unresolved")),
            |correlation_id, report| sent.push((correlation_id, report)),
        );

        assert_eq!(
            sent,
            [(
                Some(request_id.to_owned()),
                instances_unavailable_report(UniGetUiInstancesUnavailableReason::CollectionFailed)
            )]
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[test]
    fn oversized_discovery_reports_unavailability_instead_of_a_partial_list() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let instances = UniGetUiInstances {
            instances: (0..2_000)
                .map(|index| UniGetUiInstance {
                    user_uuid: Uuid::new_v4().to_string(),
                    session_id: index,
                    display_name: format!("DOMAIN\\user{index} (session {index})"),
                    signature_verified: true,
                })
                .collect(),
            registry_epoch: Uuid::new_v4().to_string(),
        };
        let mut sent = Vec::new();

        report_instances(request_id, Ok(instances), |correlation_id, report| {
            sent.push((correlation_id, report));
        });

        assert_eq!(
            sent,
            [(
                Some(request_id.to_owned()),
                instances_unavailable_report(UniGetUiInstancesUnavailableReason::TooLarge)
            )]
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §instances
    #[test]
    fn complete_discovery_reports_the_whole_list() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let instances = UniGetUiInstances {
            instances: vec![UniGetUiInstance {
                user_uuid: "bb195c19-20e1-4ad9-8eca-d8396c153881".to_owned(),
                session_id: 1,
                display_name: "DOMAIN\\user (session 1)".to_owned(),
                signature_verified: true,
            }],
            registry_epoch: "e154c84b-c928-40b5-9171-c970d960bd16".to_owned(),
        };
        let mut sent = Vec::new();

        report_instances(request_id, Ok(instances.clone()), |correlation_id, report| {
            sent.push((correlation_id, report));
        });

        assert_eq!(
            sent,
            [(
                Some(request_id.to_owned()),
                report(Report::UnigetuiInstances(instances))
            )]
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
    #[test]
    fn busy_inventory_request_reports_unavailability_with_correlation() {
        let target_user_uuid = "bb195c19-20e1-4ad9-8eca-d8396c153881";
        let registry_epoch = "e154c84b-c928-40b5-9171-c970d960bd16";
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let request = Request::SyncInventory(agent_channel_proto::SyncInventory {
            target_user_uuid: target_user_uuid.to_owned(),
            registry_epoch: registry_epoch.to_owned(),
        });
        let mut sent = Vec::new();

        reject_busy_request(request_id, request, |correlation_id, report| {
            sent.push((correlation_id, report));
        });

        let [
            (
                correlation_id,
                DeviceManagementReport {
                    report: Some(Report::InventoryUnavailable(unavailable)),
                },
            ),
        ] = sent.as_slice()
        else {
            panic!("expected an unavailable report");
        };
        assert_eq!(correlation_id.as_deref(), Some(request_id));
        assert_eq!(unavailable.target_user_uuid, target_user_uuid);
        assert_eq!(unavailable.registry_epoch, registry_epoch);
        assert_eq!(unavailable.reason, 2);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
    #[test]
    fn inventory_page_indexes_use_the_agreed_wire_fields() {
        let page = InventoryReport {
            page_index: 1,
            page_count: 2,
            ..Default::default()
        };

        assert_eq!(page.encode_to_vec(), [0x38, 1, 0x40, 2]);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
    #[test]
    fn empty_inventory_has_one_complete_page() {
        let inventory = inventory(Vec::new(), Vec::new(), Vec::new());

        let pages = inventory_parts(inventory, "user", "epoch").expect("inventory fits in one page");

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].page_count, 1);
        assert_eq!(pages[0].page_index, 0);
        assert!(pages[0].last);
        assert!(!pages[0].report_id.is_empty());
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct LegacyReport {
        #[prost(message, optional, tag = "2")]
        package_operation_result: Option<PackageOperationResult>,
    }

    #[test]
    fn unknown_result_does_not_decode_as_a_legacy_failure() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let report = package_operation_report(PackageOperationResult {
            operation_id: "operation-1".to_owned(),
            success: false,
            error: String::new(),
            status: PackageOperationStatus::Unknown.into(),
            execution_started: None,
        });

        assert!(matches!(report.report, Some(Report::PackageOperationUnknown(_))));
        let encoded = report.encode_to_vec();
        assert_eq!(encoded.first(), Some(&0x2a));
        let legacy = LegacyReport::decode(encoded.as_slice()).expect("decode legacy report");
        assert!(legacy.package_operation_result.is_none());
    }

    #[test]
    fn known_result_uses_the_existing_report_field() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
        let report = package_operation_report(PackageOperationResult {
            operation_id: "operation-1".to_owned(),
            success: true,
            error: String::new(),
            status: PackageOperationStatus::Unspecified.into(),
            execution_started: None,
        });

        assert!(matches!(report.report, Some(Report::PackageOperationResult(_))));
        let legacy = LegacyReport::decode(report.encode_to_vec().as_slice()).expect("decode legacy report");
        assert_eq!(
            legacy.package_operation_result.map(|result| result.operation_id),
            Some("operation-1".to_owned())
        );
    }

    #[test]
    fn inventory_pages_identify_a_complete_collection() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let manager = PackageManager {
            name: "winget".to_owned(),
            installed: true,
            enabled: true,
            version: String::new(),
        };
        let source = PackageSource {
            manager: "winget".to_owned(),
            name: "winget".to_owned(),
            url: String::new(),
        };
        let inventory = inventory(
            (0..500)
                .map(|index| InstalledPackage {
                    manager: "winget".to_owned(),
                    source: "winget".to_owned(),
                    source_name: "winget".to_owned(),
                    id: format!("package-{index}"),
                    name: "n".repeat(128),
                    version: "1.0".to_owned(),
                    available_version: String::new(),
                    scope: "UNKNOWN".to_owned(),
                    reported_scope: String::new(),
                })
                .collect(),
            vec![manager.clone()],
            vec![source.clone()],
        );
        let target_user_uuid = "bb195c19-20e1-4ad9-8eca-d8396c153881";
        let registry_epoch = "e154c84b-c928-40b5-9171-c970d960bd16";

        let pages = inventory_parts(inventory, target_user_uuid, registry_epoch).expect("inventory fits in pages");

        assert!(pages.len() > 1);
        assert_eq!(pages[0].managers, [manager]);
        assert_eq!(pages[0].sources, [source]);
        assert!(
            pages[1..]
                .iter()
                .all(|page| page.managers.is_empty() && page.sources.is_empty())
        );
        for (index, page) in pages.iter().enumerate() {
            assert_eq!(page.target_user_uuid, target_user_uuid);
            assert_eq!(page.registry_epoch, registry_epoch);
            assert_eq!(page.scan_completed_at, pages[0].scan_completed_at);
            assert_eq!(page.update_scan_completed_at, pages[0].update_scan_completed_at);
            assert_eq!(page.report_id, pages[0].report_id);
            assert_eq!(usize::try_from(page.page_index).expect("page index fits"), index);
            assert_eq!(usize::try_from(page.page_count).expect("page count fits"), pages.len());
            assert_eq!(page.last, index + 1 == pages.len());
            // oracle: mutant omitted the final page-size bound
            assert!(page.encoded_len() <= MAX_INVENTORY_PART_BYTES);
            let envelope = agent_channel_proto::AgentMessage {
                id: "888351ae-4a56-43a7-926e-cb461403b60d".to_owned(),
                correlation_id: Some("91948c6a-7c54-409d-bbd6-a42dd9b73e32".to_owned()),
                payload: Some(agent_channel_proto::agent_message::Payload::DeviceManagement(report(
                    Report::Inventory(page.clone()),
                ))),
            };
            // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
            assert!(envelope.encoded_len() <= 65_536);
        }
    }

    // oracle: mutant omitted page header from the size check
    #[test]
    fn package_must_fit_with_the_next_page_header() {
        let inventory = inventory(
            vec![InstalledPackage {
                id: "p".repeat(59_950),
                ..Default::default()
            }],
            vec![PackageManager {
                name: "m".repeat(1_000),
                ..Default::default()
            }],
            Vec::new(),
        );

        assert!(inventory_parts(inventory, "user", "epoch").is_err());
    }

    #[test]
    fn oversized_package_prevents_an_incomplete_inventory_report() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let inventory = inventory(
            vec![InstalledPackage {
                manager: "winget".to_owned(),
                source: "winget".to_owned(),
                source_name: "winget".to_owned(),
                id: "oversized".to_owned(),
                name: "n".repeat(MAX_INVENTORY_PART_BYTES),
                version: "1.0".to_owned(),
                available_version: String::new(),
                scope: "UNKNOWN".to_owned(),
                reported_scope: String::new(),
            }],
            Vec::new(),
            Vec::new(),
        );

        assert!(inventory_parts(inventory, "user", "epoch").is_err());
    }

    #[test]
    fn oversized_inventory_metadata_is_rejected() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let inventory = inventory(
            Vec::new(),
            Vec::new(),
            vec![PackageSource {
                manager: "winget".to_owned(),
                name: "n".repeat(MAX_INVENTORY_PART_BYTES),
                url: String::new(),
            }],
        );

        assert!(inventory_parts(inventory, "user", "epoch").is_err());
    }
}
