//! Handles device-management requests for UniGetUI discovery, package inventory and software catalogs.

mod software_catalog;
mod unigetui;

use std::sync::Mutex;

use agent_channel_client::Reporter;
use agent_channel_proto::device_management_report::Report;
use agent_channel_proto::device_management_request::Request;
use agent_channel_proto::{
    CatalogSyncResult, DeviceManagementReport, DeviceManagementRequest, InstalledPackage, InventoryReport,
    InventoryUnavailable, InventoryUnavailableReason, PackageManager, PackageOperationRequest, PackageOperationResult,
    PackageOperationStatus, PackageSource, UniGetUiInstances,
};
use anyhow::Context as _;
use prost::Message as _;
use tokio::sync::{Semaphore, SemaphorePermit, watch};
use uuid::Uuid;

/// The Hello capability that tells Devolutions Server that this agent handles device management requests.
pub const CAPABILITY: &str = "device_management";

/// Largest encoded inventory part. The channel rejects an envelope over 64 KiB.
const MAX_INVENTORY_PART_BYTES: usize = 60_000;
const MAX_CHANNEL_ENVELOPE_BYTES: usize = 65_536;

/// Maximum number of concurrent device-management request workers.
const MAX_CONCURRENT_REQUESTS: usize = 8;
// UNTESTED: This cap prevents request floods from spawning unbounded tasks.
// Check that permits stay held for the worker lifetime when changing dispatch.

/// Serves one device management request, answering the request message `id` through `reporter`.
pub(crate) fn handle(
    identity_id: Uuid,
    id: String,
    request: DeviceManagementRequest,
    reporter: Reporter,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(request) = request.request else {
        debug!(%id, "Device management request without content");
        return;
    };

    let Some(permit) = request_permit() else {
        warn!(%id, "Device-management request limit reached");
        reject_busy_request(&id, request, |correlation_id, report| {
            reporter.send(correlation_id, report);
        });
        return;
    };

    tokio::spawn(async move {
        let _permit = permit;
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => {}
            () = async move {
                match request {
                    Request::SyncInventory(request) => {
                        send_inventory(&id, &request.target_user_sid, |correlation_id, report| {
                            reporter.send(correlation_id, report);
                        })
                        .await;
                    }
                    Request::DiscoverUnigetuiInstances(_) => send_instances(&reporter, &id).await,
                    Request::PackageOperation(request) => {
                        let result = run_package_operation(request);
                        reporter.send(Some(id.clone()), package_operation_report(result));
                    }
                    Request::CatalogSync(request) => {
                        // Serializes catalog writes, because each request runs on its own task.
                        static CATALOG_LOCK: Mutex<()> = Mutex::new(());

                        let revision = request.revision;
                        let result = tokio::task::spawn_blocking(move || {
                            let _guard = CATALOG_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                            software_catalog::apply(identity_id, request)
                        })
                        .await
                        .unwrap_or_else(|error| Err(anyhow::anyhow!("catalog synchronization worker failed: {error}")));
                        let error = match &result {
                            Ok(()) => String::new(),
                            Err(error) => {
                                warn!(
                                    revision,
                                    error = format!("{error:#}"),
                                    "Software catalog synchronization failed"
                                );
                                format!("{error:#}")
                            }
                        };
                        reporter.send(
                            Some(id),
                            report(Report::CatalogSyncResult(CatalogSyncResult {
                                revision,
                                ok: result.is_ok(),
                                error,
                            })),
                        );
                    }
                }
            } => {},
        }
    });
}

fn reject_busy_request(id: &str, request: Request, mut send: impl FnMut(Option<String>, DeviceManagementReport)) {
    let error = "device-management request capacity reached".to_owned();
    let response = match request {
        Request::PackageOperation(request) => Some(package_operation_report(PackageOperationResult {
            operation_id: request.operation_id,
            success: false,
            error,
            status: PackageOperationStatus::Unknown.into(),
        })),
        Request::CatalogSync(request) => Some(report(Report::CatalogSyncResult(CatalogSyncResult {
            revision: request.revision,
            ok: false,
            error,
        }))),
        Request::SyncInventory(request) => {
            send_bounded_report(
                id,
                inventory_unavailable_report(&request.target_user_sid, InventoryUnavailableReason::Busy),
                &mut send,
            );
            return;
        }
        Request::DiscoverUnigetuiInstances(_) => None,
    };
    if let Some(report) = response {
        send(Some(id.to_owned()), report);
    }
}

fn request_permit() -> Option<SemaphorePermit<'static>> {
    static REQUEST_PERMITS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_REQUESTS);
    REQUEST_PERMITS.try_acquire().ok()
}

fn report(report: Report) -> DeviceManagementReport {
    DeviceManagementReport { report: Some(report) }
}

fn package_operation_report(result: PackageOperationResult) -> DeviceManagementReport {
    let report = if result.status == i32::from(PackageOperationStatus::Unknown) {
        Report::PackageOperationUnknown(result)
    } else {
        Report::PackageOperationResult(result)
    };
    DeviceManagementReport { report: Some(report) }
}

fn inventory_unavailable_report(target_user_sid: &str, reason: InventoryUnavailableReason) -> DeviceManagementReport {
    report(Report::InventoryUnavailable(InventoryUnavailable {
        target_user_sid: target_user_sid.to_owned(),
        reason: reason.into(),
    }))
}

/// Sends `report` only when its whole envelope, including the outer ID and correlation, fits the channel limit.
fn send_bounded_report(
    correlation_id: &str,
    report: DeviceManagementReport,
    send: &mut impl FnMut(Option<String>, DeviceManagementReport),
) {
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
        return;
    }
    send(Some(correlation_id.to_owned()), report);
}

/// Sends the inventory in parts that each fit in one channel envelope.
async fn send_inventory(
    correlation_id: &str,
    target_user_sid: &str,
    mut send: impl FnMut(Option<String>, DeviceManagementReport),
) {
    let inventory = match collect_inventory(target_user_sid).await {
        Ok(inventory) => inventory,
        Err(error) => {
            warn!(
                correlation_id,
                error = format!("{error:#}"),
                "UniGetUI inventory is unavailable"
            );
            send_bounded_report(
                correlation_id,
                inventory_unavailable_report(target_user_sid, InventoryUnavailableReason::SafeEndpointUnavailable),
                &mut send,
            );
            return;
        }
    };

    let parts = match inventory_parts(inventory, target_user_sid) {
        Ok(parts) => parts,
        Err(error) => {
            warn!(
                correlation_id,
                error = format!("{error:#}"),
                "Failed to paginate UniGetUI inventory"
            );
            send_bounded_report(
                correlation_id,
                inventory_unavailable_report(target_user_sid, InventoryUnavailableReason::CollectionFailed),
                &mut send,
            );
            return;
        }
    };
    for part in parts {
        send_bounded_report(correlation_id, report(Report::Inventory(part)), &mut send);
    }
}

async fn send_instances(reporter: &Reporter, correlation_id: &str) {
    match unigetui::instances().await {
        Ok(instances) => send_bounded_report(
            correlation_id,
            report(Report::UnigetuiInstances(UniGetUiInstances { instances })),
            &mut |correlation_id, report| reporter.send(correlation_id, report),
        ),
        Err(error) => warn!(error = format!("{error:#}"), "Failed to discover UniGetUI instances"),
    }
}

fn inventory_parts(inventory: Inventory, target_user_sid: &str) -> anyhow::Result<Vec<InventoryReport>> {
    let report_id = Uuid::new_v4().to_string();
    let mut parts = Vec::new();
    // Reserve the largest page header, including the final-page flag, before assigning indexes.
    let mut current = InventoryReport {
        report_id: report_id.clone(),
        last: true,
        packages: Vec::new(),
        managers: inventory.managers,
        sources: inventory.sources,
        target_user_sid: target_user_sid.to_owned(),
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
                target_user_sid: target_user_sid.to_owned(),
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

struct Inventory {
    packages: Vec<InstalledPackage>,
    managers: Vec<PackageManager>,
    sources: Vec<PackageSource>,
}

async fn collect_inventory(target_user_sid: &str) -> anyhow::Result<Inventory> {
    collect_inventory_from(unigetui::resolve_target(target_user_sid)).await
}

async fn collect_inventory_from(
    resolve: impl Future<Output = anyhow::Result<unigetui::TargetInstance>>,
) -> anyhow::Result<Inventory> {
    // The legacy inventory calls can modify manager state and expose source details.
    // Replace them with a safe endpoint; removing this guard must not enable the legacy routes.
    require_safe_inventory_endpoint()?;

    let instance = resolve.await.context("failed to resolve UniGetUI target")?;
    let (managers, managers_loading) = unigetui::managers(&instance)
        .await
        .context("failed to collect UniGetUI package managers")?;

    if managers_loading {
        anyhow::bail!("UniGetUI package managers are still loading");
    }

    // UniGetUI returns an empty list for a manager that is not ready, for example just after logon or wake.
    if !managers.iter().any(|manager| manager.enabled && manager.installed) {
        anyhow::bail!("no UniGetUI package manager is ready");
    }

    let packages = unigetui::installed_packages(&instance)
        .await
        .context("failed to collect UniGetUI inventory")?;
    info!(count = packages.len(), "Collected UniGetUI inventory");
    let sources = unigetui::sources(&instance)
        .await
        .context("failed to collect UniGetUI package sources")?;

    Ok(Inventory {
        packages,
        managers,
        sources,
    })
}

fn require_safe_inventory_endpoint() -> anyhow::Result<()> {
    anyhow::bail!("safe UniGetUI inventory endpoint is unavailable")
}

fn run_package_operation(request: PackageOperationRequest) -> PackageOperationResult {
    let operation_id = request.operation_id;
    let error = "authorized UniGetUI broker routing is not available in this build".to_owned();
    warn!(%operation_id, %error, "Package operation rejected");
    PackageOperationResult {
        operation_id,
        success: false,
        error,
        status: PackageOperationStatus::Unspecified.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
    #[tokio::test]
    async fn unavailable_inventory_does_not_contact_unigetui() {
        let attempted = AtomicBool::new(false);
        let result = collect_inventory_from(async {
            attempted.store(true, Ordering::SeqCst);
            Err(anyhow::anyhow!("target unavailable"))
        })
        .await;

        assert!(!attempted.load(Ordering::SeqCst), "inventory contacted UniGetUI");
        assert!(result.is_err());
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
    #[tokio::test]
    async fn unavailable_inventory_reports_reason_and_request_correlation() {
        let target_user_sid = "S-1-5-21-200";
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let mut sent = Vec::new();

        send_inventory(request_id, target_user_sid, |correlation_id, report| {
            sent.push((correlation_id, report));
        })
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
        assert_eq!(unavailable.target_user_sid, target_user_sid);
        assert_eq!(unavailable.reason, 1);
        assert_eq!(sent[0].1.encode_to_vec().first(), Some(&0x32));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    #[tokio::test]
    async fn oversized_inventory_target_never_produces_an_oversized_report() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let target_user_sid = "x".repeat(65_470);
        let mut sent = Vec::new();
        let request = agent_channel_proto::ServerMessage {
            id: request_id.to_owned(),
            correlation_id: None,
            payload: Some(agent_channel_proto::server_message::Payload::DeviceManagement(
                DeviceManagementRequest {
                    request: Some(Request::SyncInventory(agent_channel_proto::SyncInventory {
                        target_user_sid: target_user_sid.clone(),
                    })),
                },
            )),
        };
        assert!(request.encoded_len() <= 65_536);

        send_inventory(request_id, &target_user_sid, |correlation_id, report| {
            sent.push((correlation_id, report));
        })
        .await;
        reject_busy_request(
            request_id,
            Request::SyncInventory(agent_channel_proto::SyncInventory { target_user_sid }),
            |correlation_id, report| {
                sent.push((correlation_id, report));
            },
        );

        for (correlation_id, report) in sent {
            let envelope = agent_channel_proto::AgentMessage {
                id: "888351ae-4a56-43a7-926e-cb461403b60d".to_owned(),
                correlation_id,
                payload: Some(agent_channel_proto::agent_message::Payload::DeviceManagement(report)),
            };
            assert!(envelope.encoded_len() <= 65_536);
        }
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    #[test]
    fn report_limit_counts_the_outer_id_and_correlation() {
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let discovery = |name_len: usize| {
            report(Report::UnigetuiInstances(UniGetUiInstances {
                instances: vec![agent_channel_proto::UniGetUiInstance {
                    user_sid: "S-1-5-21-200".to_owned(),
                    session_id: 1,
                    display_name: "n".repeat(name_len),
                    signature_verified: true,
                }],
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

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
    #[test]
    fn busy_inventory_request_reports_unavailability_with_correlation() {
        let target_user_sid = "S-1-5-21-200";
        let request_id = "91948c6a-7c54-409d-bbd6-a42dd9b73e32";
        let request = Request::SyncInventory(agent_channel_proto::SyncInventory {
            target_user_sid: target_user_sid.to_owned(),
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
        assert_eq!(unavailable.target_user_sid, target_user_sid);
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
        let inventory = Inventory {
            packages: Vec::new(),
            managers: Vec::new(),
            sources: Vec::new(),
        };

        let pages = inventory_parts(inventory, "S-1-5-21-200").expect("inventory fits in one page");

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
        let inventory = Inventory {
            packages: (0..500)
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
            managers: Vec::new(),
            sources: Vec::new(),
        };
        let target_user_sid = "S-1-5-21-200";

        let pages = inventory_parts(inventory, target_user_sid).expect("inventory fits in pages");

        assert!(pages.len() > 1);
        for (index, page) in pages.iter().enumerate() {
            assert_eq!(page.target_user_sid, target_user_sid);
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
        let inventory = Inventory {
            packages: vec![InstalledPackage {
                id: "p".repeat(59_950),
                ..Default::default()
            }],
            managers: vec![PackageManager {
                name: "m".repeat(1_000),
                ..Default::default()
            }],
            sources: Vec::new(),
        };

        assert!(inventory_parts(inventory, "S-1-5-21-200").is_err());
    }

    #[test]
    fn oversized_package_prevents_an_incomplete_inventory_report() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let inventory = Inventory {
            packages: vec![InstalledPackage {
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
            managers: Vec::new(),
            sources: Vec::new(),
        };

        assert!(inventory_parts(inventory, "S-1-5-21-200").is_err());
    }

    #[test]
    fn oversized_inventory_metadata_is_rejected() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let inventory = Inventory {
            packages: Vec::new(),
            managers: Vec::new(),
            sources: vec![PackageSource {
                manager: "winget".to_owned(),
                name: "n".repeat(MAX_INVENTORY_PART_BYTES),
                url: String::new(),
            }],
        };

        assert!(inventory_parts(inventory, "S-1-5-21-200").is_err());
    }
}
