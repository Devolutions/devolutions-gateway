//! Handles device-management requests for UniGetUI discovery, package inventory and software catalogs.

mod software_catalog;
mod unigetui;

use std::sync::Mutex;

use agent_channel_client::Reporter;
use agent_channel_proto::device_management_report::Report;
use agent_channel_proto::device_management_request::Request;
use agent_channel_proto::{
    CatalogSyncResult, DeviceManagementReport, DeviceManagementRequest, InstalledPackage, InventoryReport,
    PackageManager, PackageOperationRequest, PackageOperationResult, PackageSource, UniGetUiInstances,
};
use prost::Message as _;
use tokio::sync::{Semaphore, SemaphorePermit, watch};
use uuid::Uuid;

/// The Hello capability that tells Devolutions Server that this agent handles device management requests.
pub const CAPABILITY: &str = "device_management";

/// Largest encoded inventory part. The channel rejects an envelope over 64 KiB.
const MAX_INVENTORY_PART_BYTES: usize = 60_000;

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
        reject_busy_request(&reporter, &id, request);
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
                        send_inventory(&reporter, &id, &request.target_user_sid).await;
                    }
                    Request::DiscoverUnigetuiInstances(_) => send_instances(&reporter, &id).await,
                    Request::PackageOperation(request) => {
                        let target_user_sid = request.target_user_sid.clone();
                        let result = run_package_operation(request);
                        reporter.send(Some(id.clone()), report(Report::PackageOperationResult(result)));
                        send_inventory(&reporter, &id, &target_user_sid).await;
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

fn reject_busy_request(reporter: &Reporter, id: &str, request: Request) {
    let error = "device-management request capacity reached".to_owned();
    match request {
        Request::PackageOperation(request) => reporter.send(
            Some(id.to_owned()),
            report(Report::PackageOperationResult(PackageOperationResult {
                operation_id: request.operation_id,
                success: false,
                error,
            })),
        ),
        Request::CatalogSync(request) => reporter.send(
            Some(id.to_owned()),
            report(Report::CatalogSyncResult(CatalogSyncResult {
                revision: request.revision,
                ok: false,
                error,
            })),
        ),
        Request::SyncInventory(_) | Request::DiscoverUnigetuiInstances(_) => {}
    }
}

fn request_permit() -> Option<SemaphorePermit<'static>> {
    static REQUEST_PERMITS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_REQUESTS);
    REQUEST_PERMITS.try_acquire().ok()
}

fn report(report: Report) -> DeviceManagementReport {
    DeviceManagementReport { report: Some(report) }
}

/// Sends the inventory in parts that each fit in one channel envelope.
async fn send_inventory(reporter: &Reporter, correlation_id: &str, target_user_sid: &str) {
    let Some(inventory) = collect_inventory(target_user_sid).await else {
        return;
    };

    let parts = match inventory_parts(inventory, target_user_sid) {
        Ok(parts) => parts,
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "Failed to paginate UniGetUI inventory; skipping the inventory report"
            );
            return;
        }
    };
    for part in parts {
        reporter.send(Some(correlation_id.to_owned()), report(Report::Inventory(part)));
    }
}

async fn send_instances(reporter: &Reporter, correlation_id: &str) {
    match unigetui::instances().await {
        Ok(instances) => reporter.send(
            Some(correlation_id.to_owned()),
            report(Report::UnigetuiInstances(UniGetUiInstances { instances })),
        ),
        Err(error) => warn!(error = format!("{error:#}"), "Failed to discover UniGetUI instances"),
    }
}

fn inventory_parts(inventory: Inventory, target_user_sid: &str) -> anyhow::Result<Vec<InventoryReport>> {
    let report_id = Uuid::new_v4().to_string();
    let mut parts = Vec::new();
    let mut current = InventoryReport {
        report_id: report_id.clone(),
        last: false,
        packages: Vec::new(),
        managers: inventory.managers,
        sources: inventory.sources,
        target_user_sid: target_user_sid.to_owned(),
    };

    if MAX_INVENTORY_PART_BYTES < current.encoded_len() {
        anyhow::bail!("inventory metadata exceeds the channel payload limit");
    }

    for package in inventory.packages {
        // A field costs its encoded length plus a tag and a length prefix of at most 4 bytes.
        let package_len = package.encoded_len() + 4;
        if MAX_INVENTORY_PART_BYTES < package_len {
            anyhow::bail!("package exceeds the inventory part size limit");
        }
        if MAX_INVENTORY_PART_BYTES < current.encoded_len() + package_len {
            let next = InventoryReport {
                report_id: report_id.clone(),
                last: false,
                packages: Vec::new(),
                managers: Vec::new(),
                sources: Vec::new(),
                target_user_sid: target_user_sid.to_owned(),
            };
            parts.push(std::mem::replace(&mut current, next));
        }
        current.packages.push(package);
    }

    current.last = true;
    parts.push(current);
    Ok(parts)
}

struct Inventory {
    packages: Vec<InstalledPackage>,
    managers: Vec<PackageManager>,
    sources: Vec<PackageSource>,
}

/// Returns `None` when UniGetUI cannot be reached or its managers are not loaded yet,
/// so Devolutions Server keeps the last known inventory.
async fn collect_inventory(target_user_sid: &str) -> Option<Inventory> {
    let instance = match unigetui::resolve_target(target_user_sid).await {
        Ok(instance) => instance,
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "Failed to resolve UniGetUI target; skipping the inventory report"
            );
            return None;
        }
    };

    let (managers, managers_loading) = match unigetui::managers(&instance).await {
        Ok(managers) => managers,
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "Failed to collect UniGetUI package managers; skipping the inventory report"
            );
            return None;
        }
    };

    if managers_loading {
        warn!("UniGetUI package managers are still loading; skipping the inventory report");
        return None;
    }

    // UniGetUI returns an empty list for a manager that is not ready, for example just after logon or wake.
    if !managers.iter().any(|manager| manager.enabled && manager.installed) {
        warn!("No UniGetUI package manager is ready; skipping the inventory report");
        return None;
    }

    let packages = match unigetui::installed_packages(&instance).await {
        Ok(packages) => {
            info!(count = packages.len(), "Collected UniGetUI inventory");
            packages
        }
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "Failed to collect UniGetUI inventory; skipping the inventory report"
            );
            return None;
        }
    };

    let sources = match unigetui::sources(&instance).await {
        Ok(sources) => sources,
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "Failed to collect UniGetUI package sources; skipping the inventory report"
            );
            return None;
        }
    };

    Some(Inventory {
        packages,
        managers,
        sources,
    })
}

fn run_package_operation(request: PackageOperationRequest) -> PackageOperationResult {
    let operation_id = request.operation_id;
    let error = "authorized UniGetUI broker routing is not available in this build".to_owned();
    warn!(%operation_id, %error, "Package operation rejected");
    PackageOperationResult {
        operation_id,
        success: false,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_inventory_page_carries_the_target_user_sid() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let inventory = Inventory {
            packages: (0..500)
                .map(|index| InstalledPackage {
                    manager: "winget".to_owned(),
                    source: "winget".to_owned(),
                    id: format!("package-{index}"),
                    name: "n".repeat(128),
                    version: "1.0".to_owned(),
                    available_version: String::new(),
                    scope: String::new(),
                })
                .collect(),
            managers: Vec::new(),
            sources: Vec::new(),
        };
        let target_user_sid = "S-1-5-21-200";

        let pages = inventory_parts(inventory, target_user_sid).expect("inventory fits in pages");

        assert!(pages.len() > 1);
        assert!(pages.iter().all(|page| page.target_user_sid == target_user_sid));
    }

    #[test]
    fn oversized_package_prevents_an_incomplete_inventory_report() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §inventory
        let inventory = Inventory {
            packages: vec![InstalledPackage {
                manager: "winget".to_owned(),
                source: "winget".to_owned(),
                id: "oversized".to_owned(),
                name: "n".repeat(MAX_INVENTORY_PART_BYTES),
                version: "1.0".to_owned(),
                available_version: String::new(),
                scope: String::new(),
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
