//! Device management prototype.
//!
//! Devolutions Server sends device management requests on the Agent Identity channel to an agent whose Hello lists
//! the [`CAPABILITY`] capability. The agent reads the inventory (installed packages, managers and sources) from the
//! local UniGetUI IPC API, which runs in the user session and needs no elevation. It runs package operations (install,
//! update, uninstall) through the package broker, then sends the result and a new inventory. Each report answers the
//! request message that caused it.

mod software_catalog;
mod unigetui;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use agent_channel_client::Reporter;
use agent_channel_proto::{
    CatalogSyncResult, DeviceManagementReport, DeviceManagementRequest, InstalledPackage, InventoryReport,
    PackageManager, PackageOperationRequest, PackageOperationResult, PackageOperationType, PackageSource,
    device_management_report::Report, device_management_request::Request,
};
use prost::Message as _;
use uuid::Uuid;

/// The Hello capability that tells Devolutions Server that this agent handles device management requests.
pub const CAPABILITY: &str = "device_management";

/// Largest encoded inventory part. The channel rejects an envelope over 64 KiB.
const MAX_INVENTORY_PART_BYTES: usize = 60_000;

const PACKAGE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(3);
const PACKAGE_STATE_MAX_ATTEMPTS: u32 = 10;

/// Serves one device management request, answering the request message `id` through `reporter`.
pub(crate) fn handle(identity_id: Uuid, id: String, request: DeviceManagementRequest, reporter: Reporter) {
    let Some(request) = request.request else {
        debug!(%id, "Device management request without content");
        return;
    };

    // An installer can run for minutes. Do not block the channel while it runs.
    tokio::spawn(async move {
        match request {
            Request::SyncInventory(_) => send_inventory(&reporter, &id).await,
            Request::PackageOperation(request) => {
                let expected = ExpectedPackageState::from_request(&request);
                let result = run_package_operation(request).await;
                let succeeded = result.success;
                reporter.send(Some(id.clone()), report(Report::PackageOperationResult(result)));

                if succeeded && let Some(expected) = &expected {
                    wait_for_package_state(expected).await;
                }
                send_inventory(&reporter, &id).await;
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
    });
}

fn report(report: Report) -> DeviceManagementReport {
    DeviceManagementReport { report: Some(report) }
}

/// Sends the inventory in parts that each fit in one channel envelope.
async fn send_inventory(reporter: &Reporter, correlation_id: &str) {
    let Some(inventory) = collect_inventory().await else {
        return;
    };

    for part in inventory_parts(inventory) {
        reporter.send(Some(correlation_id.to_owned()), report(Report::Inventory(part)));
    }
}

fn inventory_parts(inventory: Inventory) -> Vec<InventoryReport> {
    let report_id = Uuid::new_v4().to_string();
    let mut parts = Vec::new();
    let mut current = InventoryReport {
        report_id: report_id.clone(),
        last: false,
        packages: Vec::new(),
        managers: inventory.managers,
        sources: inventory.sources,
    };

    for package in inventory.packages {
        // A field costs its encoded length plus a tag and a length prefix of at most 4 bytes.
        let package_len = package.encoded_len() + 4;
        if package_len > MAX_INVENTORY_PART_BYTES {
            warn!(package_id = %package.id, "Package is too large for an inventory report; skipping it");
            continue;
        }
        if current.encoded_len() + package_len > MAX_INVENTORY_PART_BYTES {
            let next = InventoryReport {
                report_id: report_id.clone(),
                last: false,
                packages: Vec::new(),
                managers: Vec::new(),
                sources: Vec::new(),
            };
            parts.push(std::mem::replace(&mut current, next));
        }
        current.packages.push(package);
    }

    current.last = true;
    parts.push(current);
    parts
}

/// The package state that the installed list must show after a successful operation.
struct ExpectedPackageState {
    manager: String,
    package_id: String,
    version: String,
    is_installed: bool,
}

impl ExpectedPackageState {
    fn from_request(request: &PackageOperationRequest) -> Option<Self> {
        let is_installed = match PackageOperationType::try_from(request.r#type).ok()? {
            PackageOperationType::Install | PackageOperationType::Update => true,
            PackageOperationType::Uninstall => false,
        };

        Some(Self {
            manager: request.manager.clone(),
            package_id: request.package_id.clone(),
            version: request.version.clone(),
            is_installed,
        })
    }

    fn is_met(&self, packages: &[InstalledPackage]) -> bool {
        let package = packages
            .iter()
            .find(|package| package.manager.eq_ignore_ascii_case(&self.manager) && package.id == self.package_id);

        match package {
            Some(package) => self.is_installed && (self.version.is_empty() || package.version == self.version),
            None => !self.is_installed,
        }
    }
}

/// UniGetUI refreshes its installed list some seconds after an installer exits. During that time,
/// a reinstalled package can be missing or show its old version.
async fn wait_for_package_state(expected: &ExpectedPackageState) {
    for attempt in 1..=PACKAGE_STATE_MAX_ATTEMPTS {
        match unigetui::installed_packages().await {
            Ok(packages) if expected.is_met(&packages) => {
                debug!(attempt, package_id = %expected.package_id, "UniGetUI installed list shows the operation result");
                return;
            }
            Ok(_) => {}
            Err(error) => warn!(
                error = format!("{error:#}"),
                "Failed to read UniGetUI installed packages"
            ),
        }

        tokio::time::sleep(PACKAGE_STATE_POLL_INTERVAL).await;
    }

    warn!(
        package_id = %expected.package_id,
        "UniGetUI installed list does not show the operation result; sending the inventory anyway"
    );
}

struct Inventory {
    packages: Vec<InstalledPackage>,
    managers: Vec<PackageManager>,
    sources: Vec<PackageSource>,
}

/// Returns `None` when UniGetUI cannot be reached or its managers are not loaded yet,
/// so Devolutions Server keeps the last known inventory.
async fn collect_inventory() -> Option<Inventory> {
    let managers = match unigetui::managers().await {
        Ok(managers) => managers,
        Err(error) => {
            warn!(
                error = format!("{error:#}"),
                "Failed to collect UniGetUI package managers; skipping the inventory report"
            );
            return None;
        }
    };

    // UniGetUI returns an empty list for a manager that is not ready, for example just after logon or wake.
    if !managers.iter().any(|manager| manager.enabled && manager.installed) {
        warn!("No UniGetUI package manager is ready; skipping the inventory report");
        return None;
    }

    let packages = match unigetui::installed_packages().await {
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

    let sources = unigetui::sources().await.unwrap_or_else(|error| {
        warn!(
            error = format!("{error:#}"),
            "Failed to collect UniGetUI package sources"
        );
        Vec::new()
    });

    Some(Inventory {
        packages,
        managers,
        sources,
    })
}

async fn run_package_operation(request: PackageOperationRequest) -> PackageOperationResult {
    let operation_id = request.operation_id.clone();
    let started = Instant::now();
    info!(
        %operation_id,
        r#type = request.r#type,
        manager = %request.manager,
        package_id = %request.package_id,
        version = %request.version,
        "Package operation started"
    );

    match broker::run(request).await {
        Ok(()) => {
            info!(%operation_id, elapsed_ms = started.elapsed().as_millis(), "Package operation succeeded");
            PackageOperationResult {
                operation_id,
                success: true,
                error: String::new(),
            }
        }
        Err(error) => {
            let error = format!("{error:#}");
            warn!(%operation_id, elapsed_ms = started.elapsed().as_millis(), %error, "Package operation failed");
            PackageOperationResult {
                operation_id,
                success: false,
                error,
            }
        }
    }
}

#[cfg(windows)]
pub use self::broker::set_broker;

#[cfg(windows)]
mod broker {
    //! Runs package operations through the package broker of this process, as the user of the active session.

    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use agent_channel_proto::{PackageOperationRequest, PackageOperationType};
    use anyhow::{Context as _, bail};
    use now_package_broker::server::BrokerState;
    use now_policy_api as api;
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::token::Token;
    use win_api_wrappers::wts::{self, WTSConnectState};

    const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);
    /// winget exit code when an upgrade finds no newer version.
    const WINGET_UPDATE_NOT_APPLICABLE: i32 = 0x8A15_002Bu32.cast_signed();

    static BROKER: OnceLock<Arc<BrokerState>> = OnceLock::new();

    /// Gives device management the package broker of this process.
    pub fn set_broker(state: Arc<BrokerState>) {
        let _ = BROKER.set(state);
    }

    pub(super) async fn run(request: PackageOperationRequest) -> anyhow::Result<()> {
        let state = BROKER.get().context("the package broker is not running")?;

        if !request.manager.eq_ignore_ascii_case("winget") {
            bail!(
                "the package broker does not support the package manager \"{}\"; only winget is supported",
                request.manager
            );
        }

        let r#type = PackageOperationType::try_from(request.r#type)
            .ok()
            .with_context(|| format!("unknown package operation type {}", request.r#type))?;
        let operation = match r#type {
            PackageOperationType::Install => api::Operation::Install,
            // `winget upgrade` ignores the version and cannot downgrade. `install --version --force` can.
            PackageOperationType::Update if !request.version.is_empty() => api::Operation::Install,
            PackageOperationType::Update => api::Operation::Update,
            PackageOperationType::Uninstall => api::Operation::Uninstall,
        };

        let user_sid = tokio::task::spawn_blocking(active_user_sid)
            .await
            .context("user lookup worker failed")??;

        let version = (!request.version.is_empty())
            .then(|| api::VersionString::parse(&request.version))
            .transpose()
            .map_err(|error| anyhow::anyhow!("invalid package version: {error}"))?;

        let package_request = api::PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: api::API_VERSION_STR.into(),
            request_id: api::ResourceId::from(request.operation_id.as_str()),
            created_at: chrono::Utc::now(),
            operation,
            manager: api::ManagerName::Winget,
            source: api::RequestSource {
                name: if request.source.is_empty() {
                    "winget".to_owned()
                } else {
                    request.source.clone()
                },
                url: None,
            },
            package: api::RequestPackage {
                id: api::PackageIdentifier(request.package_id.clone()),
                version,
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
                transport: api::Transport::HttpNamedPipe,
                requested_elevation: api::Elevation::Elevated,
                effective_user: user_sid.to_string(),
                client_executable_path: std::env::current_exe()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                client_version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            include_command_preview: false,
            capture_output: false,
        };

        let response = state
            .execute(package_request, &user_sid)
            .await
            .map_err(|error| anyhow::anyhow!("the package broker rejected the request: {}", error.message))?;
        let Some(submission) = response.operation else {
            bail!(
                "the package broker policy denied the request: {}",
                response.decision.reason
            );
        };

        let operation_id = submission.operation_id.to_string();
        loop {
            let tracked = state
                .tracker
                .get(&operation_id)
                .context("the package broker lost the operation")?;
            if tracked.status.is_terminal() {
                return match tracked.status {
                    api::OperationStatus::Completed => Ok(()),
                    _ if r#type == PackageOperationType::Update
                        && tracked.exit_code == Some(WINGET_UPDATE_NOT_APPLICABLE) =>
                    {
                        info!(package_id = %request.package_id, "Package is already on the latest version");
                        Ok(())
                    }
                    status => bail!(
                        "the package operation ended with status {status:?}: {}",
                        tracked.note.unwrap_or_default()
                    ),
                };
            }
            tokio::time::sleep(STATUS_POLL_INTERVAL).await;
        }
    }

    /// Returns the user of the active interactive session. The broker runs the operation with the elevated token of
    /// this user.
    fn active_user_sid() -> anyhow::Result<Sid> {
        let session = wts::get_sessions()?
            .into_iter()
            .find(|session| session.state == WTSConnectState::Active && session.session_id != 0)
            .context("no active user session")?;
        let token = Token::for_session(session.session_id).context("open the token of the active session")?;
        Ok(token.sid_and_attributes()?.sid)
    }
}

#[cfg(not(windows))]
mod broker {
    use agent_channel_proto::PackageOperationRequest;

    pub(super) async fn run(_: PackageOperationRequest) -> anyhow::Result<()> {
        anyhow::bail!("package operations need the package broker, which runs only on Windows")
    }
}
