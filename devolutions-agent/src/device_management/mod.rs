//! Device management prototype.
//!
//! The agent enrolls the machine in Devolutions Server with an unauthenticated gRPC call (prototype
//! only, no security), then keeps a bidirectional gRPC stream open. Devolutions Server asks for an inventory sync on this stream, and
//! the agent reads the installed packages from the local UniGetUI IPC API. DVLS also sends package operations (install,
//! update, uninstall) on this stream. The agent runs them through UniGetUI, then sends the result and a new inventory.

mod unigetui;

use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use backoff::backoff::Backoff as _;
use devolutions_agent_shared::get_data_dir;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::transport::Endpoint;
use uuid::Uuid;

use crate::config::{ConfHandle, DeviceManagementConf};

#[allow(unused_qualifications, clippy::clone_on_ref_ptr, clippy::similar_names)]
pub mod protocol {
    tonic::include_proto!("devolutions.device_management.v1");
}

use protocol::agent_message::Payload as AgentPayload;
use protocol::device_management_client::DeviceManagementClient;
use protocol::server_message::Payload as ServerPayload;
use protocol::{
    AgentMessage, EnrollRequest, Hello, InstalledPackage, InventoryReport, PackageOperationRequest,
    PackageOperationResult, PackageOperationType,
};

const DEVICE_ID_FILE_NAME: &str = "device_management_id";

pub struct DeviceManagementTask {
    conf_handle: ConfHandle,
}

impl DeviceManagementTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for DeviceManagementTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "device management";

    async fn run(self, shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        let conf = self
            .conf_handle
            .get_conf()
            .device_management
            .clone()
            .context("device management task started but device management is disabled")?;
        let agent = DeviceManagementAgent::new(conf)?;
        agent.run(shutdown_signal).await
    }
}

struct DeviceManagementAgent {
    conf: DeviceManagementConf,
    device_id: String,
    machine_name: String,
}

impl DeviceManagementAgent {
    fn new(conf: DeviceManagementConf) -> anyhow::Result<Self> {
        Ok(Self {
            conf,
            device_id: load_or_create_device_id()?,
            machine_name: machine_name(),
        })
    }

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
        const RETRY_MAX_INTERVAL: Duration = Duration::from_secs(60);
        const CONNECTED_THRESHOLD: Duration = Duration::from_secs(30);

        let mut backoff = backoff::ExponentialBackoffBuilder::default()
            .with_initial_interval(RETRY_INITIAL_INTERVAL)
            .with_max_interval(RETRY_MAX_INTERVAL)
            .with_multiplier(2.0)
            .with_max_elapsed_time(None)
            .build();

        loop {
            let start = Instant::now();

            match self.run_single_session(&mut shutdown_signal).await {
                Ok(()) => return Ok(()),
                Err(error) => warn!(
                    url = %self.conf.grpc_url,
                    error = format!("{error:#}"),
                    "Device management session failed"
                ),
            }

            if start.elapsed() > CONNECTED_THRESHOLD {
                backoff.reset();
            }

            let wait = backoff.next_backoff().unwrap_or(RETRY_INITIAL_INTERVAL);
            info!(?wait, "Reconnecting device management after backoff");

            tokio::select! {
                _ = shutdown_signal.wait() => return Ok(()),
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Enrolls the device, then serves the gRPC stream until it closes.
    async fn run_single_session(&self, shutdown_signal: &mut ShutdownSignal) -> anyhow::Result<()> {
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
        const CALL_TIMEOUT: Duration = Duration::from_secs(30);
        // A half-open connection does not fail by itself. Without pings, the stream read waits forever.
        const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
        const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

        let grpc_url = self.conf.grpc_url.to_string();
        let channel = Endpoint::from_shared(grpc_url.clone())?
            .connect_timeout(CONNECT_TIMEOUT)
            .tcp_keepalive(Some(KEEP_ALIVE_INTERVAL))
            .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .connect()
            .await
            .with_context(|| format!("failed to connect device management gRPC endpoint at {grpc_url}"))?;
        let mut client = DeviceManagementClient::new(channel);

        tokio::time::timeout(
            CALL_TIMEOUT,
            client.enroll(EnrollRequest {
                device_id: self.device_id.clone(),
                machine_name: self.machine_name.clone(),
                operating_system: operating_system(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            }),
        )
        .await
        .context("enroll timed out")?
        .context("enroll rejected")?;
        info!(device_id = %self.device_id, "Device enrolled in Devolutions Server");

        let (outgoing_tx, outgoing_rx) = mpsc::channel(16);
        outgoing_tx
            .send(AgentMessage {
                payload: Some(AgentPayload::Hello(self.hello())),
            })
            .await
            .context("failed to queue hello")?;

        let mut response_stream = tokio::time::timeout(
            CALL_TIMEOUT,
            client.connect(Request::new(ReceiverStream::new(outgoing_rx))),
        )
        .await
        .context("opening the device management stream timed out")?
        .context("failed to open device management stream")?
        .into_inner();

        info!(device_id = %self.device_id, url = %grpc_url, "Device management stream connected");

        loop {
            tokio::select! {
                _ = shutdown_signal.wait() => return Ok(()),
                message = response_stream.message() => {
                    let Some(message) = message.context("failed to read device management message")? else {
                        bail!("Devolutions Server closed the device management stream");
                    };

                    match message.payload {
                        Some(ServerPayload::SyncInventory(_)) => {
                            if let Some(report) = collect_inventory().await {
                                outgoing_tx
                                    .send(AgentMessage { payload: Some(AgentPayload::Inventory(report)) })
                                    .await
                                    .context("failed to queue inventory report")?;
                            }
                        }
                        Some(ServerPayload::PackageOperation(request)) => {
                            // An installer can run for minutes. Do not block the stream while it runs.
                            let outgoing_tx = outgoing_tx.clone();
                            tokio::spawn(async move {
                                let expected = ExpectedPackageState::from_request(&request);
                                let result = run_package_operation(request).await;
                                let succeeded = result.success;
                                if outgoing_tx
                                    .send(AgentMessage { payload: Some(AgentPayload::OperationResult(result)) })
                                    .await
                                    .is_err()
                                {
                                    debug!("Device management stream closed before the operation result was sent");
                                    return;
                                }

                                // The inventory report updates the package list of the machine in DVLS.
                                if succeeded {
                                    if let Some(expected) = &expected {
                                        wait_for_package_state(expected).await;
                                    }
                                }
                                let Some(report) = collect_inventory().await else {
                                    return;
                                };
                                if outgoing_tx
                                    .send(AgentMessage { payload: Some(AgentPayload::Inventory(report)) })
                                    .await
                                    .is_err()
                                {
                                    debug!("Device management stream closed before the inventory report was sent");
                                }
                            });
                        }
                        None => {}
                    }
                }
            }
        }
    }

    fn hello(&self) -> Hello {
        Hello {
            device_id: self.device_id.clone(),
        }
    }
}

const PACKAGE_STATE_POLL_INTERVAL: Duration = Duration::from_secs(3);
const PACKAGE_STATE_MAX_ATTEMPTS: u32 = 10;

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
            Err(error) => warn!(error = format!("{error:#}"), "Failed to read UniGetUI installed packages"),
        }

        tokio::time::sleep(PACKAGE_STATE_POLL_INTERVAL).await;
    }

    warn!(
        package_id = %expected.package_id,
        "UniGetUI installed list does not show the operation result; sending the inventory anyway"
    );
}

/// Returns `None` when UniGetUI cannot be reached or its managers are not loaded yet,
/// so Devolutions Server keeps the last known inventory.
async fn collect_inventory() -> Option<InventoryReport> {
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

    Some(InventoryReport {
        packages,
        managers,
        sources,
    })
}

async fn run_package_operation(request: PackageOperationRequest) -> PackageOperationResult {
    let operation = match PackageOperationType::try_from(request.r#type) {
        Ok(PackageOperationType::Install) => unigetui::PackageOperation::Install,
        // `winget upgrade` ignores the version and cannot downgrade. `install --version --force` can.
        Ok(PackageOperationType::Update) if !request.version.is_empty() => unigetui::PackageOperation::Install,
        Ok(PackageOperationType::Update) => unigetui::PackageOperation::Update,
        Ok(PackageOperationType::Uninstall) => unigetui::PackageOperation::Uninstall,
        Err(_) => {
            return PackageOperationResult {
                operation_id: request.operation_id,
                success: false,
                error: format!("Unknown package operation type {}.", request.r#type),
            };
        }
    };

    let started = Instant::now();
    info!(
        operation_id = %request.operation_id,
        ?operation,
        manager = %request.manager,
        package_id = %request.package_id,
        version = %request.version,
        "UniGetUI package operation started"
    );

    let result = unigetui::package_operation(
        operation,
        &request.manager,
        &request.source,
        &request.package_id,
        &request.version,
    )
    .await;

    match result {
        Ok(()) => {
            info!(
                operation_id = %request.operation_id,
                elapsed_ms = started.elapsed().as_millis(),
                "UniGetUI package operation succeeded"
            );
            PackageOperationResult {
                operation_id: request.operation_id,
                success: true,
                error: String::new(),
            }
        }
        Err(error) => {
            let error = format!("{error:#}");
            warn!(
                operation_id = %request.operation_id,
                elapsed_ms = started.elapsed().as_millis(),
                %error,
                "UniGetUI package operation failed"
            );
            PackageOperationResult {
                operation_id: request.operation_id,
                success: false,
                error,
            }
        }
    }
}

fn load_or_create_device_id() -> anyhow::Result<String> {
    let path = get_data_dir().join(DEVICE_ID_FILE_NAME);

    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim();
        if Uuid::parse_str(existing).is_ok() {
            return Ok(existing.to_owned());
        }
    }

    let device_id = Uuid::new_v4().to_string();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("failed to create {parent}"))?;
    }
    std::fs::write(&path, &device_id).with_context(|| format!("failed to write {path}"))?;
    Ok(device_id)
}

fn machine_name() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn operating_system() -> String {
    format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH)
}
