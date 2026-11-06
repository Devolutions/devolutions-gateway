//! Device management prototype.
//!
//! The agent keeps a bidirectional gRPC stream open to Devolutions Server, on the Agent Identity channel URL. It
//! authenticates the stream with its Agent Identity: the opening request is signed with the identity key, and the first
//! message answers the server challenge with a proof (same handshake as the Agent Identity channel). Devolutions Server
//! asks for an inventory sync on this stream, and the agent reads the installed packages from the local UniGetUI IPC
//! API. DVLS also sends package operations (install, update, uninstall) on this stream. The agent runs them through
//! UniGetUI, then sends the result and a new inventory.

mod unigetui;

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_identity::schedule::{self, ChannelUrl};
use agent_identity::state::{IDENTITY_KEY_PREFIX, Store};
use agent_identity::{client, metadata};
use agent_identity_httpsig::{ChannelLayer, OpeningNonce, RequestSigner};
use anyhow::{Context as _, anyhow, bail};
use async_trait::async_trait;
use backoff::backoff::Backoff as _;
use device_key::{DeviceKey, KeyBackend};
use devolutions_agent_shared::get_data_dir;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tower::Layer as _;
use url::Url;
use uuid::Uuid;

use crate::config::{Conf, ConfHandle};
use crate::identity::config::IdentityKeyBackend;

#[allow(unused_qualifications, clippy::clone_on_ref_ptr, clippy::similar_names)]
pub mod protocol {
    tonic::include_proto!("devolutions.device_management.v1");
}

use protocol::agent_message::Payload as AgentPayload;
use protocol::device_management_client::DeviceManagementClient;
use protocol::server_message::Payload as ServerPayload;
use protocol::{
    AgentMessage, Hello, InstalledPackage, InventoryReport, PackageOperationRequest, PackageOperationResult,
    PackageOperationType,
};

const CHANNEL_PROOF_DOMAIN: &[u8] = b"devolutions-agent-identity/v1/channel-proof";

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
        let conf = self.conf_handle.get_conf();
        if conf.device_management.is_none() {
            bail!("device management task started but device management is disabled");
        }
        DeviceManagementAgent { conf }.run(shutdown_signal).await
    }
}

/// The enrolled Agent Identity that authenticates one device management session.
struct SessionIdentity {
    identity_id: Uuid,
    url: Url,
    key: Arc<dyn DeviceKey>,
    leaf_certificate_der: Vec<u8>,
}

struct DeviceManagementAgent {
    conf: Arc<Conf>,
}

impl DeviceManagementAgent {
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
                Err(error) => warn!(error = format!("{error:#}"), "Device management session failed"),
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

    /// Reads the first usable Agent Identity from the store. The identity task owns enrollment and renewal.
    fn session_identity(&self) -> anyhow::Result<SessionIdentity> {
        let settings = self.conf.debug.identity.clone().unwrap_or_default();
        let data_dir = get_data_dir();
        let backend = match self.conf.identity.key_backend {
            IdentityKeyBackend::File => Store::file_backend(&data_dir),
            IdentityKeyBackend::WindowsSoftwareProvider => KeyBackend::WindowsSoftwareProvider,
        };
        let store = Store::new(
            data_dir,
            backend,
            settings
                .key_name_prefix
                .clone()
                .unwrap_or_else(|| IDENTITY_KEY_PREFIX.to_owned()),
            settings.acl_grant_current_user.unwrap_or_default(),
        )
        .context("open Agent Identity store")?;

        for identity in store.list_identities().context("list Agent Identities")? {
            if identity.rejected.is_some() {
                continue;
            }
            let ChannelUrl::Usable(url) = schedule::channel_url(&identity.config) else {
                continue;
            };
            let current = &identity.keys.current;
            let chain = current
                .certificate_chain
                .as_deref()
                .context("identity key has no certificate chain")?;
            let key = device_key::open(store.key_backend(), &current.key_name)?
                .context("Agent Identity key is missing")?;
            return Ok(SessionIdentity {
                identity_id: identity.identity_id,
                url,
                key: Arc::from(key),
                leaf_certificate_der: client::leaf_certificate_der(chain)?,
            });
        }

        bail!("waiting for an enrolled Agent Identity with a channel URL")
    }

    /// Opens the authenticated stream, then serves it until it closes.
    async fn run_single_session(&self, shutdown_signal: &mut ShutdownSignal) -> anyhow::Result<()> {
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
        const CALL_TIMEOUT: Duration = Duration::from_secs(30);
        // A half-open connection does not fail by itself. Without pings, the stream read waits forever.
        const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
        const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

        let identity = self.session_identity()?;
        let settings = self.conf.debug.identity.clone().unwrap_or_default();

        let host = identity.url.host_str().context("channel URL without host")?;
        let port = identity.url.port_or_known_default().context("channel URL without port")?;
        let origin = format!("https://{host}:{port}");

        let mut tls = ClientTlsConfig::new().with_native_roots();
        if let Some(path) = &settings.extra_trusted_root {
            let pem = std::fs::read(path).with_context(|| format!("failed to read {path}"))?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }

        let channel = Endpoint::from_shared(origin.clone())?
            .tls_config(tls)?
            .connect_timeout(CONNECT_TIMEOUT)
            .tcp_keepalive(Some(KEEP_ALIVE_INTERVAL))
            .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .connect()
            .await
            .with_context(|| format!("failed to connect device management endpoint at {origin}"))?;
        let signer = RequestSigner::new(Arc::clone(&identity.key), &identity.leaf_certificate_der);
        let mut client = DeviceManagementClient::new(ChannelLayer::new(signer, &identity.url).layer(channel));

        let (outgoing_tx, outgoing_rx) = mpsc::channel(16);
        let (handoff, nonce_rx) = OpeningNonce::new();
        let mut request = Request::new(ReceiverStream::new(outgoing_rx));
        request.extensions_mut().insert(handoff);

        let (mut response_stream, challenge) = tokio::time::timeout(CALL_TIMEOUT, async {
            let mut response_stream = client
                .connect(request)
                .await
                .context("failed to open device management stream")?
                .into_inner();
            loop {
                let message = response_stream
                    .message()
                    .await
                    .context("failed to read device management challenge")?
                    .context("Devolutions Server closed the stream before the challenge")?;
                if let Some(ServerPayload::Challenge(challenge)) = message.payload {
                    return anyhow::Ok((response_stream, challenge));
                }
            }
        })
        .await
        .context("opening the device management stream timed out")??;
        let nonce = nonce_rx.await.context("opening signed without a nonce")?;

        let proof = identity
            .key
            .try_sign(&channel_proof_input(&challenge.challenge, &nonce))
            .map_err(|error| anyhow!("sign channel proof: {error}"))?;
        let hello = Hello {
            correlation_id: challenge.challenge_id,
            proof: proof.to_bytes().to_vec(),
            metadata: metadata::collect(env!("CARGO_PKG_VERSION"), settings.metadata_override_path.as_deref())
                .into_iter()
                .collect(),
        };
        outgoing_tx
            .send(AgentMessage {
                payload: Some(AgentPayload::Hello(hello)),
            })
            .await
            .context("failed to queue hello")?;

        info!(identity_id = %identity.identity_id, url = %identity.url, "Device management stream connected");

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
                        Some(ServerPayload::Challenge(_)) | None => {}
                    }
                }
            }
        }
    }
}

/// Returns the bytes that the channel proof signs: the domain, a separator, the challenge and the signed opening nonce.
fn channel_proof_input(challenge: &[u8], connect_nonce: &str) -> Vec<u8> {
    let mut input = Vec::with_capacity(CHANNEL_PROOF_DOMAIN.len() + 1 + challenge.len() + connect_nonce.len());
    input.extend_from_slice(CHANNEL_PROOF_DOMAIN);
    input.push(0x00);
    input.extend_from_slice(challenge);
    input.extend_from_slice(connect_nonce.as_bytes());
    input
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
