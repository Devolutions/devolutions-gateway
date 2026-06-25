mod process;

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use backoff::backoff::Backoff as _;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::transport::Endpoint;
use uuid::Uuid;

use crate::config::{ConfHandle, dto};
use crate::psu_grpc_agent::process::{ProcessControl, ProcessRegistry};

#[allow(unused_qualifications)]
pub mod protocol {
    tonic::include_proto!("devolutions.psu.agent.poc.v1");
}

use protocol::agent_control_client::AgentControlClient;
use protocol::agent_message::Payload as AgentPayload;
use protocol::server_message::Payload as ServerPayload;
use protocol::{
    AgentCapability, AgentDiagnostic, AgentMessage, PowerShellRuntime, RegisterAgent, StreamClosed, StreamData,
};

const PROTOCOL_VERSION: &str = "poc.v1";
const CAPABILITY_JOB_EXECUTION: &str = "job_execution";
const CAPABILITY_PSREMOTING_TUNNEL: &str = "psremoting_grpc_tunnel";

pub struct PsuGrpcAgentTask {
    conf_handle: ConfHandle,
}

impl PsuGrpcAgentTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for PsuGrpcAgentTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "psu grpc agent";

    async fn run(self, shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        let conf = self.conf_handle.get_conf().psu_grpc_agent.clone();
        let agent = PsuGrpcAgent::new(conf).context("failed to initialize PSU gRPC agent")?;
        agent.run(shutdown_signal).await
    }
}

#[derive(Debug, Clone)]
struct PsuGrpcAgent {
    conf: dto::PsuGrpcAgentConf,
    server_url: String,
    agent_id: String,
    display_name: String,
    machine_name: String,
    powershell_executable: String,
}

impl PsuGrpcAgent {
    fn new(conf: dto::PsuGrpcAgentConf) -> anyhow::Result<Self> {
        let server_url = conf
            .server_url
            .as_ref()
            .context("PsuGrpcAgent is enabled but ServerUrl is not configured")?
            .to_string();
        let machine_name = machine_name();
        let agent_id = conf.agent_id.clone().unwrap_or_else(|| machine_name.clone());
        let display_name = conf.display_name.clone().unwrap_or_else(|| agent_id.clone());
        let powershell_executable = resolve_powershell_executable(&conf.powershell)
            .to_string_lossy()
            .into_owned();

        Ok(Self {
            conf,
            server_url,
            agent_id,
            display_name,
            machine_name,
            powershell_executable,
        })
    }

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
        const RETRY_MAX_INTERVAL: Duration = Duration::from_secs(60);
        const RETRY_MULTIPLIER: f64 = 2.0;
        const CONNECTED_THRESHOLD: Duration = Duration::from_secs(30);

        let mut backoff = backoff::ExponentialBackoffBuilder::default()
            .with_initial_interval(RETRY_INITIAL_INTERVAL)
            .with_max_interval(RETRY_MAX_INTERVAL)
            .with_multiplier(RETRY_MULTIPLIER)
            .with_max_elapsed_time(None)
            .build();

        loop {
            let start = Instant::now();

            match self.run_single_connection(&mut shutdown_signal).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    warn!(url = %self.server_url, error = format!("{error:#}"), "PSU gRPC agent connection failed")
                }
            }

            if start.elapsed() > CONNECTED_THRESHOLD {
                backoff.reset();
            }

            let wait = match backoff.next_backoff() {
                Some(wait) => wait,
                None => {
                    warn!("PSU gRPC agent reconnect backoff exhausted, resetting");
                    backoff.reset();
                    RETRY_INITIAL_INTERVAL
                }
            };

            info!(?wait, "Reconnecting PSU gRPC agent after backoff");

            tokio::select! {
                _ = shutdown_signal.wait() => return Ok(()),
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    async fn run_single_connection(&self, shutdown_signal: &mut ShutdownSignal) -> anyhow::Result<()> {
        let endpoint = Endpoint::from_shared(self.server_url.clone())?;
        let channel = endpoint
            .connect()
            .await
            .with_context(|| format!("failed to connect PSU gRPC endpoint at {}", self.server_url))?;
        let mut client = AgentControlClient::new(channel);

        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let powershell_version = get_powershell_version(&self.powershell_executable).await;
        outgoing_tx
            .send(self.create_registration_message(powershell_version))
            .await
            .context("failed to queue PSU gRPC agent registration")?;

        let mut response_stream = client
            .connect(Request::new(ReceiverStream::new(outgoing_rx)))
            .await
            .context("failed to start PSU gRPC agent stream")?
            .into_inner();

        info!(agent_id = %self.agent_id, url = %self.server_url, "Connected PSU gRPC agent");

        let registry = ProcessRegistry::default();
        let mut process_tasks = JoinSet::new();
        let mut connection_id = String::new();

        loop {
            tokio::select! {
                _ = shutdown_signal.wait() => {
                    process_tasks.shutdown().await;
                    return Ok(());
                }
                message = response_stream.message() => {
                    let Some(message) = message.context("failed to read PSU gRPC server message")? else {
                        bail!("PSU gRPC server closed the agent stream");
                    };

                    if !message.connection_id.trim().is_empty() {
                        connection_id.clone_from(&message.connection_id);
                    }

                    self.handle_server_message(
                        message,
                        &outgoing_tx,
                        &registry,
                        &mut process_tasks,
                        &mut connection_id,
                    ).await?;
                }
                Some(result) = process_tasks.join_next(), if !process_tasks.is_empty() => {
                    match result {
                        Ok(Ok(())) => trace!("PSU gRPC child process task completed"),
                        Ok(Err(error)) => warn!(error = format!("{error:#}"), "PSU gRPC child process task failed"),
                        Err(error) => warn!(%error, "PSU gRPC child process task panicked"),
                    }
                }
            }
        }
    }

    async fn handle_server_message(
        &self,
        message: protocol::ServerMessage,
        outgoing_tx: &mpsc::Sender<AgentMessage>,
        registry: &ProcessRegistry,
        process_tasks: &mut JoinSet<anyhow::Result<()>>,
        connection_id: &mut String,
    ) -> anyhow::Result<()> {
        match message.payload {
            Some(ServerPayload::RegisterAccepted(accepted)) => {
                connection_id.clone_from(&accepted.connection_id);
                info!(connection_id = %accepted.connection_id, "PSU gRPC agent registration accepted");
            }
            Some(ServerPayload::StartProcess(start_process)) => {
                let incoming_rx = registry.register_stream(&start_process.stream_id).await;
                let (control_tx, control_rx) = oneshot::channel();
                registry
                    .register_process(
                        start_process.correlation_id.clone(),
                        ProcessControl { stop: control_tx },
                    )
                    .await;

                let agent_id = self.agent_id.clone();
                let connection_id = connection_id.clone();
                let default_executable = self.powershell_executable.clone();
                let outgoing_tx = outgoing_tx.clone();
                let registry = registry.clone();

                process_tasks.spawn(async move {
                    process::run_process(
                        start_process,
                        incoming_rx,
                        control_rx,
                        outgoing_tx,
                        registry,
                        agent_id,
                        connection_id,
                        default_executable,
                    )
                    .await
                });
            }
            Some(ServerPayload::StreamData(stream_data)) => registry.dispatch_stream_data(stream_data).await,
            Some(ServerPayload::StreamClosed(stream_closed)) => registry.close_stream(&stream_closed.stream_id).await,
            Some(ServerPayload::StopProcess(stop_process)) => {
                registry
                    .stop_process(&stop_process.correlation_id, stop_process.kill_process)
                    .await;
            }
            Some(ServerPayload::Heartbeat(_)) | None => {}
        }

        Ok(())
    }

    fn create_registration_message(&self, powershell_version: String) -> AgentMessage {
        AgentMessage {
            request_id: Uuid::new_v4().simple().to_string(),
            agent_id: self.agent_id.clone(),
            connection_id: String::new(),
            timestamp: Some(timestamp_now()),
            payload: Some(AgentPayload::RegisterAgent(RegisterAgent {
                agent_id: self.agent_id.clone(),
                instance_id: Uuid::new_v4().simple().to_string(),
                display_name: self.display_name.clone(),
                machine_name: self.machine_name.clone(),
                os: std::env::consts::OS.to_owned(),
                architecture: std::env::consts::ARCH.to_owned(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION.to_owned(),
                hubs: self.conf.hubs.clone(),
                capabilities: vec![
                    AgentCapability {
                        name: CAPABILITY_JOB_EXECUTION.to_owned(),
                        version: PROTOCOL_VERSION.to_owned(),
                    },
                    AgentCapability {
                        name: CAPABILITY_PSREMOTING_TUNNEL.to_owned(),
                        version: PROTOCOL_VERSION.to_owned(),
                    },
                ],
                powershell_runtimes: vec![PowerShellRuntime {
                    runtime_id: "pwsh-default".to_owned(),
                    kind: "pwsh".to_owned(),
                    version: powershell_version,
                    executable_path: self.powershell_executable.clone(),
                }],
            })),
        }
    }
}

pub(crate) fn agent_message(agent_id: &str, connection_id: &str, payload: AgentPayload) -> AgentMessage {
    AgentMessage {
        request_id: Uuid::new_v4().simple().to_string(),
        agent_id: agent_id.to_owned(),
        connection_id: connection_id.to_owned(),
        timestamp: Some(timestamp_now()),
        payload: Some(payload),
    }
}

pub(crate) fn stream_data(stream_id: String, sequence: u64, data: Vec<u8>, end_of_stream: bool) -> StreamData {
    StreamData {
        stream_id,
        sequence,
        data,
        end_of_stream,
    }
}

pub(crate) fn stream_closed(stream_id: String, reason: String, error: bool) -> StreamClosed {
    StreamClosed {
        stream_id,
        reason,
        error,
    }
}

pub(crate) fn diagnostic(level: &str, message: String) -> AgentDiagnostic {
    AgentDiagnostic {
        level: level.to_owned(),
        message,
        properties: HashMap::new(),
    }
}

fn timestamp_now() -> prost_types::Timestamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    prost_types::Timestamp {
        seconds: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(now.subsec_nanos()).unwrap_or(0),
    }
}

fn machine_name() -> String {
    hostname::get()
        .ok()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "devolutions-agent".to_owned())
}

fn resolve_powershell_executable(conf: &dto::PsuPowerShellConf) -> std::ffi::OsString {
    if let Some(path) = &conf.executable_path {
        return path.as_str().into();
    }

    if let Some(selector) = &conf.version_selector {
        if selector.eq_ignore_ascii_case("pwsh")
            || selector.eq_ignore_ascii_case("pwsh-preview")
            || selector.eq_ignore_ascii_case("pwsh-lts")
            || selector.starts_with("pwsh-")
        {
            return selector.into();
        }

        return format!("pwsh-{selector}").into();
    }

    if conf.use_windows_power_shell {
        "powershell.exe".into()
    } else {
        "pwsh".into()
    }
}

async fn get_powershell_version(executable: &str) -> String {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(executable)
            .arg("-NoLogo")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("$PSVersionTable.PSVersion.ToString()")
            .output(),
    )
    .await;

    match output {
        Ok(Ok(output)) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if version.is_empty() {
                "unknown".to_owned()
            } else {
                version
            }
        }
        _ => "unknown".to_owned(),
    }
}
