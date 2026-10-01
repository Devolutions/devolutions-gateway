mod process;

mod powershell;

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use backoff::backoff::Backoff as _;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt as _};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Streaming};
use url::Url;
use uuid::Uuid;

use crate::config::{ConfHandle, PsuConf, dto};
use crate::psu_agent::powershell::{PowerShellWorker, app_token_secret_reference_name};
use crate::psu_agent::process::{ProcessControl, ProcessRegistry};

#[allow(unused_qualifications, clippy::clone_on_ref_ptr, clippy::similar_names)]
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

pub struct PsuAgentTask {
    conf_handle: ConfHandle,
}

impl PsuAgentTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for PsuAgentTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "psu agent";

    async fn run(self, shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        let conf = self
            .conf_handle
            .get_conf()
            .psu_agent
            .clone()
            .context("PSU agent task started but the PSU agent is disabled")?;
        let agent = PsuAgent::new(conf).context("failed to initialize PSU agent")?;
        agent.run(shutdown_signal).await
    }
}

/// Timing parameters for the PSU gRPC connection and its reconnection policy.
#[derive(Debug, Clone, Copy)]
struct ConnectionSettings {
    /// Upper bound for resolving a `$secret:` AppToken through PowerShell.
    app_token_resolution_timeout: Duration,
    /// Upper bound for establishing the transport (TCP, TLS, and HTTP/2 handshakes).
    connect_timeout: Duration,
    /// Upper bound for the server to accept the agent stream once the transport is established.
    stream_start_timeout: Duration,
    /// Interval between TCP keepalive probes and HTTP/2 PING frames.
    keep_alive_interval: Duration,
    /// Time to wait for an HTTP/2 PING acknowledgement before closing the connection.
    keep_alive_timeout: Duration,
    retry_initial_interval: Duration,
    retry_max_interval: Duration,
    /// A connection that stayed up at least this long resets the reconnect backoff.
    stable_connection_threshold: Duration,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            app_token_resolution_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(15),
            stream_start_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(20),
            retry_initial_interval: Duration::from_secs(1),
            retry_max_interval: Duration::from_secs(60),
            stable_connection_threshold: Duration::from_secs(30),
        }
    }
}

/// An established agent stream.
struct PsuConnection {
    // Owned for the lifetime of the stream, matching the previous single-scope connection handling.
    _client: AgentControlClient<Channel>,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    response_stream: Streaming<protocol::ServerMessage>,
}

#[derive(Debug, Clone)]
struct PsuAgent {
    conf: PsuConf,
    settings: ConnectionSettings,
    server_url: String,
    agent_id: String,
    display_name: String,
    machine_name: String,
    powershell_executable: String,
}

impl PsuAgent {
    fn new(conf: PsuConf) -> anyhow::Result<Self> {
        let server_url = conf.server_url.to_string();
        let machine_name = machine_name();
        let agent_id = conf.agent_id.clone().unwrap_or_else(|| machine_name.clone());
        let display_name = conf.display_name.clone().unwrap_or_else(|| agent_id.clone());
        let powershell_executable = resolve_powershell_executable(&conf.powershell)
            .to_string_lossy()
            .into_owned();

        Ok(Self {
            conf,
            settings: ConnectionSettings::default(),
            server_url,
            agent_id,
            display_name,
            machine_name,
            powershell_executable,
        })
    }

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        const RETRY_MULTIPLIER: f64 = 2.0;

        if is_plaintext_to_remote_host(&self.conf.server_url) {
            warn!(
                url = %self.server_url,
                "PSU gRPC agent uses plaintext HTTP to a non-loopback host; the AppToken and job traffic are not encrypted"
            );
        }

        let mut backoff = backoff::ExponentialBackoffBuilder::default()
            .with_initial_interval(self.settings.retry_initial_interval)
            .with_max_interval(self.settings.retry_max_interval)
            .with_multiplier(RETRY_MULTIPLIER)
            .with_max_elapsed_time(None)
            .build();

        loop {
            // The connect phase may block on secret resolution, the network, or the server,
            // so it must not delay the service shutdown.
            let connection = tokio::select! {
                _ = shutdown_signal.wait() => return Ok(()),
                connection = self.connect() => connection,
            };

            match connection {
                Ok(connection) => {
                    let connected_at = Instant::now();

                    match self.serve(connection, &mut shutdown_signal).await {
                        Ok(()) => return Ok(()),
                        Err(error) => {
                            warn!(url = %self.server_url, error = format!("{error:#}"), "PSU gRPC agent connection lost")
                        }
                    }

                    if connected_at.elapsed() >= self.settings.stable_connection_threshold {
                        backoff.reset();
                    }
                }
                Err(error) => {
                    warn!(url = %self.server_url, error = format!("{error:#}"), "PSU gRPC agent connection failed")
                }
            }

            // The backoff has no maximum elapsed time, so it always yields a value.
            let wait = backoff.next_backoff().unwrap_or(self.settings.retry_max_interval);

            info!(?wait, "Reconnecting PSU gRPC agent after backoff");

            tokio::select! {
                _ = shutdown_signal.wait() => return Ok(()),
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    async fn connect(&self) -> anyhow::Result<PsuConnection> {
        // Resolved on every attempt so a secret vault that is not ready yet, or a rotated secret, is picked up.
        let app_token = self.resolve_app_token().await?;

        let endpoint = psu_endpoint(&self.server_url, &self.settings)?;
        let channel = tokio::time::timeout(self.settings.connect_timeout, endpoint.connect())
            .await
            .with_context(|| format!("timed out connecting PSU gRPC endpoint at {}", self.server_url))?
            .with_context(|| format!("failed to connect PSU gRPC endpoint at {}", self.server_url))?;
        let mut client = AgentControlClient::new(channel);

        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let powershell_version = get_powershell_version(&self.powershell_executable).await;
        outgoing_tx
            .send(self.create_registration_message(powershell_version))
            .await
            .context("failed to queue PSU gRPC agent registration")?;

        let request = connect_request(ReceiverStream::new(outgoing_rx), Some(&app_token))?;
        let response_stream = tokio::time::timeout(self.settings.stream_start_timeout, client.connect(request))
            .await
            .context("timed out starting PSU gRPC agent stream")?
            .context("failed to start PSU gRPC agent stream")?
            .into_inner();

        info!(agent_id = %self.agent_id, url = %self.server_url, "Connected PSU gRPC agent");

        Ok(PsuConnection {
            _client: client,
            outgoing_tx,
            response_stream,
        })
    }

    async fn serve(&self, mut connection: PsuConnection, shutdown_signal: &mut ShutdownSignal) -> anyhow::Result<()> {
        self.serve_messages(
            &mut connection.response_stream,
            &connection.outgoing_tx,
            shutdown_signal,
        )
        .await
    }

    async fn serve_messages<S>(
        &self,
        messages: &mut S,
        outgoing_tx: &mpsc::Sender<AgentMessage>,
        shutdown_signal: &mut ShutdownSignal,
    ) -> anyhow::Result<()>
    where
        S: Stream<Item = Result<protocol::ServerMessage, tonic::Status>> + Unpin,
    {
        let registry = ProcessRegistry::default();
        let mut process_tasks = JoinSet::new();
        let mut connection_id = String::new();

        loop {
            tokio::select! {
                _ = shutdown_signal.wait() => {
                    process_tasks.shutdown().await;
                    return Ok(());
                }
                message = messages.next() => {
                    let Some(message) = message else {
                        bail!("PSU gRPC server closed the agent stream");
                    };
                    let message = message.context("failed to read PSU gRPC server message")?;

                    if !message.connection_id.trim().is_empty() {
                        connection_id.clone_from(&message.connection_id);
                    }

                    // Shutdown must not wait for message handling to complete.
                    let handled = tokio::select! {
                        _ = shutdown_signal.wait() => None,
                        result = self.handle_server_message(
                            message,
                            outgoing_tx,
                            &registry,
                            &mut process_tasks,
                            &mut connection_id,
                        ) => Some(result),
                    };

                    match handled {
                        Some(result) => result?,
                        None => {
                            process_tasks.shutdown().await;
                            return Ok(());
                        }
                    }
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
                let (control_tx, control_rx) = mpsc::channel(8);
                let incoming_rx = registry
                    .register_stream(&start_process.stream_id, control_tx.clone())
                    .await;
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

    async fn resolve_app_token(&self) -> anyhow::Result<String> {
        let app_token = self.conf.app_token.as_str();

        // Avoid constructing a PowerShell worker unless the token is a secret reference.
        if app_token_secret_reference_name(app_token).is_none() {
            return Ok(app_token.to_owned());
        }

        // A hung secret vault must not stall every reconnect attempt; the worker kills the PowerShell process on timeout.
        let worker = PowerShellWorker::new(self.conf.powershell.clone(), self.settings.app_token_resolution_timeout)
            .context("failed to initialize PSU PowerShell worker for gRPC AppToken secret resolution")?;

        worker
            .resolve_app_token(app_token)
            .await
            .context("failed to resolve PSU gRPC AppToken secret")
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

fn psu_endpoint(server_url: &str, settings: &ConnectionSettings) -> Result<Endpoint, tonic::transport::Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // HTTP/2 PINGs detect a silently dropped connection (for example, after a NAT or firewall idle timeout)
    // even when no job is running, and make the pending stream read fail so the agent reconnects.
    Ok(Endpoint::new(server_url.to_owned())?
        .connect_timeout(settings.connect_timeout)
        .tcp_keepalive(Some(settings.keep_alive_interval))
        .http2_keep_alive_interval(settings.keep_alive_interval)
        .keep_alive_timeout(settings.keep_alive_timeout)
        .keep_alive_while_idle(true))
}

/// Returns whether the URL sends traffic unencrypted to a host other than the local machine.
fn is_plaintext_to_remote_host(url: &Url) -> bool {
    let is_loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };

    url.scheme() == "http" && !is_loopback
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

fn connect_request<T>(stream: T, app_token: Option<&str>) -> anyhow::Result<Request<T>> {
    let mut request = Request::new(stream);

    if let Some(token) = app_token {
        let authorization = format!("Bearer {token}");
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(authorization).context("invalid PSU gRPC AppToken metadata")?,
        );
    }

    Ok(request)
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
            || selector.to_ascii_lowercase().starts_with("pwsh-")
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
            .kill_on_drop(true)
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

#[cfg(test)]
mod tests {
    use devolutions_gateway_task::ShutdownHandle;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

    use super::*;

    async fn first_connection_byte(scheme: &str) -> u8 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind endpoint");
        let url = format!("{scheme}://{}", listener.local_addr().expect("listener address"));
        let endpoint = psu_endpoint(&url, &ConnectionSettings::default()).expect("create endpoint");
        let connection = tokio::spawn(async move { endpoint.connect().await });

        let first_byte = tokio::time::timeout(Duration::from_secs(5), async {
            let (mut stream, _) = listener.accept().await.expect("accept connection");
            let mut byte = [0];
            stream.read_exact(&mut byte).await.expect("read client preface");
            byte[0]
        })
        .await
        .expect("client did not connect");

        connection.abort();
        first_byte
    }

    #[tokio::test]
    async fn https_endpoint_starts_tls_handshake() {
        assert_eq!(
            first_connection_byte("https").await,
            0x16,
            "HTTPS connection must start with a TLS ClientHello"
        );
    }

    #[tokio::test]
    async fn http_endpoint_starts_http2_preface() {
        assert_eq!(
            first_connection_byte("http").await,
            b'P',
            "HTTP connection must start with the HTTP/2 preface"
        );
    }

    #[test]
    fn connect_request_omits_authorization_without_app_token() {
        let request = connect_request((), None).expect("create request");

        assert!(!request.metadata().contains_key("authorization"));
    }

    #[test]
    fn connect_request_adds_authorization_with_app_token() {
        let request = connect_request((), Some("token")).expect("create request");

        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .expect("authorization metadata")
                .to_str()
                .expect("metadata string"),
            "Bearer token"
        );
    }

    #[tokio::test]
    async fn literal_app_token_does_not_require_secret_resolution() {
        let agent = test_agent("http://localhost:5000", "literal-token", ConnectionSettings::default());

        let app_token = agent.resolve_app_token().await.expect("resolve AppToken");

        assert_eq!(app_token, "literal-token");
    }

    fn test_agent(server_url: &str, app_token: &str, settings: ConnectionSettings) -> PsuAgent {
        let mut agent = PsuAgent::new(PsuConf {
            server_url: server_url.parse().expect("server URL"),
            agent_id: Some("agent-01".to_owned()),
            display_name: None,
            app_token: app_token.to_owned(),
            powershell: dto::PsuPowerShellConf {
                executable_path: Some("missing-pwsh".into()),
                ..dto::PsuPowerShellConf::default()
            },
        })
        .expect("create agent");
        agent.settings = settings;
        agent
    }

    /// Binds a TCP listener that accepts connections and never answers, like a peer behind a silently dropped route.
    async fn unresponsive_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind endpoint");
        let url = format!("http://{}", listener.local_addr().expect("listener address"));
        let server = tokio::spawn(async move {
            let mut connections = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                // Hold the stream open without ever reading or writing.
                connections.push(stream);
            }
            drop(connections);
        });

        (url, server)
    }

    #[test]
    fn plaintext_warning_only_targets_remote_http_hosts() {
        for (url, expected) in [
            ("http://psu.example.com", true),
            ("http://192.0.2.10:5000", true),
            ("http://localhost:5000", false),
            ("http://LOCALHOST:5000", false),
            ("http://127.0.0.1:5000", false),
            ("http://[::1]:5000", false),
            ("https://psu.example.com", false),
        ] {
            let url = url.parse::<Url>().expect("parse URL");
            assert_eq!(is_plaintext_to_remote_host(&url), expected, "{url}");
        }
    }

    #[tokio::test]
    async fn secret_resolution_failure_is_retried_until_shutdown() {
        let agent = test_agent(
            "http://127.0.0.1:9",
            "$secret:AppToken",
            ConnectionSettings {
                retry_initial_interval: Duration::from_millis(10),
                retry_max_interval: Duration::from_millis(10),
                ..ConnectionSettings::default()
            },
        );

        // The PowerShell executable does not exist, so every secret resolution attempt fails.
        let error = agent.connect().await.err().expect("secret resolution should fail");
        assert!(format!("{error:#}").contains("AppToken"), "unexpected error: {error:#}");

        let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let run = tokio::spawn(agent.run(shutdown_signal));

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !run.is_finished(),
            "agent must keep retrying when the secret cannot be resolved"
        );

        shutdown_handle.signal();
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("agent did not stop")
            .expect("agent task panicked")
            .expect("agent run failed");
    }

    #[tokio::test]
    async fn hung_app_token_resolution_times_out_and_kills_powershell() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let marker = temp_dir.path().join("still-running");

        // Stands in for PowerShell blocked on a secret vault: it ignores its arguments and writes the marker
        // only if it is still alive after the timeout.
        let script = if cfg!(windows) {
            let script = temp_dir.path().join("hung-pwsh.cmd");
            let content = format!("@ping -n 4 127.0.0.1 >nul\r\n@echo done> \"{}\"\r\n", marker.display());
            std::fs::write(&script, content).expect("write script");
            script
        } else {
            let script = temp_dir.path().join("hung-pwsh.sh");
            let content = format!("#!/bin/sh\nsleep 3\ntouch '{}'\n", marker.display());
            std::fs::write(&script, content).expect("write script");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod script");
            }
            script
        };

        let mut agent = test_agent(
            "http://127.0.0.1:9",
            "$secret:AppToken",
            ConnectionSettings {
                app_token_resolution_timeout: Duration::from_millis(500),
                ..ConnectionSettings::default()
            },
        );
        agent.conf.powershell.executable_path =
            Some(camino::Utf8PathBuf::from_path_buf(script).expect("UTF-8 script path"));

        let error = tokio::time::timeout(Duration::from_secs(2), agent.resolve_app_token())
            .await
            .expect("AppToken resolution was not bounded by its timeout")
            .expect_err("hung AppToken resolution should fail");
        assert!(
            format!("{error:#}").contains("timed out"),
            "unexpected error: {error:#}"
        );

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!marker.exists(), "the timed-out PowerShell process was not killed");
    }

    #[tokio::test]
    async fn shutdown_cancels_pending_connection() {
        let (url, server) = unresponsive_server().await;
        let agent = test_agent(&url, "literal-token", ConnectionSettings::default());

        let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let run = tokio::spawn(agent.run(shutdown_signal));

        // Let the agent reach the server and wait for the stream to start.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!run.is_finished(), "agent must wait for the unresponsive server");

        shutdown_handle.signal();
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("shutdown did not interrupt the connect phase")
            .expect("agent task panicked")
            .expect("agent run failed");

        server.abort();
    }

    #[tokio::test]
    async fn http2_keep_alive_detects_unresponsive_server() {
        let (url, server) = unresponsive_server().await;
        let agent = test_agent(
            &url,
            "literal-token",
            ConnectionSettings {
                keep_alive_interval: Duration::from_millis(200),
                keep_alive_timeout: Duration::from_millis(200),
                ..ConnectionSettings::default()
            },
        );

        // Without HTTP/2 keepalive, this would wait for the 30-second stream start timeout.
        let result = tokio::time::timeout(Duration::from_secs(10), agent.connect())
            .await
            .expect("keepalive did not close the unresponsive connection");
        let error = result.err().expect("connection to an unresponsive server should fail");
        assert!(
            format!("{error:#}").contains("keep-alive timed out"),
            "connection should fail on keepalive: {error:#}"
        );

        server.abort();
    }

    fn server_message(payload: ServerPayload) -> protocol::ServerMessage {
        protocol::ServerMessage {
            request_id: String::new(),
            connection_id: String::new(),
            timestamp: None,
            payload: Some(payload),
        }
    }

    fn start_process(id: &str, executable: &str, arguments: &[&str]) -> protocol::ServerMessage {
        server_message(ServerPayload::StartProcess(protocol::StartProcess {
            correlation_id: id.to_owned(),
            stream_id: id.to_owned(),
            executable: executable.to_owned(),
            arguments: arguments.iter().map(|&argument| argument.to_owned()).collect(),
            working_directory: String::new(),
            environment: HashMap::new(),
            metadata: HashMap::new(),
        }))
    }

    #[tokio::test]
    async fn stalled_child_stdin_does_not_block_other_streams_or_shutdown() {
        // The stalled child never reads stdin; the echo child copies stdin to stdout.
        let (stalled, echo) = if cfg!(windows) {
            (
                start_process("stalled", "ping", &["-n", "60", "127.0.0.1"]),
                start_process("echo", "findstr", &["^"]),
            )
        } else {
            (
                start_process("stalled", "sleep", &["60"]),
                start_process("echo", "cat", &[]),
            )
        };

        let agent = test_agent("http://127.0.0.1:9", "literal-token", ConnectionSettings::default());
        let (server_tx, server_rx) = mpsc::channel::<Result<protocol::ServerMessage, tonic::Status>>(16);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(1024);
        let (shutdown_handle, mut shutdown_signal) = ShutdownHandle::new();

        let serve = tokio::spawn(async move {
            agent
                .serve_messages(&mut ReceiverStream::new(server_rx), &outgoing_tx, &mut shutdown_signal)
                .await
        });

        server_tx.send(Ok(stalled)).await.expect("send StartProcess");
        server_tx.send(Ok(echo)).await.expect("send StartProcess");

        // Large frames fill the OS pipe buffer quickly, so the agent-side stdin buffer for the stalled child fills too.
        let flood = tokio::spawn({
            let server_tx = server_tx.clone();
            async move {
                for sequence in 0..1024 {
                    let frame = stream_data("stalled".to_owned(), sequence, vec![b'x'; 64 * 1024], false);
                    if server_tx
                        .send(Ok(server_message(ServerPayload::StreamData(frame))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });

        tokio::time::timeout(Duration::from_secs(10), flood)
            .await
            .expect("serve loop blocked on the stalled stream")
            .expect("flood task panicked");

        for (sequence, data, end_of_stream) in [(0, b"hello".to_vec(), false), (1, Vec::new(), true)] {
            let frame = stream_data("echo".to_owned(), sequence, data, end_of_stream);
            server_tx
                .send(Ok(server_message(ServerPayload::StreamData(frame))))
                .await
                .expect("send StreamData");
        }

        let mut stalled_closed = None;
        let mut echoed = false;
        tokio::time::timeout(Duration::from_secs(20), async {
            while stalled_closed.is_none() || !echoed {
                let message = outgoing_rx.recv().await.expect("outgoing channel closed");
                match message.payload {
                    Some(AgentPayload::StreamClosed(closed)) if closed.stream_id == "stalled" => {
                        stalled_closed = Some(closed);
                    }
                    Some(AgentPayload::StreamData(data)) if data.stream_id == "echo" && data.data == b"hello" => {
                        echoed = true;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("expected the stalled stream to be stopped and the echo stream to be served");

        let stalled_closed = stalled_closed.expect("stalled stream closed");
        assert!(stalled_closed.error);
        assert!(
            stalled_closed.reason.contains("stopped consuming stdin"),
            "unexpected reason: {}",
            stalled_closed.reason
        );

        shutdown_handle.signal();
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .expect("shutdown did not stop the serve loop")
            .expect("serve task panicked")
            .expect("serve failed");
    }
}
