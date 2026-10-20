use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use protocol::agent_control_server::{AgentControl, AgentControlServer};
use protocol::agent_message::Payload;
use protocol::{AgentMessage, ProcessCredential, RegisterAgent, ServerMessage, StartProcess};
use rstest::rstest;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_util::task::AbortOnDropHandle;
use tonic::{Request, Response, Status, Streaming};

#[expect(
    unused_qualifications,
    unreachable_pub,
    reason = "tonic generates public fully qualified bindings for a private test fixture"
)]
#[expect(
    clippy::similar_names,
    clippy::clone_on_ref_ptr,
    clippy::large_enum_variant,
    reason = "the complete test-local protocol retains tonic/prost generated representations and names"
)]
mod protocol {
    tonic::include_proto!("devolutions.psu.agent.poc.v1");
}

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const PASSWORD_SENTINEL: &str = "not-a-real-password-psu-conformance";
const USERNAME_SENTINEL: &str = "psu-conformance-synthetic-user";
const DOMAIN_SENTINEL: &str = "psu-conformance-synthetic-domain";

#[tokio::test]
async fn app_token_http_registration_does_not_advertise_run_as() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    tokio::time::timeout(RESPONSE_TIMEOUT, fixture.valid_control())
        .await
        .context("setup: credential-free control timed out")??;

    // CONTRACT.md "Connection eligibility": advertisement requires Windows, device auth and verified HTTPS.
    assert!(
        !fixture
            .registration
            .capabilities
            .iter()
            .any(|capability| capability.name == "job_execution_run_as" && capability.version == "poc.v1"),
        "an app-token HTTP connection must not advertise the Run As capability"
    );
    #[cfg(windows)]
    // CONTRACT.md "Connection eligibility": a Windows Agent reports exactly "windows".
    assert_eq!(fixture.registration.os, "windows");

    fixture.stop().await
}

#[rstest]
#[case::nonempty(ProcessCredential {
    username: USERNAME_SENTINEL.to_owned(),
    password: PASSWORD_SENTINEL.to_owned(),
    domain: DOMAIN_SENTINEL.to_owned(),
})]
#[case::present_empty(ProcessCredential::default())]
#[tokio::test]
async fn app_token_http_rejects_present_credential(#[case] credential: ProcessCredential) -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    tokio::time::timeout(RESPONSE_TIMEOUT, fixture.valid_control())
        .await
        .context("setup: credential-free control timed out")??;
    std::fs::remove_file(fixture.marker()).context("setup: remove successful control marker")?;

    let mut launch = fixture.launch();
    launch.correlation_id = "credential-present".to_owned();
    launch.stream_id = "credential-present-stream".to_owned();
    launch.credential = Some(credential);
    fixture.send_launch(launch).await?;

    // CONTRACT.md "Launch and failure behavior": a present credential cannot fall back to service identity.
    // These cases test presence on an ineligible connection, not credential-field or Windows-logon validation.
    tokio::time::timeout(RESPONSE_TIMEOUT, assert_rejected(&mut fixture))
        .await
        .context("missing launch-failure responses; not proof of rejection")??;
    assert!(
        !fixture.marker().exists(),
        "the rejected request executed the control script under a substitute identity"
    );
    fixture.stop().await
}

async fn assert_rejected(fixture: &mut Fixture) -> anyhow::Result<()> {
    let mut responses = Vec::new();
    loop {
        match fixture.next().await? {
            Payload::StreamClosed(closed) if closed.stream_id == "credential-omitted-stream" => {}
            Payload::StreamData(_) | Payload::Heartbeat(_) | Payload::Diagnostic(_) => {}
            response => {
                let completed = matches!(response, Payload::ProcessCompleted(_));
                responses.push(response);
                if completed {
                    break;
                }
            }
        }
    }
    // Wait for completion before asserting so even a nonconforming quick control process can exit.
    assert!(
        !responses
            .iter()
            .any(|response| matches!(response, Payload::ProcessStarted(_))),
        "a credential-bearing launch started on an ineligible connection"
    );
    let [Payload::StreamClosed(closed), Payload::ProcessCompleted(completed)] = responses.as_slice() else {
        panic!("expected StreamClosed followed by ProcessCompleted for the refused launch");
    };
    assert_eq!(closed.stream_id, "credential-present-stream");
    assert!(closed.error, "a refused launch must close its stream with error=true");
    assert!(!closed.reason.is_empty(), "a refused launch must explain the failure");
    assert_eq!(completed.correlation_id, "credential-present");
    assert_eq!(completed.exit_code, -1);
    assert!(!completed.canceled);
    assert_eq!(completed.error_message, closed.reason);
    Ok(())
}

struct ControlService {
    requests: mpsc::Sender<Streaming<AgentMessage>>,
    responses: std::sync::Mutex<Option<mpsc::Receiver<Result<ServerMessage, Status>>>>,
}

#[tonic::async_trait]
impl AgentControl for ControlService {
    type ConnectStream = ReceiverStream<Result<ServerMessage, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let responses = self
            .responses
            .lock()
            .expect("test response lock")
            .take()
            .ok_or_else(|| Status::failed_precondition("fixture accepts only one connection"))?;
        self.requests
            .send(request.into_inner())
            .await
            .map_err(|_| Status::unavailable("fixture request receiver closed"))?;
        Ok(Response::new(ReceiverStream::new(responses)))
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    process: tokio::process::Child,
    server: AbortOnDropHandle<Result<(), tonic::transport::Error>>,
    requests: Streaming<AgentMessage>,
    responses: mpsc::Sender<Result<ServerMessage, Status>>,
    registration: RegisterAgent,
    executable: String,
}

impl Fixture {
    async fn start() -> anyhow::Result<Self> {
        let executable = powershell_executable()?;
        let directory = tempfile::tempdir().context("setup: create isolated Agent config directory")?;
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("setup: bind loopback gRPC listener")?;
        let address = listener.local_addr().context("setup: read gRPC listener address")?;
        let (request_sender, mut request_receiver) = mpsc::channel(1);
        let (response_sender, response_receiver) = mpsc::channel(16);
        let service = ControlService {
            requests: request_sender,
            responses: std::sync::Mutex::new(Some(response_receiver)),
        };
        let server = AbortOnDropHandle::new(tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AgentControlServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        }));

        // Public config DTOs at 406a74c: PsuConf, PsuPowerShellConf and ConfFile.
        // UNTESTED: Keep unrelated modules disabled and proxy mode Off to prevent host services or external traffic;
        // review these settings whenever the fixture configuration changes.
        let config = serde_json::json!({
            "LogFile": directory.path().join("agent"),
            "Updater": { "Enabled": false },
            "RemoteDesktop": { "Enabled": false },
            "Pedm": { "Enabled": false },
            "Session": { "Enabled": false },
            "PackageBroker": { "Enabled": false },
            "Tunnel": { "Enabled": false },
            "Proxy": { "Mode": "Off" },
            "PsuAgent": {
                "Enabled": true,
                "ServerUrl": format!("http://{address}"),
                "AgentId": "psu-run-as-conformance",
                "AppToken": "test-owned-app-token",
                "PowerShell": {
                    "ExecutablePath": executable,
                    "WorkerPoolSize": 0,
                    "MaxWorkerPoolSize": 1
                }
            }
        });
        std::fs::write(
            directory.path().join("agent.json"),
            serde_json::to_vec(&config).context("setup: serialize public Agent configuration")?,
        )
        .context("setup: write isolated Agent configuration")?;
        let stdout =
            std::fs::File::create(directory.path().join("stdout.log")).context("setup: create stdout capture")?;
        let stderr =
            std::fs::File::create(directory.path().join("stderr.log")).context("setup: create stderr capture")?;
        let process = testsuite::cli::agent_tokio_cmd()
            .arg("run")
            .env("DAGENT_CONFIG_PATH", directory.path())
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .context("setup: start foreground Agent")?;
        let requests = tokio::time::timeout(RESPONSE_TIMEOUT, request_receiver.recv())
            .await
            .context("setup: Agent did not open AgentControl.Connect")?
            .context("setup: gRPC service stopped before Connect")?;
        let mut fixture = Self {
            directory,
            process,
            server,
            requests,
            responses: response_sender,
            registration: RegisterAgent::default(),
            executable,
        };
        fixture.registration = match fixture.next().await.context("setup: receive registration")? {
            Payload::RegisterAgent(registration) => registration,
            _ => anyhow::bail!("setup: expected RegisterAgent before launch"),
        };
        fixture
            .responses
            .send(Ok(ServerMessage {
                connection_id: "conformance-connection".to_owned(),
                payload: Some(protocol::server_message::Payload::RegisterAccepted(
                    protocol::RegisterAccepted {
                        connection_id: "conformance-connection".to_owned(),
                    },
                )),
                ..ServerMessage::default()
            }))
            .await
            .context("setup: accept registration")?;
        Ok(fixture)
    }

    fn marker(&self) -> PathBuf {
        self.directory.path().join("executed.txt")
    }

    fn launch(&self) -> StartProcess {
        let marker = self.marker().to_string_lossy().replace('\'', "''");
        StartProcess {
            correlation_id: "credential-omitted".to_owned(),
            stream_id: "credential-omitted-stream".to_owned(),
            executable: self.executable.clone(),
            arguments: vec![
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-Command".to_owned(),
                format!("[IO.File]::WriteAllText('{marker}', 'executed'); exit 0"),
            ],
            working_directory: self.directory.path().to_string_lossy().into_owned(),
            ..StartProcess::default()
        }
    }

    async fn send_launch(&self, launch: StartProcess) -> anyhow::Result<()> {
        self.responses
            .send(Ok(ServerMessage {
                connection_id: "conformance-connection".to_owned(),
                payload: Some(protocol::server_message::Payload::StartProcess(launch)),
                ..ServerMessage::default()
            }))
            .await
            .context("send launch on established connection")
    }

    async fn valid_control(&mut self) -> anyhow::Result<()> {
        self.send_launch(self.launch())
            .await
            .context("setup: send credential-free control")?;
        let mut started = false;
        loop {
            match self.next().await.context("setup: credential-free control response")? {
                Payload::ProcessStarted(process) => {
                    anyhow::ensure!(
                        process.correlation_id == "credential-omitted" && 0 < process.process_id,
                        "setup: credential-free control did not report its process"
                    );
                    started = true;
                }
                Payload::ProcessCompleted(process) => {
                    anyhow::ensure!(
                        started
                            && process.correlation_id == "credential-omitted"
                            && process.exit_code == 0
                            && !process.canceled
                            && process.error_message.is_empty(),
                        "setup: credential-free control did not complete successfully"
                    );
                    break;
                }
                Payload::StreamClosed(_) | Payload::StreamData(_) | Payload::Heartbeat(_) | Payload::Diagnostic(_) => {}
                Payload::RegisterAgent(_) => anyhow::bail!("setup: unexpected replacement registration"),
            }
        }
        // CONTRACT.md "Credential message": omission preserves credential-free execution on app-token HTTP.
        anyhow::ensure!(
            std::fs::read(self.marker()).context("setup: control did not execute its script")? == b"executed",
            "setup: credential-free control marker differs from the requested script"
        );
        Ok(())
    }

    async fn next(&mut self) -> anyhow::Result<Payload> {
        let message = tokio::time::timeout(RESPONSE_TIMEOUT, self.requests.message())
            .await
            .context("no protocol response before deadline; not proof of rejection")?
            .context("Agent stream transport failed; not proof of rejection")?
            .context("Agent disconnected; not proof of rejection")?;
        // CONTRACT.md "Credential confidentiality": diagnostics must not disclose credentials.
        if matches!(
            &message.payload,
            Some(Payload::Diagnostic(_) | Payload::ProcessCompleted(_) | Payload::StreamClosed(_))
        ) {
            assert_no_credential(&format!("{:?}", message.payload));
        }
        message.payload.context("Agent message has no payload")
    }

    async fn stop(mut self) -> anyhow::Result<()> {
        self.process.kill().await.context("stop test-owned Agent process")?;
        self.process.wait().await.context("reap test-owned Agent process")?;
        self.server.abort();
        match self.server.await {
            Err(error) if error.is_cancelled() => {}
            result => result
                .context("join loopback gRPC server")?
                .context("serve loopback gRPC")?,
        }
        for entry in std::fs::read_dir(self.directory.path()).context("read isolated Agent captures")? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let bytes = std::fs::read(entry.path())?;
                assert_no_credential(&String::from_utf8_lossy(&bytes));
            }
        }
        Ok(())
    }
}

fn assert_no_credential(text: &str) {
    for sentinel in [USERNAME_SENTINEL, PASSWORD_SENTINEL, DOMAIN_SENTINEL] {
        assert!(
            !text.contains(sentinel),
            "Agent diagnostics or configuration disclosed a test credential"
        );
    }
}

fn powershell_executable() -> anyhow::Result<String> {
    let name = if cfg!(windows) { "pwsh.exe" } else { "pwsh" };
    let path = std::env::var_os("PATH").context("setup: PATH is required to locate PowerShell")?;
    let executable = std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .context("setup: install PowerShell 7 and place pwsh on PATH")?;
    executable
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("setup: PowerShell path is not UTF-8"))
}
