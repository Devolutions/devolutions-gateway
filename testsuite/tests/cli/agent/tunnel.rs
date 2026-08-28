use std::ffi::{OsStr, OsString};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use devolutions_gateway::target_addr::TargetAddr;
use devolutions_gateway::token::{
    AccessScope, ApplicationProtocol, AssociationTokenClaims, ConnectionMode, EnrollmentTokenClaims,
    ReconnectionPolicy, RecordingPolicy, ScopeTokenClaims, SessionTtl,
};
use futures_util::{SinkExt as _, StreamExt as _};
use ipnetwork::Ipv4Network;
use nonempty::NonEmpty;
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::PrivateKey;
use serde::Serialize;
use testsuite::cli::{agent_assert_cmd, agent_tokio_cmd, dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{AgentTunnelConfig, DgwConfig};
use tokio::net::TcpListener;
use tokio::process::Child;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use uuid::Uuid;

const DOCKER_TARGET_PORT: u16 = 9000;
const DOCKER_EXACT_ROUTE: &str = "exact.route.test";
const DOCKER_WILDCARD_ROUTE: &str = "*.wild.route.test";
const DOCKER_WILDCARD_TARGET: &str = "child.wild.route.test";
const DOCKER_GATEWAY_HOST: &str = "gateway.test";
const AGENT_BINARY: &str = "/opt/devolutions/agent/devolutions-agent";
const POWERSHELL_BINARY: &str = "/var/lib/devolutions-agent/.pwsh/bin/pwsh";

fn docker<I, S>(args: I) -> anyhow::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<OsString> = args.into_iter().map(|arg| arg.as_ref().to_owned()).collect();
    let output = Command::new("docker").args(&args).output()?;
    anyhow::ensure!(
        output.status.success(),
        "docker {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output)
}

fn docker_stdout<I, S>(args: I) -> anyhow::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = docker(args)?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn remove_container(name: &str) {
    let _ = Command::new("docker")
        .args(["rm", "--force", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn container_logs(name: &str) -> String {
    docker_stdout(["logs", name]).unwrap_or_default()
}

fn assert_container_running(name: &str) {
    let running = docker_stdout(["inspect", "--format", "{{.State.Running}}", name]).unwrap_or_default();
    assert_eq!(running, "true", "container stopped: {}", container_logs(name));
}

struct DockerEnvironment {
    image: String,
    network: String,
    target_container: String,
    dns_agent_container: String,
    ip_agent_container: String,
    dns_volume: String,
    ip_volume: String,
    target_ip: String,
    dns_agent_ip: String,
    ip_agent_ip: String,
}

impl DockerEnvironment {
    fn create(repo_root: &Path) -> anyhow::Result<Self> {
        docker(["info", "--format", "{{.ServerVersion}}"])?;

        let id = Uuid::new_v4();
        let subnet = format!("10.{}.{}.0/24", id.as_bytes()[0], id.as_bytes()[1]);
        let suffix = id.simple().to_string();
        let mut environment = Self {
            image: format!("dgw-agent-tunnel-e2e:{suffix}"),
            network: format!("dgw-agent-tunnel-e2e-{suffix}"),
            target_container: format!("dgw-agent-tunnel-target-{suffix}"),
            dns_agent_container: format!("dgw-agent-tunnel-dns-agent-{suffix}"),
            ip_agent_container: format!("dgw-agent-tunnel-ip-agent-{suffix}"),
            dns_volume: format!("dgw-agent-tunnel-dns-{suffix}"),
            ip_volume: format!("dgw-agent-tunnel-ip-{suffix}"),
            target_ip: String::new(),
            dns_agent_ip: String::new(),
            ip_agent_ip: String::new(),
        };

        docker([
            OsStr::new("build"),
            OsStr::new("--build-arg"),
            OsStr::new("BUILD_TARGET=local"),
            OsStr::new("--file"),
            repo_root.join("package/AgentLinux/Dockerfile").as_os_str(),
            OsStr::new("--tag"),
            environment.image.as_ref(),
            repo_root.as_os_str(),
        ])?;

        docker([
            "network",
            "create",
            "--driver",
            "bridge",
            "--subnet",
            &subnet,
            &environment.network,
        ])?;
        let subnet: Ipv4Network = docker_stdout([
            "network",
            "inspect",
            "--format",
            "{{(index .IPAM.Config 0).Subnet}}",
            &environment.network,
        ])?
        .parse()?;
        let network = u32::from(subnet.network());
        let address = |offset| Ipv4Addr::from(network + offset);
        let target_ip = address(10);
        let dns_agent_ip = address(20);
        let ip_agent_ip = address(21);
        anyhow::ensure!(
            [target_ip, dns_agent_ip, ip_agent_ip]
                .into_iter()
                .all(|address| subnet.contains(address) && address != subnet.broadcast()),
            "docker network subnet is too small for the test fixture"
        );
        environment.target_ip = target_ip.to_string();
        environment.dns_agent_ip = dns_agent_ip.to_string();
        environment.ip_agent_ip = ip_agent_ip.to_string();
        docker(["volume", "create", &environment.dns_volume])?;
        docker(["volume", "create", &environment.ip_volume])?;
        Ok(environment)
    }

    fn start_target(&self, allowed_agent_ip: &str) -> anyhow::Result<()> {
        let script = r#"
$allowed = [Net.IPAddress]::Parse($env:ALLOWED_CLIENT)
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 9000)
$listener.Start()
Write-Output 'READY'
while ($true) {
    $client = $listener.AcceptTcpClient()
    if (-not $client.Client.RemoteEndPoint.Address.Equals($allowed)) {
        $client.Dispose()
        continue
    }
    $stream = $client.GetStream()
    $buffer = [byte[]]::new(8192)
    $count = $stream.Read($buffer, 0, $buffer.Length)
    if ($count -gt 0) {
        $stream.Write($buffer, 0, $count)
    }
    $client.Dispose()
}
"#;
        docker([
            "run",
            "--detach",
            "--name",
            &self.target_container,
            "--network",
            &self.network,
            "--ip",
            &self.target_ip,
            "--network-alias",
            DOCKER_EXACT_ROUTE,
            "--network-alias",
            DOCKER_WILDCARD_TARGET,
            "--env",
            &format!("ALLOWED_CLIENT={allowed_agent_ip}"),
            "--entrypoint",
            POWERSHELL_BINARY,
            &self.image,
            "-NoLogo",
            "-NoProfile",
            "-Command",
            script,
        ])?;
        Ok(())
    }

    fn wait_for_target(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if docker_stdout(["logs", &self.target_container])?.contains("READY") {
                return Ok(());
            }
            anyhow::ensure!(Instant::now() < deadline, "docker target did not become ready");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn enroll_agent(
        &self,
        volume: &str,
        agent_ip: &str,
        token_path: &Path,
        route_flag: &str,
        routes: &str,
    ) -> anyhow::Result<()> {
        let token_mount = format!(
            "type=bind,src={},dst=/run/enrollment-token,readonly",
            token_path.to_string_lossy()
        );
        let config_mount = format!("type=volume,src={volume},dst=/etc/devolutions-agent");
        let command = format!(
            "{AGENT_BINARY} up --enrollment-string \"$(cat /run/enrollment-token)\" {route_flag} '{routes}' && \
             chown -R devolutions-agent:devolutions-agent /etc/devolutions-agent"
        );
        docker([
            "run",
            "--rm",
            "--user",
            "0",
            "--network",
            &self.network,
            "--ip",
            agent_ip,
            "--add-host",
            &format!("{DOCKER_GATEWAY_HOST}:host-gateway"),
            "--mount",
            &config_mount,
            "--mount",
            &token_mount,
            "--entrypoint",
            "/bin/sh",
            &self.image,
            "-c",
            &command,
        ])?;
        Ok(())
    }

    fn start_agent(&self, name: &str, volume: &str, agent_ip: &str) -> anyhow::Result<()> {
        let config_mount = format!("type=volume,src={volume},dst=/etc/devolutions-agent");
        docker([
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            &self.network,
            "--ip",
            agent_ip,
            "--add-host",
            &format!("{DOCKER_GATEWAY_HOST}:host-gateway"),
            "--mount",
            &config_mount,
            "--entrypoint",
            AGENT_BINARY,
            &self.image,
            "run",
        ])?;
        Ok(())
    }
}

impl Drop for DockerEnvironment {
    fn drop(&mut self) {
        for container in [
            &self.target_container,
            &self.dns_agent_container,
            &self.ip_agent_container,
        ] {
            remove_container(container);
        }
        for volume in [&self.dns_volume, &self.ip_volume] {
            let _ = Command::new("docker")
                .args(["volume", "rm", "--force", volume])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("docker")
            .args(["image", "rm", "--force", &self.image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn unix_timestamp() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("read system time")
            .as_secs(),
    )
    .expect("system time should fit in an i64")
}

fn sign<T: Serialize>(key: &PrivateKey, content_type: &str, claims: &T) -> String {
    let now = unix_timestamp();
    let mut claims = serde_json::to_value(claims).expect("serialize test claims");
    let claims = claims.as_object_mut().expect("test claims should be an object");
    claims.insert("iat".to_owned(), serde_json::json!(now));
    claims.insert("nbf".to_owned(), serde_json::json!(now - 1));
    CheckedJwtSig::new_with_cty(JwsAlg::RS256, content_type, claims)
        .encode(key)
        .expect("sign test token")
}

fn association_token(key: &PrivateKey, target: TargetAddr, agent_id: Option<Uuid>) -> (Uuid, String) {
    let session_id = Uuid::new_v4();
    let claims = AssociationTokenClaims {
        jet_aid: session_id,
        jet_ap: ApplicationProtocol::unknown(),
        jet_cm: ConnectionMode::Fwd {
            targets: NonEmpty::new(target),
        },
        jet_rec: RecordingPolicy::None,
        jet_flt: false,
        jet_ttl: SessionTtl::Unlimited,
        jet_reuse: ReconnectionPolicy::Disallowed,
        exp: unix_timestamp() + 60,
        jti: Uuid::new_v4(),
        cert_thumb256: None,
        jet_agent_id: agent_id,
    };
    (session_id, sign(key, "ASSOCIATION", &claims))
}

fn forwarding_request(
    http_port: u16,
    key: &PrivateKey,
    target: TargetAddr,
    agent_id: Option<Uuid>,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let (session_id, token) = association_token(key, target, agent_id);
    let mut request = format!("ws://127.0.0.1:{http_port}/jet/fwd/tcp/{session_id}")
        .into_client_request()
        .expect("build forwarding request");
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {token}").parse().expect("build authorization header"),
    );
    request
}

fn start_gateway(config_dir: &Path) -> Child {
    dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_dir)
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start gateway")
}

async fn round_trip(
    http_port: u16,
    key: &PrivateKey,
    target: TargetAddr,
    agent_id: Option<Uuid>,
    payload: &[u8],
) -> anyhow::Result<()> {
    let (mut socket, _) =
        tokio_tungstenite::connect_async(forwarding_request(http_port, key, target, agent_id)).await?;
    socket.send(Message::Binary(payload.to_vec().into())).await?;
    let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("forwarding socket closed"))??;
    anyhow::ensure!(
        message.into_data().as_ref() == payload,
        "forwarding response did not match request"
    );
    Ok(())
}

async fn wait_for_round_trip(
    http_port: u16,
    key: &PrivateKey,
    target: TargetAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let error = match round_trip(http_port, key, target.clone(), None, payload).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(error);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_registered_agent(
    http_port: u16,
    key: &PrivateKey,
    agent_name: &str,
    expected_subnets: &[&str],
    expected_domains: &[&str],
    timeout: Duration,
    container_logs: impl Fn() -> String,
) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + timeout;
    let mut last_response = serde_json::Value::Null;

    loop {
        let claims = ScopeTokenClaims {
            scope: AccessScope::AgentRead,
            exp: unix_timestamp() + 60,
            jti: Uuid::new_v4(),
        };
        let response = client
            .get(format!("http://127.0.0.1:{http_port}/jet/tunnel/agents"))
            .bearer_auth(sign(key, "SCOPE", &claims))
            .send()
            .await;

        if let Ok(response) = response
            && response.status().is_success()
            && let Ok(agents) = response.json::<serde_json::Value>().await
        {
            last_response = agents.clone();
            if let Some(agent) = agents.as_array().and_then(|agents| {
                agents
                    .iter()
                    .find(|agent| agent.get("name").and_then(serde_json::Value::as_str) == Some(agent_name))
            }) {
                let subnets = agent
                    .get("subnets")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>();
                let domains = agent
                    .get("domains")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|domain| domain.get("domain").and_then(serde_json::Value::as_str))
                    .collect::<Vec<_>>();
                let domains_are_explicit =
                    agent
                        .get("domains")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|domains| {
                            domains.iter().all(|domain| {
                                domain.get("auto_detected").and_then(serde_json::Value::as_bool) == Some(false)
                            })
                        });

                if agent.get("status").and_then(serde_json::Value::as_str) == Some("online")
                    && subnets == expected_subnets
                    && domains == expected_domains
                    && domains_are_explicit
                {
                    return;
                }
            }
        }

        assert!(
            Instant::now() < deadline,
            "agent registration did not match within {timeout:?}; response={last_response}; logs={}",
            container_logs()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn enrollment_token_file(key: &PrivateKey, http_port: u16, agent_name: &str) -> tempfile::NamedTempFile {
    let claims = EnrollmentTokenClaims {
        exp: unix_timestamp() + 60,
        jti: Uuid::new_v4(),
        jet_gw_url: format!("http://{DOCKER_GATEWAY_HOST}:{http_port}"),
        jet_agent_name: agent_name.to_owned(),
    };
    let file = tempfile::NamedTempFile::new().expect("create enrollment token file");
    std::fs::write(file.path(), sign(key, "ENROLLMENT", &claims)).expect("write enrollment token file");
    file
}

async fn start_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo server");
    let port = listener.local_addr().expect("read echo server address").port();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept echo connection");
            tokio::spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    (port, task)
}

fn enrolled_agent_id(config_dir: &Path) -> Uuid {
    std::fs::read_dir(config_dir.join("certs"))
        .expect("read agent certificate directory")
        .filter_map(Result::ok)
        .find_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix("-cert.pem"))
                .and_then(|id| Uuid::parse_str(id).ok())
        })
        .expect("find enrolled agent identity")
}

async fn assert_explicit_ip_is_refused(http_port: u16, key: &PrivateKey, agent_id: Uuid) {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind refused target");
    let port = target_listener
        .local_addr()
        .expect("read refused target address")
        .port();
    let (mut socket, _) = tokio_tungstenite::connect_async(forwarding_request(
        http_port,
        key,
        TargetAddr::from_components("tcp", "127.0.0.1", port).expect("build refused target"),
        Some(agent_id),
    ))
    .await
    .expect("open authenticated forwarding socket");
    socket
        .send(Message::Binary(b"must not connect".to_vec().into()))
        .await
        .expect("send refused payload");
    let response = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("forwarding refusal timed out");
    assert!(!matches!(response, Some(Ok(Message::Binary(_)))));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), target_listener.accept())
            .await
            .is_err()
    );
}

async fn delete_agent(http_port: u16, key: &PrivateKey, agent_id: Uuid) {
    let claims = ScopeTokenClaims {
        scope: AccessScope::AgentDelete,
        exp: unix_timestamp() + 60,
        jti: Uuid::new_v4(),
    };
    let response = reqwest::Client::new()
        .delete(format!("http://127.0.0.1:{http_port}/jet/tunnel/agents/{agent_id}"))
        .bearer_auth(sign(key, "SCOPE", &claims))
        .send()
        .await
        .expect("delete Agent");
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}

async fn list_agents(http_port: u16, key: &PrivateKey) -> Vec<serde_json::Value> {
    let claims = ScopeTokenClaims {
        scope: AccessScope::AgentRead,
        exp: unix_timestamp() + 60,
        jti: Uuid::new_v4(),
    };
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{http_port}/jet/tunnel/agents"))
        .bearer_auth(sign(key, "SCOPE", &claims))
        .send()
        .await
        .expect("list Agents")
        .error_for_status()
        .expect("Agent listing succeeds")
        .json()
        .await
        .expect("decode Agent listing")
}

async fn assert_agent_stays_rejected(
    http_port: u16,
    key: &PrivateKey,
    target: TargetAddr,
    agent_id: Uuid,
    duration: Duration,
) {
    let deadline = Instant::now() + duration;
    loop {
        assert!(
            round_trip(
                http_port,
                key,
                target.clone(),
                Some(agent_id),
                b"deleted Agent must stay rejected"
            )
            .await
            .is_err()
        );
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn enrolled_agent_forwards_domain_only_route_and_reconnects() {
    let provisioner_key = PrivateKey::generate_rsa(2048).expect("generate provisioner key");
    let public_key_data = format!(
        "m{}",
        base64::engine::general_purpose::STANDARD.encode(
            provisioner_key
                .to_public_key()
                .expect("derive provisioner public key")
                .to_der()
                .expect("encode provisioner public key")
        )
    );
    let config = DgwConfig::builder()
        .hostname("localhost".to_owned())
        .provisioner_public_key_data(public_key_data)
        .agent_tunnel(AgentTunnelConfig::builder().build())
        .enable_unstable(true)
        .build()
        .init()
        .expect("initialize gateway config");
    let mut gateway = start_gateway(config.config_dir());
    wait_for_tcp_port(config.http_port())
        .await
        .expect("gateway http port ready");

    let agent_config = tempfile::tempdir().expect("create agent config directory");
    let enrollment_claims = EnrollmentTokenClaims {
        exp: unix_timestamp() + 60,
        jti: Uuid::new_v4(),
        jet_gw_url: format!("http://127.0.0.1:{}", config.http_port()),
        jet_agent_name: "smoke-agent".to_owned(),
    };
    let enrollment_token = sign(&provisioner_key, "ENROLLMENT", &enrollment_claims);
    agent_assert_cmd()
        .env("DAGENT_CONFIG_PATH", agent_config.path())
        .args([
            "up",
            "--enrollment-string",
            &enrollment_token,
            "--advertise-domains",
            "localhost",
        ])
        .assert()
        .success();
    let agent_id = enrolled_agent_id(agent_config.path());
    let agents = list_agents(config.http_port(), &provisioner_key).await;
    let offline = agents
        .iter()
        .find(|agent| agent.get("agent_id").and_then(serde_json::Value::as_str) == Some(&agent_id.to_string()))
        .expect("enrolled Agent is listed before connecting");
    assert_eq!(
        offline.get("name").and_then(serde_json::Value::as_str),
        Some("smoke-agent")
    );
    assert_eq!(
        offline.get("status").and_then(serde_json::Value::as_str),
        Some("offline")
    );
    assert!(offline.get("last_seen_ms").is_some_and(serde_json::Value::is_null));
    assert!(offline.get("subnets").is_some_and(serde_json::Value::is_null));
    assert!(offline.get("domains").is_some_and(serde_json::Value::is_null));
    assert!(offline.get("cert_fingerprint").is_none());
    assert!(offline.get("route_epoch").is_none());
    let mut agent = agent_tokio_cmd()
        .env("DAGENT_CONFIG_PATH", agent_config.path())
        .arg("run")
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start agent");
    let (echo_port, echo_task) = start_echo_server().await;
    let echo_target = TargetAddr::from_components("tcp", "localhost", echo_port).expect("build echo target");

    wait_for_round_trip(
        config.http_port(),
        &provisioner_key,
        echo_target.clone(),
        b"before restart",
    )
    .await
    .expect("forward before restart");
    gateway.kill().await.expect("stop gateway");
    gateway.wait().await.expect("wait for gateway shutdown");
    gateway = start_gateway(config.config_dir());
    wait_for_tcp_port(config.http_port())
        .await
        .expect("restarted gateway http port ready");
    wait_for_round_trip(
        config.http_port(),
        &provisioner_key,
        echo_target.clone(),
        b"after restart",
    )
    .await
    .expect("forward after restart");
    assert_explicit_ip_is_refused(config.http_port(), &provisioner_key, agent_id).await;
    delete_agent(config.http_port(), &provisioner_key, agent_id).await;
    assert_agent_stays_rejected(
        config.http_port(),
        &provisioner_key,
        echo_target.clone(),
        agent_id,
        Duration::from_secs(2),
    )
    .await;

    gateway.kill().await.expect("stop gateway after Agent deletion");
    gateway.wait().await.expect("wait for gateway shutdown");
    gateway = start_gateway(config.config_dir());
    wait_for_tcp_port(config.http_port())
        .await
        .expect("gateway http port ready after Agent deletion");
    assert_agent_stays_rejected(
        config.http_port(),
        &provisioner_key,
        echo_target,
        agent_id,
        Duration::from_secs(2),
    )
    .await;

    agent.kill().await.expect("stop agent");
    gateway.kill().await.expect("stop gateway");
    echo_task.abort();
}

#[tokio::test]
#[ignore = "requires a running Docker daemon"]
async fn docker_isolates_real_agent_dns_and_ip_routes() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("testsuite should have a repository parent")
        .to_owned();
    let docker = DockerEnvironment::create(&repo_root).expect("create Docker environment");
    let provisioner_key = PrivateKey::generate_rsa(2048).expect("generate provisioner key");
    let public_key_data = format!(
        "m{}",
        base64::engine::general_purpose::STANDARD.encode(
            provisioner_key
                .to_public_key()
                .expect("derive provisioner public key")
                .to_der()
                .expect("encode provisioner public key")
        )
    );
    let config = DgwConfig::builder()
        .hostname(DOCKER_GATEWAY_HOST.to_owned())
        .listener_host("0.0.0.0")
        .provisioner_public_key_data(public_key_data)
        .agent_tunnel(AgentTunnelConfig::builder().build())
        .enable_unstable(true)
        .build()
        .init()
        .expect("initialize gateway config");
    let mut gateway = start_gateway(config.config_dir());
    wait_for_tcp_port(config.http_port())
        .await
        .expect("gateway http port ready");

    docker
        .start_target(&docker.dns_agent_ip)
        .expect("start dns target container");
    docker.wait_for_target().expect("wait for dns target container");
    let exact_target =
        TargetAddr::from_components("tcp", DOCKER_EXACT_ROUTE, DOCKER_TARGET_PORT).expect("build exact dns target");
    assert!(
        round_trip(
            config.http_port(),
            &provisioner_key,
            exact_target.clone(),
            None,
            b"must fail without agent"
        )
        .await
        .is_err()
    );

    let dns_agent_name = "docker-dns-agent";
    let dns_token = enrollment_token_file(&provisioner_key, config.http_port(), dns_agent_name);
    docker
        .enroll_agent(
            &docker.dns_volume,
            &docker.dns_agent_ip,
            dns_token.path(),
            "--advertise-domains",
            &format!("{DOCKER_EXACT_ROUTE},{DOCKER_WILDCARD_ROUTE}"),
        )
        .expect("enroll dns-only agent");
    docker
        .start_agent(&docker.dns_agent_container, &docker.dns_volume, &docker.dns_agent_ip)
        .expect("start dns-only agent");
    wait_for_registered_agent(
        config.http_port(),
        &provisioner_key,
        dns_agent_name,
        &[],
        &[DOCKER_EXACT_ROUTE, DOCKER_WILDCARD_ROUTE],
        Duration::from_secs(40),
        || container_logs(&docker.dns_agent_container),
    )
    .await;
    wait_for_round_trip(
        config.http_port(),
        &provisioner_key,
        exact_target.clone(),
        b"exact DNS route",
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "exact dns route failed: {error:#}; agent logs={}; target logs={}",
            container_logs(&docker.dns_agent_container),
            container_logs(&docker.target_container)
        )
    });
    assert_container_running(&docker.target_container);
    let wildcard_target = TargetAddr::from_components("tcp", DOCKER_WILDCARD_TARGET, DOCKER_TARGET_PORT)
        .expect("build wildcard dns target");
    wait_for_round_trip(
        config.http_port(),
        &provisioner_key,
        wildcard_target.clone(),
        b"wildcard DNS route",
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "wildcard dns route failed: {error:#}; agent logs={}; target logs={}",
            container_logs(&docker.dns_agent_container),
            container_logs(&docker.target_container)
        )
    });

    gateway.kill().await.expect("stop gateway");
    gateway.wait().await.expect("wait for gateway shutdown");
    gateway = start_gateway(config.config_dir());
    wait_for_tcp_port(config.http_port())
        .await
        .expect("restarted gateway http port ready");
    wait_for_registered_agent(
        config.http_port(),
        &provisioner_key,
        dns_agent_name,
        &[],
        &[DOCKER_EXACT_ROUTE, DOCKER_WILDCARD_ROUTE],
        Duration::from_secs(150),
        || container_logs(&docker.dns_agent_container),
    )
    .await;
    wait_for_round_trip(
        config.http_port(),
        &provisioner_key,
        wildcard_target,
        b"DNS route after restart",
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "dns route after restart failed: {error:#}; agent logs={}; target logs={}",
            container_logs(&docker.dns_agent_container),
            container_logs(&docker.target_container)
        )
    });

    remove_container(&docker.dns_agent_container);
    remove_container(&docker.target_container);
    docker
        .start_target(&docker.ip_agent_ip)
        .expect("start ip target container");
    docker.wait_for_target().expect("wait for ip target container");
    let ip_target = TargetAddr::from_components("tcp", &docker.target_ip, DOCKER_TARGET_PORT).expect("build ip target");
    assert!(
        round_trip(
            config.http_port(),
            &provisioner_key,
            ip_target.clone(),
            None,
            b"must fail without IP agent"
        )
        .await
        .is_err()
    );

    let ip_agent_name = "docker-ip-agent";
    let ip_route = format!("{}/32", docker.target_ip);
    let ip_token = enrollment_token_file(&provisioner_key, config.http_port(), ip_agent_name);
    docker
        .enroll_agent(
            &docker.ip_volume,
            &docker.ip_agent_ip,
            ip_token.path(),
            "--advertise-subnets",
            &ip_route,
        )
        .expect("enroll ip agent");
    docker
        .start_agent(&docker.ip_agent_container, &docker.ip_volume, &docker.ip_agent_ip)
        .expect("start ip agent");
    wait_for_registered_agent(
        config.http_port(),
        &provisioner_key,
        ip_agent_name,
        &[&ip_route],
        &[],
        Duration::from_secs(40),
        || container_logs(&docker.ip_agent_container),
    )
    .await;
    wait_for_round_trip(config.http_port(), &provisioner_key, ip_target, b"IP route")
        .await
        .unwrap_or_else(|error| {
            panic!(
                "ip route failed: {error:#}; agent logs={}; target logs={}",
                container_logs(&docker.ip_agent_container),
                container_logs(&docker.target_container)
            )
        });

    gateway.kill().await.expect("stop gateway");
}
