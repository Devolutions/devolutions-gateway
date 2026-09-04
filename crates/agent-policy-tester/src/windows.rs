use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::ClientOptions;

const FULL_POLICY: &str = include_str!("../../now-package-broker/src/assets/samples/corporate-allowlist.policy.json");

struct AgentHarness {
    child: tokio::process::Child,
    _data_dir: tempfile::TempDir,
    pipe_name: String,
    policy_path: PathBuf,
}

impl AgentHarness {
    async fn start(agent_path: &Path, policy: Option<&Value>) -> anyhow::Result<Self> {
        let data_dir = tempfile::tempdir().context("create Agent data directory")?;
        let pipe_name = format!(
            r"\\.\pipe\Devolutions.Now.PackageBroker.tests.{}.{}",
            std::process::id(),
            fastrand::u64(..)
        );
        let policy_path = data_dir.path().join("policy.json");

        if let Some(policy) = policy {
            std::fs::write(&policy_path, serde_json::to_vec_pretty(policy)?).context("write policy")?;
            secure_policy_file(&policy_path)?;
        }

        let config = json!({
            "PackageBroker": {
                "Enabled": true,
                "PipeName": pipe_name,
                "PolicyPath": policy_path,
            },
            "__debug__": {
                "skip_broker_signature_validation": true,
            },
        });
        std::fs::write(data_dir.path().join("agent.json"), serde_json::to_vec_pretty(&config)?)
            .context("write Agent configuration")?;

        let child = tokio::process::Command::new(agent_path)
            .env("DAGENT_CONFIG_PATH", data_dir.path())
            .arg("run")
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("start Devolutions Agent")?;

        let mut harness = Self {
            child,
            _data_dir: data_dir,
            pipe_name,
            policy_path,
        };
        harness.wait_until_ready().await?;

        Ok(harness)
    }

    async fn wait_until_ready(&mut self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);

        loop {
            if let Some(status) = self.child.try_wait().context("query Agent status")? {
                bail!("agent exited before package broker startup with {status}");
            }

            match request(&self.pipe_name, "GET", "/v1/health").await {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(_) | Err(_) if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(50)).await,
                Ok(response) => bail!("agent package broker returned HTTP {}", response.status),
                Err(error) => return Err(error).context("agent package broker did not become ready"),
            }
        }
    }
}

impl Drop for AgentHarness {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> anyhow::Result<Value> {
        serde_json::from_slice(&self.body).context("response body is not valid JSON")
    }
}

pub(crate) async fn run() -> anyhow::Result<()> {
    let agent_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: agent-policy-tester <path-to-devolutions-agent>")?;
    ensure!(
        agent_path.is_file(),
        "agent executable does not exist: {}",
        agent_path.display()
    );

    unavailable_policy_and_method_restrictions(&agent_path).await?;
    complete_snapshots_across_reload(&agent_path).await?;

    Ok(())
}

async fn request(pipe_name: &str, method: &str, path: &str) -> anyhow::Result<HttpResponse> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut pipe = loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(pipe) => break pipe,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error).with_context(|| format!("open named pipe {pipe_name}")),
        }
    };

    let request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    pipe.write_all(request.as_bytes()).await.context("write HTTP request")?;
    pipe.flush().await.context("flush HTTP request")?;

    let mut raw_response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), pipe.read_to_end(&mut raw_response))
        .await
        .context("timed out reading HTTP response")?
        .context("read HTTP response")?;

    parse_response(raw_response)
}

fn parse_response(raw_response: Vec<u8>) -> anyhow::Result<HttpResponse> {
    let header_end = raw_response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("HTTP response has no header terminator")?;
    let headers = std::str::from_utf8(&raw_response[..header_end]).context("HTTP response headers are not UTF-8")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .context("HTTP response has no status")?
        .parse()
        .context("HTTP response status is invalid")?;

    Ok(HttpResponse {
        status,
        body: raw_response[header_end + 4..].to_vec(),
    })
}

fn full_policy() -> Value {
    serde_json::from_str(FULL_POLICY).expect("sample policy is valid JSON")
}

fn empty_policy() -> Value {
    let mut policy = full_policy();
    policy["Metadata"]["Id"] = json!("tests.empty-policy");
    policy["Metadata"]["Revision"] = json!(1);
    policy["Rules"] = json!([]);
    policy
}

fn secure_policy_file(path: &Path) -> anyhow::Result<()> {
    let owner_status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/setowner", "*S-1-5-18"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("set policy owner")?;
    ensure!(
        owner_status.success(),
        "setting the policy owner to LocalSystem failed; run the tester as LocalSystem"
    );

    let dacl_status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("set policy DACL")?;
    ensure!(
        dacl_status.success(),
        "failed to set a system-and-administrators-only policy DACL"
    );

    Ok(())
}

async fn unavailable_policy_and_method_restrictions(agent_path: &Path) -> anyhow::Result<()> {
    let agent = AgentHarness::start(agent_path, None).await?;

    for path in ["/v1/health", "/v1/capabilities"] {
        let response = request(&agent.pipe_name, "GET", path).await?;
        ensure!(response.status == 200, "{path} returned HTTP {}", response.status);
    }

    let response = request(&agent.pipe_name, "GET", "/v1/policy").await?;
    ensure!(
        response.status == 503,
        "unavailable policy returned HTTP {}",
        response.status
    );
    let error = response.json()?;
    ensure!(
        error["Code"] == "BrokerPaused",
        "unexpected unavailable-policy error code"
    );
    ensure!(
        error["Message"] == "active policy is unavailable",
        "unexpected unavailable-policy error message"
    );
    ensure!(
        error["Details"].is_null(),
        "unavailable-policy error details are not null"
    );
    ensure!(
        error.get("Policy").is_none(),
        "unavailable-policy response exposed a policy"
    );

    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"] {
        let response = request(&agent.pipe_name, method, "/v1/policy").await?;
        ensure!(
            response.status == 405,
            "{method} /v1/policy returned HTTP {}",
            response.status
        );
    }

    for (method, path) in [("GET", "/v1/policy/management"), ("POST", "/v1/policy/validate")] {
        let response = request(&agent.pipe_name, method, path).await?;
        ensure!(
            response.status == 404,
            "{method} {path} returned HTTP {}",
            response.status
        );
    }

    let response = request(&agent.pipe_name, "GET", "/v1/not-a-route").await?;
    ensure!(
        response.status == 404,
        "unknown route returned HTTP {}",
        response.status
    );

    Ok(())
}

async fn complete_snapshots_across_reload(agent_path: &Path) -> anyhow::Result<()> {
    let empty = empty_policy();
    let agent = AgentHarness::start(agent_path, Some(&empty)).await?;

    let initial = request(&agent.pipe_name, "GET", "/v1/policy").await?;
    ensure!(initial.status == 200, "active policy returned HTTP {}", initial.status);
    let initial = initial.json()?;
    ensure!(
        initial["ResponseKind"] == "PolicyResponse",
        "unexpected policy response kind"
    );
    ensure!(
        initial["ResponseVersion"] == "1.0",
        "unexpected policy response version"
    );
    ensure!(
        initial["Server"]["Transport"] == "HttpNamedPipe",
        "unexpected policy response transport"
    );
    ensure!(
        initial["Policy"] == empty,
        "initial policy response does not match the empty policy"
    );

    let head = request(&agent.pipe_name, "HEAD", "/v1/policy").await?;
    ensure!(head.status == 200, "HEAD /v1/policy returned HTTP {}", head.status);
    ensure!(head.body.is_empty(), "HEAD /v1/policy returned a body");

    let full = full_policy();
    let replacement_path = agent.policy_path.clone();
    let replacement = serde_json::to_vec_pretty(&full)?;
    let replace = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(25));
        std::fs::write(replacement_path, replacement)
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = request(&agent.pipe_name, "GET", "/v1/policy").await?;
        ensure!(
            response.status == 200,
            "policy reload returned HTTP {}",
            response.status
        );
        let response = response.json()?;
        let policy = &response["Policy"];
        ensure!(
            policy == &empty || policy == &full,
            "response contained a partial policy snapshot"
        );
        if policy == &full {
            break;
        }
        ensure!(Instant::now() < deadline, "agent did not reload the policy");
        tokio::task::yield_now().await;
    }

    replace
        .await
        .context("join policy replacement task")?
        .context("replace policy")?;

    Ok(())
}
