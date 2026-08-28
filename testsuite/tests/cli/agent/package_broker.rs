use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use serde_json::{Value, json};
use testsuite::cli::agent_tokio_cmd;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::ClientOptions;

const FULL_POLICY: &str =
    include_str!("../../../../crates/now-package-broker/src/assets/samples/corporate-allowlist.policy.json");

struct AgentHarness {
    child: tokio::process::Child,
    _data_dir: tempfile::TempDir,
    pipe_name: String,
    policy_path: PathBuf,
}

impl AgentHarness {
    async fn start(policy: Option<&Value>) -> anyhow::Result<Option<Self>> {
        let data_dir = tempfile::tempdir().context("create Agent data directory")?;
        let pipe_name = format!(
            r"\\.\pipe\Devolutions.Now.PackageBroker.tests.{}.{}",
            std::process::id(),
            fastrand::u64(..)
        );
        let policy_path = data_dir.path().join("policy.json");

        if let Some(policy) = policy {
            std::fs::write(&policy_path, serde_json::to_vec_pretty(policy)?).context("write policy")?;
            if !secure_policy_file(&policy_path)? {
                return Ok(None);
            }
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

        let child = agent_tokio_cmd()
            .env("DAGENT_CONFIG_PATH", data_dir.path())
            .arg("run")
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("start Devolutions Agent")?;

        let harness = Self {
            child,
            _data_dir: data_dir,
            pipe_name,
            policy_path,
        };
        harness.wait_until_ready().await?;

        Ok(Some(harness))
    }

    async fn wait_until_ready(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);

        loop {
            match request(&self.pipe_name, "GET", "/v1/health").await {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(_) | Err(_) if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(50)).await,
                Ok(response) => bail!("Agent package broker returned HTTP {}", response.status),
                Err(error) => return Err(error).context("Agent package broker did not become ready"),
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
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response body is valid JSON")
    }
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

fn secure_policy_file(path: &Path) -> anyhow::Result<bool> {
    let dacl_status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("set policy DACL")?;
    if !dacl_status.success() {
        bail!("failed to set an admin-only policy DACL");
    }

    let owner_status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/setowner", "*S-1-5-32-544"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("set policy owner")?;
    if !owner_status.success() {
        eprintln!("Skipping active-policy E2E test: setting an administrator owner requires an elevated test process");
        return Ok(false);
    }

    Ok(true)
}

#[tokio::test]
async fn policy_endpoint_reports_unavailable_policy_and_rejects_other_methods() {
    let Some(agent) = AgentHarness::start(None).await.expect("start Agent") else {
        unreachable!("an unavailable policy needs no privileged setup");
    };

    for path in ["/v1/health", "/v1/capabilities"] {
        assert_eq!(request(&agent.pipe_name, "GET", path).await.unwrap().status, 200);
    }

    let response = request(&agent.pipe_name, "GET", "/v1/policy").await.unwrap();
    assert_eq!(response.status, 503);
    let error = response.json();
    assert_eq!(error["Code"], "BrokerPaused");
    assert_eq!(error["Message"], "active policy is unavailable");
    assert!(error["Details"].is_null());
    assert!(error.get("Policy").is_none());

    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"] {
        assert_eq!(
            request(&agent.pipe_name, method, "/v1/policy").await.unwrap().status,
            405,
            "unexpected status for {method}"
        );
    }
    assert_eq!(
        request(&agent.pipe_name, "GET", "/v1/not-a-route")
            .await
            .unwrap()
            .status,
        404
    );
}

#[tokio::test]
async fn policy_endpoint_serves_complete_snapshots_across_reload() {
    let empty = empty_policy();
    let Some(agent) = AgentHarness::start(Some(&empty)).await.expect("start Agent") else {
        return;
    };

    let initial = request(&agent.pipe_name, "GET", "/v1/policy").await.unwrap();
    assert_eq!(initial.status, 200);
    let initial = initial.json();
    assert_eq!(initial["ResponseKind"], "PolicyResponse");
    assert_eq!(initial["ResponseVersion"], "1.0");
    assert_eq!(initial["Server"]["Transport"], "HttpNamedPipe");
    assert_eq!(initial["Policy"], empty);

    let head = request(&agent.pipe_name, "HEAD", "/v1/policy").await.unwrap();
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());

    let full = full_policy();
    let replacement_path = agent.policy_path.clone();
    let replacement = serde_json::to_vec_pretty(&full).unwrap();
    let replace = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(25));
        std::fs::write(replacement_path, replacement)
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = request(&agent.pipe_name, "GET", "/v1/policy").await.unwrap();
        assert_eq!(response.status, 200);
        let response = response.json();
        let policy = &response["Policy"];
        assert!(
            policy == &empty || policy == &full,
            "response contained a partial policy snapshot"
        );
        if policy == &full {
            break;
        }
        assert!(Instant::now() < deadline, "Agent did not reload the policy");
        tokio::task::yield_now().await;
    }
    replace.await.unwrap().unwrap();
}
