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
        let data_dir = create_data_dir()?;
        let pipe_name = format!(
            r"\\.\pipe\Devolutions.Now.PackageBroker.tests.{}.{}",
            std::process::id(),
            fastrand::u64(..)
        );
        let policy_path = data_dir.path().join("policy.json");

        if let Some(policy) = policy {
            std::fs::write(&policy_path, serde_json::to_vec_pretty(policy)?).context("write policy")?;
            secure_policy_path(&policy_path, false)?;
        }

        Self::start_with_path(agent_path, data_dir, pipe_name, policy_path).await
    }

    async fn start_with_path(
        agent_path: &Path,
        data_dir: tempfile::TempDir,
        pipe_name: String,
        policy_path: PathBuf,
    ) -> anyhow::Result<Self> {
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
    redirected_policy_paths_fail_closed(&agent_path).await?;
    management_write_tokens_survive_watcher_reload(&agent_path).await?;

    Ok(())
}

async fn request(pipe_name: &str, method: &str, path: &str) -> anyhow::Result<HttpResponse> {
    request_with_body(pipe_name, method, path, None, &[]).await
}

async fn request_with_body(
    pipe_name: &str,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> anyhow::Result<HttpResponse> {
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

    let content_type = content_type.map_or_else(String::new, |value| format!("Content-Type: {value}\r\n"));
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         {content_type}Content-Length: {}\r\n\r\n",
        body.len()
    );
    pipe.write_all(request.as_bytes()).await.context("write HTTP request")?;
    pipe.write_all(body).await.context("write HTTP request body")?;
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

fn policy_draft(id: &str, publisher: &str) -> Value {
    json!({
        "$schema": "https://devolutions.net/schemas/now-policy-draft.schema.1.0.json",
        "PolicyVersion": "1.0.0",
        "PolicyType": "PackageBrokerPolicy",
        "Metadata": { "Id": id, "Publisher": publisher },
        "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
        "Rules": []
    })
}

fn create_data_dir() -> anyhow::Result<tempfile::TempDir> {
    let program_data = std::env::var_os("ProgramData").context("ProgramData is not defined")?;
    let data_dir = tempfile::Builder::new()
        .prefix("dgw-agent-policy-")
        .tempdir_in(program_data)
        .context("create Agent data directory")?;
    secure_policy_path(data_dir.path(), true)?;
    Ok(data_dir)
}

fn secure_policy_path(path: &Path, directory: bool) -> anyhow::Result<()> {
    let owner_status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/setowner", "*S-1-5-18"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("set policy owner")?;
    ensure!(
        owner_status.success(),
        "setting the policy path owner to LocalSystem failed; run the tester as LocalSystem"
    );

    let system_grant = if directory {
        "*S-1-5-18:(OI)(CI)(F)"
    } else {
        "*S-1-5-18:(F)"
    };
    let administrators_grant = if directory {
        "*S-1-5-32-544:(OI)(CI)(F)"
    } else {
        "*S-1-5-32-544:(F)"
    };
    let dacl_status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", system_grant, administrators_grant])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("set policy DACL")?;
    ensure!(
        dacl_status.success(),
        "failed to set a system-and-administrators-only policy path DACL"
    );

    Ok(())
}

fn grant_users_full_control(path: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/grant:r", "*S-1-5-32-545:(OI)(CI)(F)"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("grant Users control of test directory")?;
    ensure!(status.success(), "failed to make test directory user-controlled");
    Ok(())
}

fn create_junction(link: &Path, target: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("create test junction")?;
    ensure!(status.success(), "failed to create test junction");
    Ok(())
}

async fn assert_redirected_policy_rejected(
    agent_path: &Path,
    data_dir: tempfile::TempDir,
    policy_path: PathBuf,
) -> anyhow::Result<()> {
    let pipe_name = format!(
        r"\\.\pipe\Devolutions.Now.PackageBroker.tests.{}.{}",
        std::process::id(),
        fastrand::u64(..)
    );
    let agent = AgentHarness::start_with_path(agent_path, data_dir, pipe_name, policy_path).await?;
    let management = request(&agent.pipe_name, "GET", "/v1/policy/management")
        .await?
        .json()?;
    ensure!(management["Management"]["State"] == "Invalid");
    ensure!(management["Management"]["WriteCapability"] == "ReadOnly");
    ensure!(management["Management"]["ReadOnlyReason"] == "UnsafePath");
    ensure!(request(&agent.pipe_name, "GET", "/v1/policy").await?.status == 404);

    let replacement = json!({
        "RequestKind": "PolicyReplacementRequest",
        "RequestVersion": "1.0",
        "ExpectedStoreToken": management["Management"]["StoreToken"],
        "Operation": "Repair",
        "ConflictHandling": "Reject",
        "WarningsAcknowledged": false,
        "Draft": full_policy(),
        "ValidationReceipt": "invalid"
    });
    let response = request_with_body(
        &agent.pipe_name,
        "PUT",
        "/v1/policy",
        Some("application/json"),
        &serde_json::to_vec(&replacement)?,
    )
    .await?;
    ensure!(response.json()?["Code"] == "UnsafePolicyPath");
    Ok(())
}

async fn redirected_policy_paths_fail_closed(agent_path: &Path) -> anyhow::Result<()> {
    let data_dir = create_data_dir()?;
    let final_dir = data_dir.path().join("trusted-final");
    let unsafe_dir = data_dir.path().join("unsafe-hop");
    std::fs::create_dir(&final_dir)?;
    std::fs::create_dir(&unsafe_dir)?;
    grant_users_full_control(&unsafe_dir)?;
    let policy = final_dir.join("policy.json");
    std::fs::write(&policy, serde_json::to_vec_pretty(&empty_policy())?)?;
    secure_policy_path(&policy, false)?;
    create_junction(&unsafe_dir.join("hop"), &final_dir)?;
    let outer = data_dir.path().join("PolicyLink");
    create_junction(&outer, &unsafe_dir)?;
    let redirected = outer.join("hop").join("policy.json");
    assert_redirected_policy_rejected(agent_path, data_dir, redirected).await?;

    let data_dir = create_data_dir()?;
    let unsafe_dir = data_dir.path().join("unsafe-hop");
    std::fs::create_dir(&unsafe_dir)?;
    grant_users_full_control(&unsafe_dir)?;
    let target = unsafe_dir.join("policy.json");
    std::fs::write(&target, serde_json::to_vec_pretty(&empty_policy())?)?;
    secure_policy_path(&target, false)?;
    let redirected = data_dir.path().join("policy.json");
    std::os::windows::fs::symlink_file(&target, &redirected).context("create test policy symlink")?;
    assert_redirected_policy_rejected(agent_path, data_dir, redirected).await
}

async fn policy_management(agent: &AgentHarness) -> anyhow::Result<Value> {
    let response = request(&agent.pipe_name, "GET", "/v1/policy/management").await?;
    ensure!(
        response.status == 200,
        "GET /v1/policy/management returned HTTP {}",
        response.status
    );
    Ok(response.json()?["Management"].clone())
}

async fn replace_policy(
    agent: &AgentHarness,
    operation: &str,
    expected_store_token: Value,
    draft: Value,
) -> anyhow::Result<Value> {
    let validation_request = json!({
        "RequestKind": "PolicyValidationRequest",
        "RequestVersion": "1.0",
        "Draft": draft
    });
    let validation_response = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        Some("application/json"),
        &serde_json::to_vec(&validation_request)?,
    )
    .await?;
    ensure!(
        validation_response.status == 200,
        "POST /v1/policy/validate returned HTTP {}",
        validation_response.status
    );
    let validation = validation_response.json()?["Validation"].clone();
    ensure!(validation["IsValid"] == true, "policy validation failed");
    let replacement_request = json!({
        "RequestKind": "PolicyReplacementRequest",
        "RequestVersion": "1.0",
        "ExpectedStoreToken": expected_store_token,
        "Operation": operation,
        "ConflictHandling": "Reject",
        "WarningsAcknowledged": true,
        "Draft": validation["CanonicalDraft"],
        "ValidationReceipt": validation["ValidationReceipt"]
    });
    let response = request_with_body(
        &agent.pipe_name,
        "PUT",
        "/v1/policy",
        Some("application/json"),
        &serde_json::to_vec(&replacement_request)?,
    )
    .await?;
    ensure!(response.status == 200, "{operation} returned HTTP {}", response.status);
    response.json()
}

async fn management_write_tokens_survive_watcher_reload(agent_path: &Path) -> anyhow::Result<()> {
    for verbatim in [false, true] {
        let data_dir = create_data_dir()?;
        let policy_path = data_dir.path().join("policy.json");
        let policy_path = if verbatim {
            PathBuf::from(format!(r"\\?\{}", policy_path.display()))
        } else {
            policy_path
        };
        let pipe_name = format!(
            r"\\.\pipe\Devolutions.Now.PackageBroker.tests.{}.{}",
            std::process::id(),
            fastrand::u64(..)
        );
        let agent = AgentHarness::start_with_path(agent_path, data_dir, pipe_name, policy_path).await?;
        let initial = policy_management(&agent).await?;
        ensure!(initial["State"] == "Missing");
        ensure!(initial["WriteCapability"] == "Writable");

        let created = replace_policy(
            &agent,
            "Create",
            initial["StoreToken"].clone(),
            policy_draft("tests.managed-write", "Test"),
        )
        .await?;
        ensure!(created["Policy"]["Metadata"]["Revision"] == 1);
        let created_token = created["Management"]["StoreToken"].clone();
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure!(
            policy_management(&agent).await?["StoreToken"] == created_token,
            "watcher reload rotated the Create token (verbatim={verbatim})"
        );

        let updated = replace_policy(
            &agent,
            "Update",
            created_token,
            policy_draft("tests.managed-write", "Updated Test"),
        )
        .await?;
        ensure!(updated["Policy"]["Metadata"]["Revision"] == 2);
        let updated_token = updated["Management"]["StoreToken"].clone();
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure!(
            policy_management(&agent).await?["StoreToken"] == updated_token,
            "watcher reload rotated the Update token (verbatim={verbatim})"
        );
    }
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
        response.status == 404,
        "unavailable policy returned HTTP {}",
        response.status
    );
    let error = response.json()?;
    ensure!(error["Code"] == "NotFound", "unexpected unavailable-policy error code");
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

    for method in ["POST", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"] {
        let response = request(&agent.pipe_name, method, "/v1/policy").await?;
        ensure!(
            response.status == 405,
            "{method} /v1/policy returned HTTP {}",
            response.status
        );
    }

    let management = request(&agent.pipe_name, "GET", "/v1/policy/management").await?;
    ensure!(
        management.status == 200,
        "GET /v1/policy/management returned HTTP {}",
        management.status
    );
    ensure!(management.json()?["Management"]["State"] == "Missing");

    for (method, path) in [("POST", "/v1/policy/validate"), ("PUT", "/v1/policy")] {
        let response = request(&agent.pipe_name, method, path).await?;
        ensure!(
            response.status == 415,
            "{method} {path} returned HTTP {}",
            response.status
        );
        ensure!(response.json()?["Code"] == "UnsupportedMediaType");

        let response = request_with_body(&agent.pipe_name, method, path, Some("application/json"), b"{}").await?;
        ensure!(
            response.status == 400,
            "malformed {method} {path} returned HTTP {}",
            response.status
        );
        ensure!(response.json()?["Code"] == "MalformedDraft");
    }

    for (method, path) in [("POST", "/v1/policy/management"), ("GET", "/v1/policy/validate")] {
        let response = request(&agent.pipe_name, method, path).await?;
        ensure!(
            response.status == 405,
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
    let initial_token = policy_management(&agent).await?["StoreToken"].clone();

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
    ensure!(
        policy_management(&agent).await?["StoreToken"] != initial_token,
        "external policy replacement did not rotate the store token"
    );

    replace
        .await
        .context("join policy replacement task")?
        .context("replace policy")?;

    Ok(())
}
