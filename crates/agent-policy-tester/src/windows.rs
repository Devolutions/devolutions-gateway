use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::ClientOptions;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY, WinBuiltinAdministratorsSid, WinLocalSystemSid};

const FULL_POLICY: &str = include_str!("../../now-package-broker/src/assets/samples/corporate-allowlist.policy.json");
const MANAGED_POLICY_RELATIVE_PATH: &str = r"Devolutions\PackageBroker\package-broker-policy.json";
const MANAGED_AUTHORITY_MARKER: &str = r"Devolutions\PackageBroker\.package-broker-managed-authority.v1";
const LEGACY_POLICY_RELATIVE_PATH: &str = r"Devolutions\Agent\package-broker-policy.json";

struct AgentHarness {
    child: tokio::process::Child,
    data_dir: tempfile::TempDir,
    pipe_name: String,
    policy_path: PathBuf,
    program_data: Option<PathBuf>,
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

    async fn start_unelevated(agent_path: &Path) -> anyhow::Result<Self> {
        let data_dir = tempfile::tempdir().context("create unelevated Agent data directory")?;
        let pipe_name = unique_pipe_name();
        let policy_path = data_dir.path().join("policy.json");
        Self::start_with_options(agent_path, data_dir, pipe_name, policy_path, false).await
    }

    async fn start_managed_default(agent_path: &Path) -> anyhow::Result<Self> {
        let data_dir = create_data_dir()?;
        let pipe_name = unique_pipe_name();
        let policy_path = data_dir.path().join(MANAGED_POLICY_RELATIVE_PATH);
        Self::start_with_options(agent_path, data_dir, pipe_name, policy_path, true).await
    }

    async fn start_with_path(
        agent_path: &Path,
        data_dir: tempfile::TempDir,
        pipe_name: String,
        policy_path: PathBuf,
    ) -> anyhow::Result<Self> {
        Self::start_with_options(agent_path, data_dir, pipe_name, policy_path, false).await
    }

    async fn start_with_options(
        agent_path: &Path,
        data_dir: tempfile::TempDir,
        pipe_name: String,
        policy_path: PathBuf,
        use_managed_default: bool,
    ) -> anyhow::Result<Self> {
        let policy_path_config = (!use_managed_default).then_some(&policy_path);
        let config = json!({
            "LogFile": data_dir.path().join("agent-e2e"),
            "PackageBroker": {
                "Enabled": true,
                "PipeName": pipe_name,
                "PolicyPath": policy_path_config,
            },
            "__debug__": {
                "skip_broker_signature_validation": true,
            },
        });
        std::fs::write(data_dir.path().join("agent.json"), serde_json::to_vec_pretty(&config)?)
            .context("write Agent configuration")?;

        let program_data = use_managed_default.then(|| data_dir.path().to_owned());
        let child = Self::spawn(agent_path, data_dir.path(), program_data.as_deref())?;

        let mut harness = Self {
            child,
            data_dir,
            pipe_name,
            policy_path,
            program_data,
        };
        harness.wait_until_ready().await?;

        Ok(harness)
    }

    fn spawn(agent_path: &Path, data_dir: &Path, program_data: Option<&Path>) -> anyhow::Result<tokio::process::Child> {
        let mut command = tokio::process::Command::new(agent_path);
        command
            .env("DAGENT_CONFIG_PATH", data_dir)
            .arg("run")
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(program_data) = program_data {
            command.env("ProgramData", program_data);
        }
        command.spawn().context("start Devolutions Agent")
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

    async fn restart(&mut self, agent_path: &Path) -> anyhow::Result<()> {
        self.stop().await?;
        self.start_again(agent_path).await
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.child.start_kill().context("stop Devolutions Agent")?;
        self.child.wait().await.context("wait for Devolutions Agent to stop")?;
        Ok(())
    }

    async fn start_again(&mut self, agent_path: &Path) -> anyhow::Result<()> {
        self.child = Self::spawn(agent_path, self.data_dir.path(), self.program_data.as_deref())?;
        self.wait_until_ready().await
    }

    fn logs(&self) -> anyhow::Result<String> {
        let mut logs = String::new();
        for entry in std::fs::read_dir(self.data_dir.path()).context("read Agent log directory")? {
            let entry = entry.context("read Agent log entry")?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("agent-e2e") {
                logs.push_str(&std::fs::read_to_string(entry.path()).context("read Agent log")?);
            }
        }
        Ok(logs)
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unelevated,
    Elevated,
}

impl Mode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "unelevated" => Ok(Self::Unelevated),
            "elevated" => Ok(Self::Elevated),
            _ => bail!("unknown mode '{value}'; expected 'unelevated' or 'elevated'"),
        }
    }
}

pub(crate) async fn run() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let agent_path = args
        .next()
        .map(PathBuf::from)
        .context("usage: agent-policy-tester <path-to-devolutions-agent> <unelevated|elevated>")?;
    let mode = args
        .next()
        .and_then(|value| value.into_string().ok())
        .context("test mode must be 'unelevated' or 'elevated'")
        .and_then(|value| Mode::parse(&value))?;
    ensure!(args.next().is_none(), "unexpected extra command-line arguments");
    verify_process_token(mode)?;
    ensure!(
        agent_path.is_file(),
        "agent executable does not exist: {}",
        agent_path.display()
    );

    match mode {
        Mode::Unelevated => standard_user_management(&agent_path).await?,
        Mode::Elevated => {
            unavailable_policy_and_method_restrictions(&agent_path).await?;
            complete_snapshots_across_reload(&agent_path).await?;
            redirected_policy_paths_fail_closed(&agent_path).await?;
            management_write_tokens_survive_watcher_reload(&agent_path).await?;
            managed_policy_lifecycle(&agent_path).await?;
        }
    }

    Ok(())
}

fn verify_process_token(mode: Mode) -> anyhow::Result<()> {
    let token = Process::current_process()
        .token(TOKEN_QUERY | TOKEN_DUPLICATE)
        .context("open tester process token")?;
    let administrators =
        Sid::from_well_known(WinBuiltinAdministratorsSid, None).context("construct Administrators SID")?;
    let is_administrator = token
        .is_member(&administrators)
        .context("query tester Administrators membership")?;
    let system = Sid::from_well_known(WinLocalSystemSid, None).context("construct LocalSystem SID")?;
    let user = token.sid_and_attributes().context("query tester user SID")?.sid;
    match mode {
        Mode::Unelevated => {
            ensure!(user != system, "unelevated mode requires a standard user account");
            ensure!(
                !is_administrator,
                "unelevated mode requires disabled Administrators membership"
            );
        }
        Mode::Elevated => {
            ensure!(is_administrator, "elevated mode requires Administrators membership");
            ensure!(
                token.is_elevated().context("query tester token elevation")?,
                "elevated mode requires an elevated token"
            );
            ensure!(user == system, "elevated mode requires the LocalSystem account");
        }
    }
    Ok(())
}

fn unique_pipe_name() -> String {
    format!(
        r"\\.\pipe\Devolutions.Now.PackageBroker.tests.{}.{}",
        std::process::id(),
        fastrand::u64(..)
    )
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

async fn validate_policy(agent: &AgentHarness, draft: &Value) -> anyhow::Result<Value> {
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
    Ok(validation)
}

async fn replace_policy_response(
    agent: &AgentHarness,
    operation: &str,
    conflict_handling: &str,
    expected_store_token: Value,
    draft: Value,
) -> anyhow::Result<HttpResponse> {
    let validation = validate_policy(agent, &draft).await?;
    let replacement_request = json!({
        "RequestKind": "PolicyReplacementRequest",
        "RequestVersion": "1.0",
        "ExpectedStoreToken": expected_store_token,
        "Operation": operation,
        "ConflictHandling": conflict_handling,
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
    Ok(response)
}

async fn replace_policy(
    agent: &AgentHarness,
    operation: &str,
    expected_store_token: Value,
    draft: Value,
) -> anyhow::Result<Value> {
    let response = replace_policy_response(agent, operation, "Reject", expected_store_token, draft).await?;
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

async fn standard_user_management(agent_path: &Path) -> anyhow::Result<()> {
    let agent = AgentHarness::start_unelevated(agent_path).await?;
    let management = policy_management(&agent).await?;
    ensure!(management["State"] == "Missing", "expected a missing policy");

    let valid_draft = policy_draft("tests.standard-user", "Test");
    let validation = validate_policy(&agent, &valid_draft).await?;
    ensure!(
        validation["CanonicalDraft"].is_object() && validation["ValidationReceipt"].is_string(),
        "valid draft did not produce a canonical draft and receipt"
    );

    let mut invalid_draft = valid_draft.clone();
    invalid_draft["$schema"] = json!("https://example.com/not-the-policy-draft-schema.json");
    let invalid_request = json!({
        "RequestKind": "PolicyValidationRequest",
        "RequestVersion": "1.0",
        "Draft": invalid_draft
    });
    let invalid_response = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        Some("application/json"),
        &serde_json::to_vec(&invalid_request)?,
    )
    .await?;
    ensure!(
        invalid_response.status == 200,
        "invalid draft validation returned HTTP {}",
        invalid_response.status
    );
    let invalid_validation = invalid_response.json()?["Validation"].clone();
    ensure!(invalid_validation["IsValid"] == false, "invalid draft was accepted");
    ensure!(
        invalid_validation.get("CanonicalDraft").is_none(),
        "invalid draft returned a canonical draft"
    );

    let denied = replace_policy_response(
        &agent,
        "Create",
        "Reject",
        management["StoreToken"].clone(),
        valid_draft,
    )
    .await?;
    ensure!(
        denied.status == 403,
        "standard-user Create returned HTTP {}",
        denied.status
    );
    ensure!(
        denied.json()?["Code"] == "AdministratorRequired",
        "standard-user Create did not require an administrator"
    );
    wait_for_log(&agent, "Policy management write denied").await
}

async fn managed_policy_lifecycle(agent_path: &Path) -> anyhow::Result<()> {
    let mut agent = AgentHarness::start_managed_default(agent_path).await?;
    let initial = policy_management(&agent).await?;
    ensure!(
        initial["State"] == "Missing",
        "managed policy was not initially missing"
    );
    ensure!(
        initial["Source"] == "DefaultPath" && initial["WriteCapability"] == "Writable",
        "isolated managed default path was not writable"
    );

    let created = replace_policy(
        &agent,
        "Create",
        initial["StoreToken"].clone(),
        policy_draft("tests.managed-lifecycle", "Create"),
    )
    .await?;
    ensure!(
        created["Policy"]["Metadata"]["Revision"] == 1,
        "Create did not assign revision 1"
    );
    let authority_marker = agent.data_dir.path().join(MANAGED_AUTHORITY_MARKER);
    ensure!(
        authority_marker.is_file() && std::fs::metadata(&authority_marker)?.len() == 0,
        "Create did not establish durable managed authority"
    );
    wait_for_log(&agent, "Policy creation succeeded").await?;

    let updated = replace_policy(
        &agent,
        "Update",
        created["Management"]["StoreToken"].clone(),
        policy_draft("tests.managed-lifecycle", "Update"),
    )
    .await?;
    ensure!(
        updated["Policy"]["Metadata"]["Revision"] == 2,
        "Update did not increment the revision"
    );

    let secret = "malformed-policy-secret-marker";
    std::fs::write(&agent.policy_path, format!(r#"{{"unterminated":"{secret}"#))
        .context("write malformed external policy")?;
    let invalid = wait_for_management(&agent, |management| management["State"] == "Invalid").await?;
    let diagnostics = &invalid["InvalidDiagnostics"];
    ensure!(
        diagnostics["Findings"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty()),
        "invalid policy did not produce diagnostics"
    );
    ensure!(
        !diagnostics.to_string().contains(secret),
        "invalid policy diagnostics exposed file contents"
    );
    wait_for_log(&agent, "External policy change rejected").await?;

    let repaired = replace_policy(
        &agent,
        "Repair",
        invalid["StoreToken"].clone(),
        policy_draft("tests.managed-repaired", "Repair"),
    )
    .await?;
    ensure!(
        repaired["Policy"]["Metadata"]["Revision"] == 1,
        "Repair did not assign revision 1"
    );

    let stale_token = repaired["Management"]["StoreToken"].clone();
    let mut external = empty_policy();
    external["Metadata"]["Id"] = json!("tests.managed-external");
    std::fs::write(&agent.policy_path, serde_json::to_vec_pretty(&external)?).context("write valid external policy")?;
    wait_for_management(&agent, |management| {
        management["Policy"]["Metadata"]["Id"] == "tests.managed-external"
    })
    .await?;
    wait_for_log(&agent, "External policy change applied").await?;

    let stale = replace_policy_response(
        &agent,
        "Update",
        "Reject",
        stale_token,
        policy_draft("tests.managed-external", "Stale"),
    )
    .await?;
    ensure!(stale.status == 409, "stale Update returned HTTP {}", stale.status);
    let stale = stale.json()?;
    ensure!(
        stale["Code"] == "StalePolicyStoreToken"
            && stale["Management"]["Policy"]["Metadata"]["Id"] == "tests.managed-external",
        "stale Update did not return the current policy snapshot"
    );
    wait_for_log(&agent, "stale_conflict").await?;

    let current_token = stale["Management"]["StoreToken"].clone();
    let confirmed = replace_policy_response(
        &agent,
        "Update",
        "ConfirmOverwrite",
        current_token.clone(),
        policy_draft("tests.managed-external", "Confirmed overwrite"),
    )
    .await?;
    ensure!(
        confirmed.status == 200,
        "exact ConfirmOverwrite returned HTTP {}",
        confirmed.status
    );
    let confirmed = confirmed.json()?;
    ensure!(
        confirmed["Policy"]["Metadata"]["Revision"] == 2,
        "confirmed Update did not increment the external policy revision"
    );
    wait_for_log(&agent, "confirmed_overwrite").await?;

    let reused = replace_policy_response(
        &agent,
        "Update",
        "ConfirmOverwrite",
        current_token,
        policy_draft("tests.managed-external", "Reused token"),
    )
    .await?;
    ensure!(
        reused.status == 409 && reused.json()?["Code"] == "StalePolicyStoreToken",
        "reused ConfirmOverwrite token did not conflict"
    );

    agent.restart(agent_path).await?;
    let restarted = request(&agent.pipe_name, "GET", "/v1/policy").await?;
    ensure!(
        restarted.status == 200,
        "policy read after restart returned HTTP {}",
        restarted.status
    );
    ensure!(
        restarted.json()?["Policy"] == confirmed["Policy"],
        "restart changed the active managed policy"
    );
    ensure!(
        authority_marker.is_file() && policy_management(&agent).await?["Source"] == "DefaultPath",
        "restart lost durable managed authority"
    );

    agent.stop().await?;
    let legacy_path = agent.data_dir.path().join(LEGACY_POLICY_RELATIVE_PATH);
    let legacy_dir = legacy_path.parent().context("legacy policy path has no parent")?;
    std::fs::create_dir_all(legacy_dir).context("create isolated legacy policy directory")?;
    secure_policy_path(legacy_dir, true)?;
    std::fs::write(&legacy_path, serde_json::to_vec_pretty(&empty_policy())?)
        .context("write isolated legacy policy")?;
    secure_policy_path(&legacy_path, false)?;
    std::fs::remove_file(&agent.policy_path).context("remove managed policy before authority restart")?;
    agent.start_again(agent_path).await?;
    let authority = policy_management(&agent).await?;
    ensure!(
        authority["State"] == "Missing" && authority["Source"] == "DefaultPath",
        "durable managed authority allowed legacy policy rollback"
    );
    ensure!(
        request(&agent.pipe_name, "GET", "/v1/policy").await?.status == 404,
        "legacy policy became active after managed authority was established"
    );
    Ok(())
}

async fn wait_for_management(agent: &AgentHarness, predicate: impl Fn(&Value) -> bool) -> anyhow::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let management = policy_management(agent).await?;
        if predicate(&management) {
            return Ok(management);
        }
        ensure!(Instant::now() < deadline, "timed out waiting for policy state");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_log(agent: &AgentHarness, expected: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if agent.logs()?.contains(expected) {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "Agent log did not contain '{expected}'");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
