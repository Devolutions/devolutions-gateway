use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use now_policy_server_template::{MAX_POLICY_MANAGEMENT_BODY_BYTES, MAX_REQUEST_BODY_BYTES};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::ClientOptions;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY, WinBuiltinAdministratorsSid};

const FULL_POLICY: &str = include_str!("../../now-package-broker/src/assets/samples/corporate-allowlist.policy.json");
const POLICY_DRAFT_SCHEMA_URI: &str = "https://devolutions.net/schemas/now-policy-draft.schema.1.0.json";

/// The Agent's test data/config directory (also hosting `PolicyPath`), materialized
/// differently depending on [`Mode`] (item 23).
///
/// `Mode::Unelevated` uses an ordinary, non-privileged temporary directory: never
/// touching anything privilege-sensitive, and (see
/// [`unelevated_management_and_validation_succeed_put_requires_administrator`])
/// deliberately owned by the current, non-admin test user, so it correctly fails the
/// store's own custom-directory security check.
///
/// `Mode::Elevated` instead creates a real, uniquely-named directory secured
/// SYSTEM/Administrators-only (see [`SecureTestDir`]), matching the strict bar the real
/// policy store enforces (`verify_policy_directory_security`): without this, every
/// elevated-mode test that expects a real `Active`/`Writable` observation would instead
/// see the store correctly (but unhelpfully, for testing) refuse an ordinary,
/// non-admin-owned temp directory.
enum TestHostDir {
    Unelevated(tempfile::TempDir),
    Elevated(SecureTestDir),
}

impl TestHostDir {
    fn create(mode: Mode) -> anyhow::Result<Self> {
        match mode {
            Mode::Unelevated => Ok(Self::Unelevated(
                tempfile::tempdir().context("create Agent data directory")?,
            )),
            Mode::Elevated => Ok(Self::Elevated(SecureTestDir::create()?)),
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::Unelevated(dir) => dir.path(),
            Self::Elevated(dir) => &dir.path,
        }
    }
}

/// RAII guard for a uniquely-named directory under
/// `%ProgramData%\Devolutions\PackageBroker\tests`, secured SYSTEM/Administrators-only
/// (owner and DACL) before any policy file is ever created inside it, so the real policy
/// store's own directory-security check (`verify_policy_directory_security`) is
/// genuinely satisfied rather than run against an ordinary user-owned temp directory
/// that could never pass it under `LocalSystem`.
///
/// Only used in `Mode::Elevated` (see [`TestHostDir`]): the tester process itself runs
/// as `LocalSystem` there (see `run-as-system.ps1`), which is exactly the identity that
/// needs `admin_only_security_attributes`-equivalent access to both secure and later
/// clean up this directory.
struct SecureTestDir {
    path: PathBuf,
}

impl SecureTestDir {
    fn create() -> anyhow::Result<Self> {
        let program_data = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let root = program_data.join("Devolutions").join("PackageBroker").join("tests");
        std::fs::create_dir_all(&root).context("create the test-host root directory")?;

        let path = root.join(format!("{}-{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir(&path).context("create the unique per-run test-host directory")?;

        // Owner must be a trusted principal (`verify_policy_directory_security`):
        // SYSTEM, the same identity the real Agent service runs as in production.
        let owner_status = std::process::Command::new("icacls.exe")
            .arg(&path)
            .args(["/setowner", "*S-1-5-18"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("set the test-host directory owner")?;
        ensure!(
            owner_status.success(),
            "setting the test-host directory owner to LocalSystem failed; run the tester as LocalSystem"
        );

        // Break inheritance and grant SYSTEM/Administrators-only full control (the same
        // admin-only bar `verify_policy_directory_security` enforces on the real policy
        // directory): no other principal may create, rename, or delete entries, or
        // rewrite the directory's own security descriptor. `(OI)(CI)` so the policy file
        // subsequently created inside inherits the same admin-only grant.
        let dacl_status = std::process::Command::new("icacls.exe")
            .arg(&path)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("set the test-host directory DACL")?;
        ensure!(
            dacl_status.success(),
            "failed to set a system-and-administrators-only test-host directory DACL"
        );

        Ok(Self { path })
    }
}

impl Drop for SecureTestDir {
    fn drop(&mut self) {
        // Best-effort cleanup. The directory (and the policy file created inside it,
        // separately owned by SYSTEM via `secure_policy_file`) grants SYSTEM full
        // control, and this process itself runs as SYSTEM in `Mode::Elevated` (see
        // `run-as-system.ps1`), so removal is expected to succeed regardless of which of
        // the two admin-only owners a given entry happens to carry. A leftover
        // directory here would not corrupt any later run, since each run gets its own
        // uniquely-named directory, but is still cleaned up so repeated runs do not
        // accumulate stale directories under ProgramData.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct AgentHarness {
    child: tokio::process::Child,
    data_dir: TestHostDir,
    pipe_name: String,
    policy_path: PathBuf,
}

impl AgentHarness {
    async fn start(agent_path: &Path, mode: Mode, policy: Option<&Value>) -> anyhow::Result<Self> {
        Self::start_with_file_name(agent_path, mode, "policy.json", policy).await
    }

    /// Same as [`Self::start`], but configures `PolicyPath` with the given file name
    /// instead of the fixed `policy.json` used everywhere else: used to exercise the
    /// store's extension-based format rejection/acceptance (item 18/31), which the fixed
    /// name can never itself trigger either way.
    async fn start_with_file_name(
        agent_path: &Path,
        mode: Mode,
        file_name: &str,
        policy: Option<&Value>,
    ) -> anyhow::Result<Self> {
        let data_dir = TestHostDir::create(mode)?;
        let pipe_name = format!(
            r"\\.\pipe\Devolutions.Now.PackageBroker.tests.{}.{}",
            std::process::id(),
            fastrand::u64(..)
        );
        let policy_path = data_dir.path().join(file_name);

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

        let child = Self::spawn(agent_path, data_dir.path())?;

        let mut harness = Self {
            child,
            data_dir,
            pipe_name,
            policy_path,
        };
        harness.wait_until_ready().await?;

        Ok(harness)
    }

    fn spawn(agent_path: &Path, data_dir: &Path) -> anyhow::Result<tokio::process::Child> {
        tokio::process::Command::new(agent_path)
            .env("DAGENT_CONFIG_PATH", data_dir)
            .arg("run")
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("start Devolutions Agent")
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

    /// Stop the Agent process and start a fresh one against the exact same data
    /// directory (configuration and policy file untouched), reusing the same pipe name.
    /// Used to prove a policy survives an Agent restart (item 23).
    async fn restart(&mut self, agent_path: &Path) -> anyhow::Result<()> {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        self.child = Self::spawn(agent_path, self.data_dir.path())?;
        self.wait_until_ready().await
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

/// Test mode, matching whether the *tester process itself* is running elevated/as
/// SYSTEM (item 23): the two modes exercise disjoint, non-contradictory assertions, so
/// unlike a single suite that assumed a specific privilege level, either mode is correct
/// for the process it actually runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The tester process itself is an ordinary, unelevated, non-SYSTEM token: policy
    /// writes (`PUT /v1/policy`) must be denied with `AdministratorRequired`, but
    /// inspection/validation must still fully succeed.
    Unelevated,
    /// The tester process itself is elevated/SYSTEM (see `run-as-system.ps1`): the full
    /// write lifecycle can be exercised end-to-end.
    Elevated,
}

impl Mode {
    fn parse(raw: Option<&str>) -> anyhow::Result<Self> {
        match raw {
            None | Some("unelevated") => Ok(Self::Unelevated),
            Some("elevated") => Ok(Self::Elevated),
            Some(other) => bail!("unknown mode '{other}'; expected 'unelevated' or 'elevated'"),
        }
    }
}

pub(crate) async fn run() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let agent_path = args
        .next()
        .map(PathBuf::from)
        .context("usage: agent-policy-tester <path-to-devolutions-agent> [unelevated|elevated]")?;
    let mode_arg = args.next();
    let mode = Mode::parse(mode_arg.as_deref().and_then(|arg| arg.to_str()))?;
    verify_process_token(mode)?;

    ensure!(
        agent_path.is_file(),
        "agent executable does not exist: {}",
        agent_path.display()
    );

    match mode {
        Mode::Unelevated => {
            // Neither of these touches anything privilege-sensitive: no policy file is
            // ever pre-seeded with an admin-only ACL, and the unelevated PUT assertion
            // specifically requires this process to *not* be elevated/SYSTEM, unlike the
            // contradictory assertion that resulted from running everything as SYSTEM
            // (item 23).
            unavailable_policy_and_method_restrictions(&agent_path).await?;
            unelevated_management_and_validation_succeed_put_requires_administrator(&agent_path).await?;
            // `POST /v1/policy/validate` requires no special privilege either way, so
            // the policy-management body-size limit is exercised unelevated.
            policy_management_body_size_limits(&agent_path).await?;
        }
        Mode::Elevated => {
            // Both of these seed/replace the policy file's own owner/ACL (via
            // `secure_policy_file`, which sets the owner to LocalSystem), which requires
            // an elevated/SYSTEM token; see `run-as-system.ps1`.
            complete_snapshots_across_reload(&agent_path).await?;
            elevated_policy_lifecycle(&agent_path).await?;
            // Both of these issue a `PUT /v1/policy` and so require an elevated,
            // Administrators-member token to ever reach the store's write-capability
            // check at all (see `unelevated_management_and_validation_succeed_put_requires_administrator`,
            // which proves the unelevated half of that gate): an unelevated caller would
            // be rejected with `AdministratorRequired` before the configured path's
            // format is ever considered, masking exactly what these prove (item 18/31).
            unsupported_configured_path_format_is_rejected(&agent_path).await?;
            uppercase_json_extension_is_active_and_writable(&agent_path).await?;
        }
    }

    Ok(())
}

fn verify_process_token(mode: Mode) -> anyhow::Result<()> {
    if mode != Mode::Unelevated {
        return Ok(());
    }

    let token = Process::current_process()
        .token(TOKEN_QUERY | TOKEN_DUPLICATE)
        .context("open tester process token")?;
    let is_elevated = token.is_elevated().context("query tester token elevation")?;
    let administrators =
        Sid::from_well_known(WinBuiltinAdministratorsSid, None).context("construct built-in Administrators SID")?;
    let is_administrator = token
        .is_member(&administrators)
        .context("query tester Administrators membership")?;
    // PsExec -l disables the Administrators group and lowers integrity, but Windows may
    // retain TokenElevation from the source token. Match the server's real authorization
    // rule instead of treating that informational flag alone as write authority.
    ensure!(
        !is_administrator,
        "unelevated test mode requires Administrators membership to be disabled"
    );
    ensure!(
        !(is_elevated && is_administrator),
        "unelevated test mode must not satisfy the policy-write authorization gate"
    );

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

/// Same as [`request`], but sends `body` as a JSON payload (`Content-Type: application/json`),
/// for the management endpoints that require a request body.
async fn request_with_body(pipe_name: &str, method: &str, path: &str, body: &Value) -> anyhow::Result<HttpResponse> {
    let payload = serde_json::to_vec(body).context("serialize request body")?;

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

    let header = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    pipe.write_all(header.as_bytes())
        .await
        .context("write HTTP request header")?;
    pipe.write_all(&payload).await.context("write HTTP request body")?;
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

/// Convert a committed policy document's JSON into an equivalent editable draft: a draft
/// omits the server-assigned `Revision` and `PublishedAt` metadata fields.
fn draft_from(policy: &Value) -> Value {
    let mut draft = policy.clone();
    draft["$schema"] = json!(POLICY_DRAFT_SCHEMA_URI);
    if let Some(metadata) = draft.get_mut("Metadata").and_then(Value::as_object_mut) {
        metadata.remove("Revision");
        metadata.remove("PublishedAt");
    }
    draft
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
    let agent = AgentHarness::start(agent_path, Mode::Unelevated, None).await?;

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

    // PUT is deliberately excluded: the Phase 2 management contract routes it to
    // policy replacement (see `policy_management_endpoints`). It is no longer rejected
    // outright.
    for method in ["POST", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"] {
        let response = request(&agent.pipe_name, method, "/v1/policy").await?;
        ensure!(
            response.status == 405,
            "{method} /v1/policy returned HTTP {}",
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

/// Must run with `Mode::Elevated` (see `run`): the seeded policy file requires an
/// admin-only ACL (`secure_policy_file`), and reaching a real `Active` observation at all
/// requires the hosting directory to itself pass the store's admin-only directory
/// security check, which only the secured test-host directory (see [`SecureTestDir`])
/// can satisfy.
async fn complete_snapshots_across_reload(agent_path: &Path) -> anyhow::Result<()> {
    let empty = empty_policy();
    let agent = AgentHarness::start(agent_path, Mode::Elevated, Some(&empty)).await?;

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

/// Exercises the Phase 2 management endpoints: `GET /v1/policy/management`,
/// `POST /v1/policy/validate`, and `PUT /v1/policy`.
///
/// Inspection and validation are authenticated but unelevated; only the replacement
/// endpoint requires an elevated Administrator token. This must run with `Mode::Unelevated`
/// (see `run`): the `PUT` denial assertion below is contradictory if the tester process
/// itself happens to be elevated/SYSTEM (item 23), which is exactly why this suite is
/// split by mode instead of assuming one privilege level for the whole binary. A full
/// write commit additionally requires SYSTEM or an elevated Administrators-member token;
/// see [`elevated_policy_lifecycle`] and `run-as-system.ps1`.
async fn unelevated_management_and_validation_succeed_put_requires_administrator(
    agent_path: &Path,
) -> anyhow::Result<()> {
    let agent = AgentHarness::start(agent_path, Mode::Unelevated, None).await?;

    // `GET /v1/policy/management` reflects the Missing state atomically, with no policy
    // or diagnostics attached, and always advertises that writes require elevation.
    let management = request(&agent.pipe_name, "GET", "/v1/policy/management").await?;
    ensure!(
        management.status == 200,
        "policy management returned HTTP {}",
        management.status
    );
    let management = management.json()?;
    ensure!(
        management["ResponseKind"] == "PolicyManagementResponse",
        "unexpected policy management response kind"
    );
    ensure!(
        management["Management"]["State"] == "Missing",
        "expected Missing state with no policy configured"
    );
    // The test harness always configures a custom `PolicyPath` inside an isolated temp
    // directory (never the real default ProgramData location), so this is always
    // ConfiguredPath. That directory is owned by the current (non-admin) test user, not
    // SYSTEM/Administrators, so it correctly fails the custom-path security check: the
    // store never rewrites a custom directory's ACL, it only ever verifies it.
    ensure!(
        management["Management"]["Source"] == "ConfiguredPath",
        "expected the harness-configured custom policy path: {management:?}"
    );
    ensure!(
        management["Management"]["WriteCapability"] == "ReadOnly"
            && management["Management"]["ReadOnlyReason"] == "UnsafePath",
        "expected a non-admin-owned custom directory to be read-only/unsafe: {management:?}"
    );
    ensure!(
        management["Management"]["ElevationRequired"] == true,
        "writes must always require elevation"
    );
    ensure!(
        management["Management"].get("Policy").is_none(),
        "Missing state must not expose a policy"
    );
    ensure!(
        management["Management"].get("InvalidDiagnostics").is_none(),
        "Missing state must not expose diagnostics"
    );
    let store_token = management["Management"]["StoreToken"]
        .as_str()
        .context("management response missing StoreToken")?
        .to_owned();

    // A well-formed, schema-compliant draft validates successfully with a canonical
    // draft and receipt, and no findings (no audit mode, no default-allow, no rules).
    let valid_draft = draft_from(&empty_policy());
    let validate = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        &json!({
            "RequestKind": "PolicyValidationRequest",
            "RequestVersion": "1.0",
            "Draft": valid_draft,
        }),
    )
    .await?;
    ensure!(
        validate.status == 200,
        "policy validate returned HTTP {}",
        validate.status
    );
    let validate_body = validate.json()?;
    ensure!(
        validate_body["ResponseKind"] == "PolicyValidationResponse",
        "unexpected policy validation response kind"
    );
    ensure!(
        validate_body["Validation"]["IsValid"] == true,
        "expected a well-formed empty policy draft to validate"
    );
    ensure!(
        validate_body["Validation"]["CanonicalDraft"].is_object(),
        "a valid result must carry a canonical draft"
    );
    ensure!(
        validate_body["Validation"]["Findings"] == json!([]),
        "expected no findings for an empty, non-audit, default-deny draft"
    );
    let receipt = validate_body["Validation"]["ValidationReceipt"]
        .as_str()
        .context("valid result missing ValidationReceipt")?
        .to_owned();

    // An unsupported schema constant is rejected with a precise finding code rather than
    // a generic schema violation.
    let mut unsupported_schema_draft = valid_draft.clone();
    unsupported_schema_draft["$schema"] = json!("https://example.com/wrong-schema.json");
    let invalid_validate = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        &json!({
            "RequestKind": "PolicyValidationRequest",
            "RequestVersion": "1.0",
            "Draft": unsupported_schema_draft,
        }),
    )
    .await?;
    ensure!(
        invalid_validate.status == 200,
        "invalid draft validate returned HTTP {}",
        invalid_validate.status
    );
    let invalid_body = invalid_validate.json()?;
    ensure!(
        invalid_body["Validation"]["IsValid"] == false,
        "expected an unsupported-schema draft to be invalid"
    );
    ensure!(
        invalid_body["Validation"].get("CanonicalDraft").is_none(),
        "an invalid result must not carry a canonical draft"
    );
    ensure!(
        invalid_body["Validation"]["Findings"]
            .as_array()
            .is_some_and(|findings| findings.iter().any(|finding| finding["Code"] == "UnsupportedSchema")),
        "expected an UnsupportedSchema finding: {invalid_body:?}"
    );

    // Audit mode is accepted but flagged as a warning, not an error.
    let mut audit_mode_draft = valid_draft.clone();
    audit_mode_draft["Enforcement"]["AuditMode"] = json!(true);
    let audit_validate = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        &json!({
            "RequestKind": "PolicyValidationRequest",
            "RequestVersion": "1.0",
            "Draft": audit_mode_draft,
        }),
    )
    .await?;
    ensure!(
        audit_validate.status == 200,
        "audit-mode draft validate returned HTTP {}",
        audit_validate.status
    );
    let audit_body = audit_validate.json()?;
    ensure!(
        audit_body["Validation"]["IsValid"] == true,
        "warnings must not invalidate an otherwise-valid draft"
    );
    ensure!(
        audit_body["Validation"]["Findings"]
            .as_array()
            .is_some_and(|findings| findings
                .iter()
                .any(|finding| finding["Code"] == "AuditModeEnabled" && finding["Severity"] == "Warning")),
        "expected an AuditModeEnabled warning: {audit_body:?}"
    );

    // Writes require an elevated, Administrators-member token; this test process
    // presents neither, so even a well-formed Create request is denied before it ever
    // touches the store.
    let replace = request_with_body(
        &agent.pipe_name,
        "PUT",
        "/v1/policy",
        &json!({
            "RequestKind": "PolicyReplacementRequest",
            "RequestVersion": "1.0",
            "ExpectedStoreToken": store_token,
            "Operation": "Create",
            "ConflictHandling": "Reject",
            "WarningsAcknowledged": true,
            "Draft": valid_draft,
            "ValidationReceipt": receipt,
        }),
    )
    .await?;
    ensure!(
        replace.status == 403,
        "unelevated policy replacement returned HTTP {}",
        replace.status
    );
    let replace_error = replace.json()?;
    ensure!(
        replace_error["Code"] == "AdministratorRequired",
        "expected AdministratorRequired for an unelevated write: {replace_error:?}"
    );

    Ok(())
}

/// Exercises the policy-management body-size limit exported by the shared contract
/// (`now_policy_server_template::MAX_POLICY_MANAGEMENT_BODY_BYTES`, 16 MiB): far larger
/// than the general per-operation limit (`MAX_REQUEST_BODY_BYTES`, 256 KiB) that every
/// `POST /v1/package-operations/*` route keeps instead. Both limits are applied
/// entirely inside the shared router, before the request ever reaches this broker's own
/// handlers, so a request need not carry a well-formed policy draft to prove either
/// bound: only that the HTTP layer accepts or rejects it by size alone. `POST
/// /v1/policy/validate` requires no special privilege either way, so this runs
/// unelevated.
async fn policy_management_body_size_limits(agent_path: &Path) -> anyhow::Result<()> {
    let agent = AgentHarness::start(agent_path, Mode::Unelevated, None).await?;

    // Comfortably above the 256 KiB operation-endpoint limit but still well inside the
    // dedicated 16 MiB policy-management limit: proves `/v1/policy/validate` does not
    // share the smaller operation-endpoint limit.
    let accepted_len = MAX_REQUEST_BODY_BYTES * 2;
    let accepted = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        &padded_validate_request(accepted_len),
    )
    .await?;
    ensure!(
        accepted.status == 200,
        "a {accepted_len}-byte request (over the 256 KiB operation limit, under the 16 MiB \
         policy-management limit) returned HTTP {}",
        accepted.status
    );

    // Comfortably over the 16 MiB policy-management limit.
    let rejected_len = MAX_POLICY_MANAGEMENT_BODY_BYTES + MAX_REQUEST_BODY_BYTES;
    let rejected = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        &padded_validate_request(rejected_len),
    )
    .await?;
    ensure!(
        rejected.status == 413,
        "a {rejected_len}-byte request (over the 16 MiB policy-management limit) returned HTTP {}",
        rejected.status
    );
    ensure!(
        rejected.json()?["Code"] == "PayloadTooLarge",
        "expected PayloadTooLarge for an oversized policy-management request"
    );

    Ok(())
}

/// Build a syntactically valid `PolicyValidationRequest` envelope whose serialized body
/// is at least `target_len` bytes, via a single large filler string in `Draft` (not a
/// well-formed policy draft): `Draft` is a raw JSON value in the shared contract, so any
/// valid JSON deserializes, and the body-size limit is enforced before the draft's
/// content is ever inspected. One contiguous allocation for the filler, reused by
/// `serde_json`/`request_with_body` without further copies, instead of building a large
/// tree of many small values.
fn padded_validate_request(target_len: usize) -> Value {
    json!({
        "RequestKind": "PolicyValidationRequest",
        "RequestVersion": "1.0",
        "Draft": "a".repeat(target_len),
    })
}

/// Authoritatively (re)validate `draft` and return its canonical validation receipt,
/// failing the test outright if the draft (expected to be well-formed) does not validate.
async fn validate_draft_or_fail(agent: &AgentHarness, draft: &Value) -> anyhow::Result<String> {
    let response = request_with_body(
        &agent.pipe_name,
        "POST",
        "/v1/policy/validate",
        &json!({
            "RequestKind": "PolicyValidationRequest",
            "RequestVersion": "1.0",
            "Draft": draft,
        }),
    )
    .await?;
    ensure!(response.status == 200, "validate returned HTTP {}", response.status);
    let body = response.json()?;
    ensure!(body["Validation"]["IsValid"] == true, "draft must validate: {body:?}");
    body["Validation"]["ValidationReceipt"]
        .as_str()
        .context("valid result missing ValidationReceipt")
        .map(str::to_owned)
}

/// Issue `PUT /v1/policy` with the given operation/conflict-handling/draft/receipt.
async fn replace_policy(
    agent: &AgentHarness,
    store_token: &str,
    operation: &str,
    conflict_handling: &str,
    draft: &Value,
    receipt: &str,
    warnings_acknowledged: bool,
) -> anyhow::Result<HttpResponse> {
    request_with_body(
        &agent.pipe_name,
        "PUT",
        "/v1/policy",
        &json!({
            "RequestKind": "PolicyReplacementRequest",
            "RequestVersion": "1.0",
            "ExpectedStoreToken": store_token,
            "Operation": operation,
            "ConflictHandling": conflict_handling,
            "WarningsAcknowledged": warnings_acknowledged,
            "Draft": draft,
            "ValidationReceipt": receipt,
        }),
    )
    .await
}

/// Build a well-formed, empty-rules policy draft/document with the given id (and,
/// for `..._document` variants, revision), for use as a distinct identity at each stage
/// of [`elevated_policy_lifecycle`].
fn policy_with_id(id: &str) -> Value {
    let mut policy = empty_policy();
    policy["Metadata"]["Id"] = json!(id);
    policy
}

/// Exercises the full privileged policy-management write lifecycle end to end (item 23):
/// Missing -> Create, Update (revision increment/new `PublishedAt`), ReplaceIdentity
/// (revision resets to 1), Invalid -> Repair (with redacted diagnostics), a warning that
/// must be explicitly acknowledged, a stale-token conflict that carries the current
/// published snapshot, `ConfirmOverwrite` against the exact current token followed by a
/// second conflict, an out-of-band external edit picked up by the watcher, and the same
/// policy remaining active across an Agent restart.
///
/// Must run with `Mode::Elevated` (see `run`): every write here requires an elevated,
/// Administrators-member (or SYSTEM) token, and the external-edit steps additionally
/// require the ability to set the policy file's owner to LocalSystem (`secure_policy_file`).
async fn elevated_policy_lifecycle(agent_path: &Path) -> anyhow::Result<()> {
    let mut agent = AgentHarness::start(agent_path, Mode::Elevated, None).await?;

    // ── Missing -> Create: exact persisted active ──────────────────────────
    let initial_management = request(&agent.pipe_name, "GET", "/v1/policy/management")
        .await?
        .json()?;
    ensure!(
        initial_management["Management"]["State"] == "Missing",
        "expected Missing before Create: {initial_management:?}"
    );
    let mut store_token = initial_management["Management"]["StoreToken"]
        .as_str()
        .context("management response missing StoreToken")?
        .to_owned();

    let draft_a = draft_from(&policy_with_id("tests.lifecycle-a"));
    let receipt_a = validate_draft_or_fail(&agent, &draft_a).await?;
    let created = replace_policy(&agent, &store_token, "Create", "Reject", &draft_a, &receipt_a, true).await?;
    ensure!(
        created.status == 200,
        "Create returned HTTP {}: {:?}",
        created.status,
        created.json()
    );
    let created_body = created.json()?;
    ensure!(created_body["Policy"]["Metadata"]["Id"] == "tests.lifecycle-a");
    ensure!(
        created_body["Policy"]["Metadata"]["Revision"] == 1,
        "Create must assign revision 1"
    );

    let get_after_create = request(&agent.pipe_name, "GET", "/v1/policy").await?.json()?;
    ensure!(
        get_after_create["Policy"] == created_body["Policy"],
        "GET after Create does not match the exact created policy: {get_after_create:?} vs {:?}",
        created_body["Policy"]
    );
    store_token = created_body["Management"]["StoreToken"]
        .as_str()
        .context("Create response missing StoreToken")?
        .to_owned();

    // ── Update: revision increments, PublishedAt changes, identity retained ─
    let previous_published_at = created_body["Policy"]["Metadata"]["PublishedAt"].clone();
    let receipt_a_again = validate_draft_or_fail(&agent, &draft_a).await?;
    let updated = replace_policy(
        &agent,
        &store_token,
        "Update",
        "Reject",
        &draft_a,
        &receipt_a_again,
        true,
    )
    .await?;
    ensure!(
        updated.status == 200,
        "Update returned HTTP {}: {:?}",
        updated.status,
        updated.json()
    );
    let updated_body = updated.json()?;
    ensure!(
        updated_body["Policy"]["Metadata"]["Id"] == "tests.lifecycle-a",
        "Update must retain identity"
    );
    ensure!(
        updated_body["Policy"]["Metadata"]["Revision"] == 2,
        "Update must increment the revision"
    );
    ensure!(
        updated_body["Policy"]["Metadata"]["PublishedAt"] != previous_published_at,
        "Update must assign a fresh PublishedAt"
    );
    store_token = updated_body["Management"]["StoreToken"]
        .as_str()
        .context("Update response missing StoreToken")?
        .to_owned();

    // ── ReplaceIdentity: different identity, revision resets to 1 ───────────
    let draft_b = draft_from(&policy_with_id("tests.lifecycle-b"));
    let receipt_b = validate_draft_or_fail(&agent, &draft_b).await?;
    let replaced_identity = replace_policy(
        &agent,
        &store_token,
        "ReplaceIdentity",
        "Reject",
        &draft_b,
        &receipt_b,
        true,
    )
    .await?;
    ensure!(
        replaced_identity.status == 200,
        "ReplaceIdentity returned HTTP {}: {:?}",
        replaced_identity.status,
        replaced_identity.json()
    );
    let replaced_identity_body = replaced_identity.json()?;
    ensure!(replaced_identity_body["Policy"]["Metadata"]["Id"] == "tests.lifecycle-b");
    ensure!(
        replaced_identity_body["Policy"]["Metadata"]["Revision"] == 1,
        "ReplaceIdentity must assign revision 1"
    );
    // Its resulting token is deliberately never used: the next stage (Invalid -> Repair)
    // bypasses the API and edits disk directly, so the fresh token it needs afterward
    // comes from re-observing that external edit, not from carrying this one forward.

    // ── Invalid -> Repair: diagnostics redacted, revision resets to 1 ───────
    let secret_marker = "sso1kkD0-attacker-controlled-marker";
    std::fs::write(&agent.policy_path, format!(r#"{{"unterminated": "{secret_marker}"#))
        .context("write malformed policy")?;
    secure_policy_file(&agent.policy_path)?;

    let invalid_management = poll_until(Duration::from_secs(10), || async {
        let management = request(&agent.pipe_name, "GET", "/v1/policy/management")
            .await?
            .json()?;
        Ok((management["Management"]["State"] == "Invalid").then_some(management))
    })
    .await
    .context("store never observed the malformed external edit")?;

    let diagnostics = &invalid_management["Management"]["InvalidDiagnostics"];
    ensure!(
        diagnostics["Findings"].as_array().is_some_and(|f| !f.is_empty()),
        "Invalid state must carry at least one finding: {invalid_management:?}"
    );
    ensure!(
        !diagnostics.to_string().contains(secret_marker),
        "diagnostics leaked the malformed on-disk content: {diagnostics:?}"
    );
    let invalid_token = invalid_management["Management"]["StoreToken"]
        .as_str()
        .context("Invalid management response missing StoreToken")?
        .to_owned();

    let draft_c = draft_from(&policy_with_id("tests.lifecycle-c"));
    let receipt_c = validate_draft_or_fail(&agent, &draft_c).await?;
    let repaired = replace_policy(&agent, &invalid_token, "Repair", "Reject", &draft_c, &receipt_c, true).await?;
    ensure!(
        repaired.status == 200,
        "Repair returned HTTP {}: {:?}",
        repaired.status,
        repaired.json()
    );
    let repaired_body = repaired.json()?;
    ensure!(
        repaired_body["Policy"]["Metadata"]["Revision"] == 1,
        "Repair must assign revision 1"
    );
    store_token = repaired_body["Management"]["StoreToken"]
        .as_str()
        .context("Repair response missing StoreToken")?
        .to_owned();

    // ── Warning must be explicitly acknowledged before it is allowed through ─
    let mut audit_draft = policy_with_id("tests.lifecycle-c");
    audit_draft["Enforcement"]["AuditMode"] = json!(true);
    let audit_draft = draft_from(&audit_draft);
    let receipt_audit = validate_draft_or_fail(&agent, &audit_draft).await?;

    let unacknowledged = replace_policy(
        &agent,
        &store_token,
        "Update",
        "Reject",
        &audit_draft,
        &receipt_audit,
        false,
    )
    .await?;
    ensure!(
        unacknowledged.status == 409,
        "an unacknowledged warning must conflict: HTTP {}",
        unacknowledged.status
    );
    ensure!(unacknowledged.json()?["Code"] == "WarningConfirmationRequired");

    let acknowledged = replace_policy(
        &agent,
        &store_token,
        "Update",
        "Reject",
        &audit_draft,
        &receipt_audit,
        true,
    )
    .await?;
    ensure!(
        acknowledged.status == 200,
        "an acknowledged warning must succeed: HTTP {}: {:?}",
        acknowledged.status,
        acknowledged.json()
    );
    store_token = acknowledged.json()?["Management"]["StoreToken"]
        .as_str()
        .context("acknowledged Update response missing StoreToken")?
        .to_owned();

    // ── Stale conflict carries the current published snapshot ──────────────
    let stale_token = store_token.clone();
    let external = policy_with_id("tests.lifecycle-external"); // a full document, not a draft: written directly to disk.
    std::fs::write(&agent.policy_path, serde_json::to_vec_pretty(&external)?).context("write external edit")?;
    secure_policy_file(&agent.policy_path)?;
    poll_until(Duration::from_secs(10), || async {
        let management = request(&agent.pipe_name, "GET", "/v1/policy/management")
            .await?
            .json()?;
        Ok((management["Management"]["Policy"]["Metadata"]["Id"] == "tests.lifecycle-external").then_some(()))
    })
    .await
    .context("store never observed the external edit before the stale-conflict check")?;

    let draft_stale = draft_from(&policy_with_id("tests.lifecycle-c"));
    let receipt_stale = validate_draft_or_fail(&agent, &draft_stale).await?;
    let stale = replace_policy(
        &agent,
        &stale_token,
        "Update",
        "Reject",
        &draft_stale,
        &receipt_stale,
        true,
    )
    .await?;
    ensure!(
        stale.status == 409,
        "a stale token must conflict: HTTP {}",
        stale.status
    );
    let stale_body = stale.json()?;
    ensure!(stale_body["Code"] == "StalePolicyStoreToken");
    ensure!(
        stale_body["Management"]["Policy"]["Metadata"]["Id"] == "tests.lifecycle-external",
        "the stale-conflict error must carry the current published snapshot: {stale_body:?}"
    );
    let current_token = stale_body["Management"]["StoreToken"]
        .as_str()
        .context("stale-conflict error missing StoreToken")?
        .to_owned();

    // ── ConfirmOverwrite: exact-token success, then a second conflict ───────
    let draft_confirm = draft_from(&policy_with_id("tests.lifecycle-external"));
    let receipt_confirm = validate_draft_or_fail(&agent, &draft_confirm).await?;
    let confirmed = replace_policy(
        &agent,
        &current_token,
        "Update",
        "ConfirmOverwrite",
        &draft_confirm,
        &receipt_confirm,
        true,
    )
    .await?;
    ensure!(
        confirmed.status == 200,
        "ConfirmOverwrite against the exact current token must succeed: HTTP {}: {:?}",
        confirmed.status,
        confirmed.json()
    );

    let re_conflict = replace_policy(
        &agent,
        &current_token,
        "Update",
        "ConfirmOverwrite",
        &draft_confirm,
        &receipt_confirm,
        true,
    )
    .await?;
    ensure!(
        re_conflict.status == 409,
        "reusing an already-consumed token must conflict again, even under ConfirmOverwrite: HTTP {}",
        re_conflict.status
    );
    ensure!(re_conflict.json()?["Code"] == "StalePolicyStoreToken");

    // ── External edit watcher: picked up with no further API call ───────────
    let watched = policy_with_id("tests.lifecycle-watched");
    std::fs::write(&agent.policy_path, serde_json::to_vec_pretty(&watched)?).context("write watched external edit")?;
    secure_policy_file(&agent.policy_path)?;
    poll_until(Duration::from_secs(10), || async {
        let response = request(&agent.pipe_name, "GET", "/v1/policy").await?;
        if response.status != 200 {
            return Ok(None);
        }
        let body = response.json()?;
        Ok((body["Policy"]["Metadata"]["Id"] == "tests.lifecycle-watched").then_some(()))
    })
    .await
    .context("the watcher never picked up the external edit")?;

    // ── Restart: the same policy remains active afterward ──────────────────
    agent.restart(agent_path).await?;
    let after_restart = request(&agent.pipe_name, "GET", "/v1/policy").await?;
    ensure!(
        after_restart.status == 200,
        "the policy must still be active after a restart: HTTP {}",
        after_restart.status
    );
    let after_restart_body = after_restart.json()?;
    ensure!(
        after_restart_body["Policy"]["Metadata"]["Id"] == "tests.lifecycle-watched",
        "policy identity changed across a restart: {after_restart_body:?}"
    );

    Ok(())
}

/// Configured-path *format* rejection, end to end (item 18/31): a policy path whose
/// extension the store does not support (anything other than case-insensitive `.json`)
/// is reported as `Invalid`/`ReadOnly`/`UnsupportedFormat` through `GET
/// /v1/policy/management`, whatever (if anything) actually exists at that path, and `PUT
/// /v1/policy` against it is rejected with the shared contract's dedicated
/// `UnsupportedPolicyFormat` (HTTP 422) -- distinct from every other read-only reason,
/// which maps to `UnsafePolicyPath`/`UnsupportedPolicyFilesystem` instead.
///
/// Must run with `Mode::Elevated` (see `run`): reaching `PolicyStore::replace`'s
/// write-capability check at all requires first passing the handler's own elevated-
/// Administrator gate (see `unelevated_management_and_validation_succeed_put_requires_administrator`,
/// which proves the unelevated half of that gate) -- an unelevated PUT would be denied
/// with `AdministratorRequired` before the configured path's format is ever considered,
/// masking exactly what this proves.
async fn unsupported_configured_path_format_is_rejected(agent_path: &Path) -> anyhow::Result<()> {
    for file_name in ["policy.yaml", "policy.yml", "policy", "policy.txt"] {
        let agent = AgentHarness::start_with_file_name(agent_path, Mode::Elevated, file_name, None).await?;

        let management = request(&agent.pipe_name, "GET", "/v1/policy/management").await?;
        ensure!(
            management.status == 200,
            "{file_name}: policy management returned HTTP {}",
            management.status
        );
        let management = management.json()?;
        ensure!(
            management["Management"]["State"] == "Invalid",
            "{file_name}: expected Invalid state for an unsupported extension: {management:?}"
        );
        ensure!(
            management["Management"]["WriteCapability"] == "ReadOnly"
                && management["Management"]["ReadOnlyReason"] == "UnsupportedFormat",
            "{file_name}: expected ReadOnly/UnsupportedFormat: {management:?}"
        );
        let store_token = management["Management"]["StoreToken"]
            .as_str()
            .context("management response missing StoreToken")?
            .to_owned();

        let draft = draft_from(&empty_policy());
        let receipt = validate_draft_or_fail(&agent, &draft).await?;
        let replace = replace_policy(&agent, &store_token, "Create", "Reject", &draft, &receipt, true).await?;
        ensure!(
            replace.status == 422,
            "{file_name}: PUT against an unsupported-format path returned HTTP {}",
            replace.status
        );
        ensure!(
            replace.json()?["Code"] == "UnsupportedPolicyFormat",
            "{file_name}: expected UnsupportedPolicyFormat: {:?}",
            replace.json()
        );
    }

    Ok(())
}

/// Companion to the rejection test above (item 18/31): an uppercase `.JSON` extension is
/// accepted end to end -- not just by shape validation in isolation, but through the
/// real disk-loading and write pipeline -- proving the case-insensitive match documented
/// on `validate_configured_path_shape` holds all the way through.
///
/// Must run with `Mode::Elevated`: seeds the policy file with an admin-only ACL (via
/// `secure_policy_file`) and issues a `PUT /v1/policy`, both of which require an
/// elevated/SYSTEM token.
async fn uppercase_json_extension_is_active_and_writable(agent_path: &Path) -> anyhow::Result<()> {
    let policy = empty_policy();
    let agent = AgentHarness::start_with_file_name(agent_path, Mode::Elevated, "policy.JSON", Some(&policy)).await?;

    let management = request(&agent.pipe_name, "GET", "/v1/policy/management").await?;
    ensure!(
        management.status == 200,
        "policy management returned HTTP {}",
        management.status
    );
    let management = management.json()?;
    ensure!(
        management["Management"]["State"] == "Active",
        "expected an uppercase .JSON policy to load as Active: {management:?}"
    );
    ensure!(
        management["Management"]["WriteCapability"] == "Writable",
        "expected an uppercase .JSON policy directory to be writable: {management:?}"
    );

    let store_token = management["Management"]["StoreToken"]
        .as_str()
        .context("management response missing StoreToken")?
        .to_owned();
    // Same id as the seeded policy above: `Update` requires the active policy's own
    // identity to be preserved (see `policy_store::plan_revision`), so this proves the
    // write path (not just the read path) works end to end for an uppercase `.JSON`
    // configured path.
    let draft = draft_from(&policy);
    let receipt = validate_draft_or_fail(&agent, &draft).await?;
    let replace = replace_policy(&agent, &store_token, "Update", "Reject", &draft, &receipt, true).await?;
    ensure!(
        replace.status == 200,
        "PUT against an uppercase .JSON path returned HTTP {}: {:?}",
        replace.status,
        replace.json()
    );

    Ok(())
}

/// Poll `probe` until it returns `Some(_)` or `deadline` elapses, sleeping briefly
/// between attempts. Used throughout [`elevated_policy_lifecycle`] to await an
/// asynchronous, watcher-driven state transition rather than assuming a fixed delay.
async fn poll_until<T, F, Fut>(timeout: Duration, mut probe: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<Option<T>>>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = probe().await? {
            return Ok(value);
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for the expected condition"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
