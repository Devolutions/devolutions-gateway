//! The system event the agent raises when its key storage policy holds a renewal back.

#![cfg(windows)]

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use serde_json::{Value, json};
use testsuite::cli;

use super::{Mock, start_mock};

/// The Event Log source and code of the event, from `devolutions-agent.mc`, which the installer registers.
const EVENT_SOURCE: &str = "Devolutions Agent";
const EVENT_ID: u32 = 1100;

/// The longest wait for the agent to enroll, then for the event to reach the log.
const WAIT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(500);

/// Deletes the machine keys the agent created under this run's key name prefix.
struct MachineKeys(String);

impl Drop for MachineKeys {
    fn drop(&mut self) {
        let backend = device_key::KeyBackend::WindowsSoftwareProvider;
        match device_key::list(&backend, &self.0) {
            Ok(names) => {
                for name in names {
                    if let Err(error) = device_key::delete(&backend, &name) {
                        eprintln!("delete Agent Identity test key {name}: {error:#}");
                    }
                }
            }
            Err(error) => eprintln!("list Agent Identity test keys: {error:#}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_renewal_held_by_the_key_storage_policy_raises_event_1100() -> anyhow::Result<()> {
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    // While a required key storage policy lists no key storage the machine offers, the agent raises event 1100 in
    // the system log, naming the identity and the listed key storages.
    // The agent creates its key in the Windows software provider's machine store, which needs an elevated
    // administrator, as on the CI runners.
    ensure!(
        win_api_wrappers::token::Token::current_process_token().is_elevated()?,
        "this test needs an elevated administrator, whom the agent's machine keys require"
    );
    let started = Instant::now();
    let mock_dir = tempfile::tempdir()?;
    let mock = start_mock(mock_dir.path()).await?;
    let http = mock_client(&mock)?;
    // No agent offers `tpm` yet, so a policy requiring it holds every renewal of the identity back.
    post_json(
        &http,
        &format!("{}/__mock__/key-storage", mock.base_url),
        None,
        &json!({ "policy": { "backends": ["tpm"], "required": true } }),
    )
    .await?;
    let token = enrollment_token(&http, &mock).await?;

    let data_dir = tempfile::tempdir()?;
    let key_name_prefix = format!("dgw-testsuite-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let _machine_keys = MachineKeys(key_name_prefix.clone());
    let config = json!({
        "Identity": { "Enabled": true },
        "__debug__": {
            "identity": {
                "extra_trusted_root": mock.ca_path,
                "key_name_prefix": key_name_prefix,
                "acl_grant_current_user": true,
                "renewal_after_secs": 1,
                "min_renewal_interval_secs": 0,
                "disable_jitter": true,
                "pending_poll_interval_ms": 200
            }
        }
    });
    std::fs::write(data_dir.path().join("agent.json"), serde_json::to_vec_pretty(&config)?)?;
    enroll(data_dir.path(), &token)?;
    let mut agent = cli::agent_tokio_cmd()
        .arg("run")
        .env("DAGENT_CONFIG_PATH", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("start devolutions-agent run")?;

    let observed = async {
        let identity_id = poll("the agent did not enroll", || stored_identity_id(data_dir.path())).await?;
        let data = poll("the agent raised no event 1100 for its held renewal", || {
            held_renewal_event(started, &identity_id)
        })
        .await?;
        ensure!(
            data.iter().any(|value| value.contains("tpm")),
            "event 1100 does not name the policy's key storage `tpm`: {data:?}"
        );
        Ok(())
    }
    .await;
    // The agent stops before its keys are deleted.
    let _ = agent.kill().await;
    observed.with_context(|| agent_log(data_dir.path()))
}

/// The agent's log files, for a failure message.
fn agent_log(data_dir: &Path) -> String {
    let mut log = String::from("agent log:\n");
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "log") {
                log.push_str(&String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default()));
            }
        }
    }
    log
}

/// An HTTP client that trusts the mock's TLS certificate.
fn mock_client(mock: &Mock) -> anyhow::Result<reqwest::Client> {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(&mock.ca_path)?)?;
    Ok(reqwest::Client::builder().add_root_certificate(ca).no_proxy().build()?)
}

async fn post_json(http: &reqwest::Client, url: &str, session: Option<&str>, body: &Value) -> anyhow::Result<Value> {
    let mut request = http.post(url).json(body);
    if let Some(session) = session {
        request = request.header("tokenId", session);
    }
    let response = request.send().await.with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let text = response.text().await?;
    ensure!(status.is_success(), "POST {url}: {status}: {text}");
    Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Creates a single-use enrollment token through the mock's management API.
async fn enrollment_token(http: &reqwest::Client, mock: &Mock) -> anyhow::Result<String> {
    let login = post_json(
        http,
        &format!("{}/api/v1/login", mock.base_url),
        None,
        &json!({ "appKey": mock.app_key, "appSecret": mock.app_secret }),
    )
    .await?;
    let session = login["tokenId"].as_str().context("login has no tokenId")?;
    let created = post_json(
        http,
        &format!("{}/api/v1/agent-identity/enrollment-token", mock.base_url),
        Some(session),
        &json!({ "name": "testsuite system event", "maxUses": 1 }),
    )
    .await?;
    Ok(created["token"]
        .as_str()
        .context("created token has no text")?
        .to_owned())
}

/// Hands the token to the agent through `identity enroll -`, which reads it from standard input.
fn enroll(data_dir: &Path, token: &str) -> anyhow::Result<()> {
    let output = cli::agent_assert_cmd()
        .args(["identity", "enroll", "-"])
        .env("DAGENT_CONFIG_PATH", data_dir)
        .write_stdin(format!("{token}\n"))
        .output()?;
    ensure!(
        output.status.success(),
        "identity enroll failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// The ID of the identity the agent stored, once it has enrolled.
fn stored_identity_id(data_dir: &Path) -> anyhow::Result<Option<String>> {
    let authorities = data_dir.join("identity").join("authorities");
    let Ok(entries) = std::fs::read_dir(authorities) else {
        return Ok(None);
    };
    for entry in entries {
        let path = entry?.path().join("identity.json");
        if let Ok(bytes) = std::fs::read(&path) {
            let identity: Value = serde_json::from_slice(&bytes)?;
            if let Some(id) = identity["identity_id"].as_str() {
                return Ok(Some(id.to_owned()));
            }
        }
    }
    Ok(None)
}

/// The inserted strings of an event 1100 from the agent's source, written since `started`, that name `identity_id`.
///
/// The machine may hold events from earlier runs, which name other identities.
/// An unregistered source still logs the inserted strings, so the match never relies on the formatted message.
fn held_renewal_event(started: Instant, identity_id: &str) -> anyhow::Result<Option<Vec<String>>> {
    let since_ms = started.elapsed().as_millis() + 1000;
    let query = format!(
        "*[System[Provider[@Name='{EVENT_SOURCE}'] and EventID={EVENT_ID} and TimeCreated[timediff(@SystemTime) <= {since_ms}]]]"
    );
    let output = std::process::Command::new("wevtutil")
        .args(["qe", "Application", &format!("/q:{query}"), "/f:xml"])
        .output()
        .context("run wevtutil")?;
    if !output.status.success() {
        bail!("wevtutil failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let events = String::from_utf8_lossy(&output.stdout);
    Ok(events
        .split("</Event>")
        .map(|event| event_data(event).map(str::to_owned).collect::<Vec<_>>())
        .find(|data| data.iter().any(|value| value.contains(identity_id))))
}

/// The inserted strings of one event's XML.
fn event_data(event: &str) -> impl Iterator<Item = &str> {
    event
        .split("<Data>")
        .skip(1)
        .filter_map(|data| data.split_once("</Data>").map(|(value, _)| value))
}

async fn poll<T>(failure: &str, mut check: impl FnMut() -> anyhow::Result<Option<T>>) -> anyhow::Result<T> {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(value) = check()? {
            return Ok(value);
        }
        ensure!(Instant::now() < deadline, "{failure} within {} seconds", WAIT.as_secs());
        tokio::time::sleep(POLL).await;
    }
}
