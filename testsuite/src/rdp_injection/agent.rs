//! Drives the public `ironrdp-agent` CLI as a real RDCleanPath client. Tests skip when the
//! binary is not installed (`cargo install ironrdp-agent --version 0.1.0`).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Context as _;

use super::tokens::next_id;
use super::{PROXY_PASSWORD, PROXY_USER};

pub const IRONRDP_AGENT_VERSION: &str = "0.1.0";

fn ironrdp_agent_bin() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("IRONRDP_AGENT") {
        return Some(PathBuf::from(path));
    }
    let name = if cfg!(windows) {
        "ironrdp-agent.exe"
    } else {
        "ironrdp-agent"
    };
    if let Ok(home) = std::env::var("CARGO_HOME") {
        let path = PathBuf::from(home).join("bin").join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    let cargo_home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .map(|home| home.join(".cargo").join("bin").join(name));
    if let Some(path) = cargo_home
        && path.is_file()
    {
        return Some(path);
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn require_ironrdp_agent() -> anyhow::Result<Option<PathBuf>> {
    let Some(bin) = ironrdp_agent_bin() else {
        eprintln!(
            "skipping RDCleanPath ironrdp-agent test: cargo install ironrdp-agent --version {IRONRDP_AGENT_VERSION}"
        );
        return Ok(None);
    };
    let output = std::process::Command::new(&bin)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", bin.display()))?;
    let version = String::from_utf8_lossy(&output.stdout);
    anyhow::ensure!(
        version.contains(IRONRDP_AGENT_VERSION),
        "expected ironrdp-agent {IRONRDP_AGENT_VERSION}, got {version:?} from {}",
        bin.display()
    );
    Ok(Some(bin))
}

pub fn ironrdp_agent_endpoint() -> String {
    let name = format!("ironrdp-e2e-{}", next_id().replace('-', ""));
    if cfg!(windows) {
        format!(r"\\.\pipe\{name}")
    } else {
        std::env::temp_dir().join(format!("{name}.sock")).display().to_string()
    }
}

pub async fn start_ironrdp_daemon(bin: &Path, endpoint: &str) -> anyhow::Result<tokio::process::Child> {
    let child = tokio::process::Command::new(bin)
        .args(["--endpoint", endpoint, "daemon-start"])
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start ironrdp-agent daemon")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = tokio::process::Command::new(bin)
            .args(["--endpoint", endpoint, "status"])
            .output()
            .await
            .context("ironrdp-agent status")?;
        if status.status.success() {
            return Ok(child);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "ironrdp-agent daemon not ready at {endpoint}: {}",
                String::from_utf8_lossy(&status.stderr)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn connect_ironrdp_rdcleanpath(
    bin: &Path,
    endpoint: &str,
    server: &str,
    token: &str,
    http_port: u16,
) -> anyhow::Result<tokio::process::Child> {
    let url = format!("ws://127.0.0.1:{http_port}/jet/rdp");
    tokio::process::Command::new(bin)
        .args([
            "--endpoint",
            endpoint,
            "connect",
            "--server",
            server,
            "--username",
            PROXY_USER,
            "--password",
            PROXY_PASSWORD,
            "--prop",
            &format!("ironrdp_rdcleanpathurl:s:{url}"),
            "--prop",
            &format!("ironrdp_rdcleanpathtoken:s:{token}"),
        ])
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start ironrdp-agent connect")
}

pub async fn agent_query_logs(bin: &Path, endpoint: &str) -> String {
    tokio::process::Command::new(bin)
        .args(["--endpoint", endpoint, "query-logs"])
        .output()
        .await
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}
