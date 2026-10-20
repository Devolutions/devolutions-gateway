use std::path::PathBuf;
use std::process::{Command, Output};

use anyhow::{Context as _, ensure};

use super::agent_identity_conformance_path;

/// Runs one conformance test against an unreachable DVLS target, where no test can reach the network.
fn run_against_dvls(filter: &str, allow_incomplete: bool) -> anyhow::Result<(Output, String)> {
    let scratch = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?
        .join("target")
        .join("agent-identity-skip-tests");
    std::fs::create_dir_all(&scratch)?;
    let work_dir = tempfile::Builder::new().prefix("skip-").tempdir_in(scratch)?;
    let bin = agent_identity_conformance_path();
    let mut command = Command::new(bin);
    command
        .args([
            "--target",
            "dvls",
            "--base-url",
            "https://127.0.0.1:1",
            "--app-key",
            "unused",
            "--app-secret",
            "unused",
            "--filter",
            filter,
        ])
        .arg("--agent-bin")
        .arg(bin)
        .arg("--work-dir")
        .arg(work_dir.path());
    if allow_incomplete {
        command.arg("--allow-incomplete");
    }
    let output = command.output().context("run the conformance runner")?;
    let stdout = String::from_utf8(output.stdout.clone())?;
    Ok((output, stdout))
}

fn assert_single_skip(filter: &str) -> anyhow::Result<()> {
    let (denied, denied_stdout) = run_against_dvls(filter, false)?;
    let (allowed, allowed_stdout) = run_against_dvls(filter, true)?;
    ensure!(
        denied.status.code() == Some(1) && allowed.status.success(),
        "SKIP of {filter} did not follow the --allow-incomplete exit policy"
    );
    for stdout in [denied_stdout, allowed_stdout] {
        ensure!(
            stdout.contains(&format!("SKIP {filter}")) && stdout.contains("SUMMARY PASS 0 FAIL 0 SKIP 1 N/A 0"),
            "{filter} was not reported as an incomplete SKIP:\n{stdout}"
        );
    }
    Ok(())
}

fn assert_single_not_applicable(filter: &str) -> anyhow::Result<()> {
    let (output, stdout) = run_against_dvls(filter, false)?;
    ensure!(
        output.status.success()
            && stdout.contains(&format!("N/A {filter}"))
            && stdout.contains("SUMMARY PASS 0 FAIL 0 SKIP 0 N/A 1"),
        "{filter} was not reported as a complete N/A run:\n{stdout}"
    );
    Ok(())
}

#[test]
fn missing_second_authority_is_skip() -> anyhow::Result<()> {
    assert_single_skip("a_multi_authority")
}

#[test]
fn dvls_stale_hello_without_config_fixture_is_skip() -> anyhow::Result<()> {
    assert_single_skip("p_config_hello_reconciles_stale_revision")
}

#[test]
fn mock_only_test_on_dvls_is_not_applicable() -> anyhow::Result<()> {
    assert_single_not_applicable("p_token_expired")
}

#[cfg(windows)]
#[test]
fn unix_only_test_on_windows_is_not_applicable() -> anyhow::Result<()> {
    assert_single_not_applicable("a_file_backend_permissions")
}

#[cfg(unix)]
#[test]
fn windows_only_test_on_unix_is_not_applicable() -> anyhow::Result<()> {
    assert_single_not_applicable("a_key_non_exportable")
}
