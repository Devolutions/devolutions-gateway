use std::process::{Command, Output};

use anyhow::{Context as _, ensure};

use super::agent_identity_conformance_path;

/// Runs one conformance test against an unreachable DVLS target, where no test can reach the network.
fn run_against_dvls(filter: &str, allow_incomplete: bool) -> anyhow::Result<(Output, String)> {
    // On Windows the runner refuses a `--work-dir` too long for key file paths to fit the Windows path limit, which a
    // directory under a checkout's `target` exceeds; the temporary directory is short, and no test here starts an agent.
    let work_dir = tempfile::Builder::new().prefix("skip-").tempdir()?;
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

/// The outcome lines of a run, as `(outcome, test)` pairs, in the order the runner printed them.
fn outcomes(stdout: &str) -> Vec<(&str, &str)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let outcome = words.next()?;
            let test = words.next()?;
            ["PASS", "FAIL", "SKIP", "N/A"]
                .contains(&outcome)
                .then_some((outcome, test))
        })
        .collect()
}

fn assert_single_skip(filter: &str) -> anyhow::Result<()> {
    let (denied, denied_stdout) = run_against_dvls(filter, false)?;
    let (allowed, allowed_stdout) = run_against_dvls(filter, true)?;
    ensure!(
        !denied.status.success() && allowed.status.success(),
        "SKIP of {filter} did not follow the --allow-incomplete exit policy"
    );
    for stdout in [denied_stdout, allowed_stdout] {
        ensure!(
            outcomes(&stdout) == [("SKIP", filter)],
            "{filter} was not reported as a SKIP:\n{stdout}"
        );
    }
    Ok(())
}

fn assert_single_not_applicable(filter: &str) -> anyhow::Result<()> {
    let (output, stdout) = run_against_dvls(filter, false)?;
    ensure!(
        output.status.success() && outcomes(&stdout) == [("N/A", filter)],
        "{filter} was not reported as a complete N/A run:\n{stdout}"
    );
    Ok(())
}

#[test]
fn missing_second_authority_is_skip() -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
    assert_single_skip("a_multi_authority")
}

#[test]
fn dvls_stale_hello_without_config_fixture_is_skip() -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
    assert_single_skip("p_config_hello_reconciles_stale_revision")
}

#[test]
fn mock_only_test_on_dvls_is_not_applicable() -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
    assert_single_not_applicable("p_token_expired")
}

#[cfg(windows)]
#[test]
fn unix_only_test_on_windows_is_not_applicable() -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
    assert_single_not_applicable("a_file_backend_permissions")
}

#[cfg(unix)]
#[test]
fn windows_only_test_on_unix_is_not_applicable() -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
    assert_single_not_applicable("a_key_non_exportable")
}
