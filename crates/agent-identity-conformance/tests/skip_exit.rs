use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, ensure};

#[test]
fn missing_second_authority_requires_allow_incomplete() -> anyhow::Result<()> {
    let bin = env!("CARGO_BIN_EXE_agent-identity-conformance");
    let work_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("agent-identity-skip-tests");
    std::fs::create_dir_all(&work_dir)?;
    let work_dir = tempfile::Builder::new().prefix("skip-").tempdir_in(work_dir)?;
    let run = |allow_incomplete| {
        let mut command = Command::new(bin);
        command.args([
            "--target",
            "dvls",
            "--base-url",
            "https://127.0.0.1:1",
            "--admin-token",
            "unused",
            "--agent-bin",
            bin,
            "--filter",
            "a_multi_authority",
            "--work-dir",
        ]);
        command.arg(work_dir.path());
        if allow_incomplete {
            command.arg("--allow-incomplete");
        }
        command.output().context("run conformance SKIP fixture")
    };
    let denied = run(false)?;
    let allowed = run(true)?;
    let denied_output = std::str::from_utf8(&denied.stdout)?;
    let allowed_output = std::str::from_utf8(&allowed.stdout)?;
    ensure!(
        denied.status.code() == Some(1) && allowed.status.success(),
        "SKIP did not follow --allow-incomplete exit policy"
    );
    for output in [denied_output, allowed_output] {
        ensure!(
            output.contains("SKIP a_multi_authority") && output.contains("SUMMARY PASS 0 FAIL 0 SKIP 1 N/A 0"),
            "SKIP fixture did not report an incomplete run"
        );
    }
    Ok(())
}
