//! CLI argument parsing integration tests for Devolutions Gateway.
//!
//! These tests exercise the binary's argument parsing without side effects.
//! `service register` / `service unregister` are intentionally excluded because
//! they interact with the OS service manager, which is not appropriate in a test
//! environment.

use tempfile::TempDir;
use testsuite::cli::dgw_assert_cmd;

/// `--config-init-only` must print a valid JSON config and exit 0.
///
/// `DGATEWAY_CONFIG_PATH` is set to a temp directory so any file writes are
/// contained and do not affect the host system.
#[test]
fn config_init_only_prints_json() {
    let tmp = TempDir::new().expect("create temp dir");

    let output = dgw_assert_cmd()
        .arg("--config-init-only")
        .env("DGATEWAY_CONFIG_PATH", tmp.path())
        .assert()
        .success();

    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();
    // The last line printed is the JSON config; find it.
    let json_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .expect("expected JSON object in stdout");

    serde_json::from_str::<serde_json::Value>(
        // The JSON spans multiple lines; collect from the first `{` to end.
        &stdout[stdout.find('{').expect("opening brace")..],
    )
    .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout:\n{stdout}"));

    let _ = json_line; // suppress unused warning
}

/// `--config-path <dir> --config-init-only` must honour the explicit config path.
///
/// The gateway should write a fresh `gateway.json` into the given directory and
/// print the config to stdout.
#[test]
fn config_path_flag_redirects_config_dir() {
    let tmp = TempDir::new().expect("create temp dir");

    let output = dgw_assert_cmd()
        .args(["--config-path", tmp.path().to_str().unwrap(), "--config-init-only"])
        .assert()
        .success();

    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();
    serde_json::from_str::<serde_json::Value>(&stdout[stdout.find('{').expect("opening brace in stdout")..])
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout:\n{stdout}"));

    // The config file should have been created in the temp directory.
    assert!(
        tmp.path().join("gateway.json").exists(),
        "expected gateway.json to be written to the temp dir"
    );
}
