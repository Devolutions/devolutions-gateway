#![allow(clippy::unwrap_used, reason = "test infrastructure can panic on errors")]

use std::sync::LazyLock;

static JETSOCAT_BIN_PATH: LazyLock<std::path::PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path("../jetsocat/Cargo.toml")
        .bin("jetsocat")
        .current_release()
        .current_target()
        .run()
        .expect("build jetsocat")
        .path()
        .to_path_buf()
});

pub fn jetsocat_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*JETSOCAT_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn jetsocat_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new(&*JETSOCAT_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn jetsocat_tokio_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&*JETSOCAT_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

static DGW_BIN_PATH: LazyLock<std::path::PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path("../devolutions-gateway/Cargo.toml")
        .bin("devolutions-gateway")
        .current_release()
        .current_target()
        .run()
        .expect("build Devolutions Gateway")
        .path()
        .to_path_buf()
});

pub fn dgw_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*DGW_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn dgw_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new(&*DGW_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn dgw_tokio_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&*DGW_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn assert_stderr_eq(output: &assert_cmd::assert::Assert, expected: expect_test::Expect) {
    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    expected.assert_eq(stderr);
}

/// Waits for a TCP port on localhost to become ready (accepting connections).
///
/// This is useful for tests that spawn a server process and need to wait for it to be ready
/// before sending requests. Polls every 50ms until the connection succeeds or 10 seconds elapse.
///
/// # Errors
/// Returns an error if the port is not ready within the timeout.
pub async fn wait_for_tcp_port(port: u16) -> anyhow::Result<()> {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    let timeout = Duration::from_secs(10);
    let poll_interval = Duration::from_millis(50);
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("port {port} did not become ready within {timeout:?}");
        }

        match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
            Ok(_) => return Ok(()),
            Err(_) => tokio::time::sleep(poll_interval).await,
        }
    }
}
