#![allow(clippy::unwrap_used, reason = "test infrastructure can panic on errors")]

use std::sync::LazyLock;

static JETSOCAT_BIN_PATH: LazyLock<std::path::PathBuf> = LazyLock::new(|| {
    let mut build = escargot::CargoBuild::new()
        .manifest_path("../jetsocat/Cargo.toml")
        .bin("jetsocat")
        .current_release()
        .current_target();

    // Match CI: on Windows, build with native-tls instead of the default rustls.
    if cfg!(windows) {
        build = build.no_default_features().features("native-tls detect-proxy");
    }

    build.run().expect("build jetsocat").path().to_path_buf()
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

/// Waits until a TCP port on localhost is bound by another process, without connecting to it.
///
/// Use this instead of [`wait_for_tcp_port`] when the target listener accepts only a single
/// connection (e.g. `tcp-listen://` or `ws-listen://` in jetsocat). Connecting to such a
/// listener would consume its one accept slot. Instead, this function attempts to bind the same
/// port itself; `AddrInUse` means the target process has already claimed it.
///
/// Polls every 50ms until the port is seen as bound or 10 seconds elapse.
///
/// # Errors
/// Returns an error if the port is not bound within the timeout.
pub async fn wait_for_port_bound(port: u16) -> anyhow::Result<()> {
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    let timeout = Duration::from_secs(10);
    let poll_interval = Duration::from_millis(50);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("port {port} was not bound within {timeout:?}");
        }

        match tokio::net::TcpListener::bind(addr).await {
            // We managed to bind it ourselves — the target hasn't claimed it yet.
            // Explicitly drop before awaiting: in async/await state machines, temporaries in
            // match arms can be kept alive across the await point, which would leave the port
            // bound while we sleep and prevent the target from claiming it.
            Ok(listener) => {
                drop(listener);
                tokio::time::sleep(poll_interval).await;
            }
            // Someone else owns the port — the target process is ready.
            // On Linux this is AddrInUse; on Windows with SO_EXCLUSIVEADDRUSE it is
            // PermissionDenied (WSAEACCES).
            Err(e) if matches!(e.kind(), ErrorKind::AddrInUse | ErrorKind::PermissionDenied) => return Ok(()),
            // Any other error is unexpected; surface it.
            Err(e) => return Err(e.into()),
        }
    }
}
