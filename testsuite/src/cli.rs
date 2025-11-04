#![expect(clippy::unwrap_used, reason = "test infrastructure can panic on errors")]

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

pub fn assert_stderr_eq(output: &assert_cmd::assert::Assert, expected: expect_test::Expect) {
    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    expected.assert_eq(stderr);
}
