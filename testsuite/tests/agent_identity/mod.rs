use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, ensure};
use serde_json::Value;
use testsuite::cli;
use tokio::process::{Child, Command};

struct Mock {
    child: Child,
    base_url: String,
    ca_path: PathBuf,
    authority_id: String,
    admin_token: String,
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn start_mock(state_dir: &Path) -> anyhow::Result<Mock> {
    let token = format!("conformance-admin-{}", uuid::Uuid::new_v4());
    let mut child = Command::new(cli::agent_identity_mock_path())
        .args(["--listen", "127.0.0.1:0", "--path-prefix", "/mock", "--admin-token"])
        .arg(&token)
        .arg("--state-dir")
        .arg(state_dir)
        .stdout(Stdio::from(std::fs::File::create(state_dir.join("mock-stdout.log"))?))
        .stderr(Stdio::from(std::fs::File::create(state_dir.join("mock-stderr.log"))?))
        .kill_on_drop(true)
        .spawn()
        .context("start Agent Identity mock")?;
    let ready_path = state_dir.join("ready.json");
    let ready = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(bytes) = std::fs::read(&ready_path) {
                return serde_json::from_slice::<Value>(&bytes).context("parse mock ready.json");
            }
            ensure!(child.try_wait()?.is_none(), "mock exited before ready.json");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("mock did not become ready")??;
    Ok(Mock {
        child,
        base_url: ready["base_url"].as_str().context("mock base_url")?.to_owned(),
        ca_path: PathBuf::from(ready["tls_ca_pem"].as_str().context("mock tls_ca_pem")?),
        authority_id: ready["authority_id"].as_str().context("mock authority_id")?.to_owned(),
        admin_token: token,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance() -> anyhow::Result<()> {
    let project_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let agent_version = std::fs::read_to_string(project_dir.join("VERSION")).context("read workspace VERSION")?;
    let agent_version = agent_version.trim();
    ensure!(!agent_version.is_empty(), "workspace VERSION is empty");
    let work_dir = project_dir.join("target").join("agent-identity-integration");
    std::fs::create_dir_all(&work_dir)?;
    let first_dir = tempfile::Builder::new().prefix("mock-1-").tempdir_in(&work_dir)?;
    let second_dir = tempfile::Builder::new().prefix("mock-2-").tempdir_in(&work_dir)?;
    let first = start_mock(first_dir.path()).await?;
    let second = start_mock(second_dir.path()).await?;
    let mut cmd = Command::new(cli::agent_identity_conformance_path());
    cmd.args(["--target", "mock", "--base-url"])
        .arg(&first.base_url)
        .arg("--admin-token")
        .arg(&first.admin_token)
        .arg("--authority-id")
        .arg(&first.authority_id)
        .arg("--extra-trusted-root")
        .arg(&first.ca_path)
        .arg("--second-base-url")
        .arg(&second.base_url)
        .arg("--second-admin-token")
        .arg(&second.admin_token)
        .arg("--second-authority-id")
        .arg(&second.authority_id)
        .arg("--second-extra-trusted-root")
        .arg(&second.ca_path)
        .arg("--agent-bin")
        .arg(cli::agent_path())
        .arg("--agent-version")
        .arg(agent_version)
        .arg("--work-dir")
        .arg(first_dir.path().join("runner"))
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(15 * 60), cmd.output())
        .await
        .context("Agent Identity conformance exceeded 15 minutes")?
        .context("run Agent Identity conformance")?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    ensure!(
        output.status.success(),
        "Agent Identity conformance failed ({})",
        output.status
    );
    Ok(())
}
