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
        for _ in 0..100 {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(unix)]
mod process_tree {
    use anyhow::{Context as _, ensure};

    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
        fn setsid() -> i32;
        fn getsid(pid: i32) -> i32;
    }

    pub(super) struct RunnerTree(i32);

    pub(super) fn start_session() -> std::io::Result<()> {
        // SAFETY: setsid is async-signal-safe and runs before the child execs.
        if unsafe { setsid() } == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    impl RunnerTree {
        pub(super) fn attach(pid: u32) -> anyhow::Result<Self> {
            let pid = i32::try_from(pid).context("runner PID exceeds process-group range")?;
            // SAFETY: The PID is the child returned by spawn.
            ensure!(unsafe { getsid(pid) } == pid, "runner has no dedicated Unix session");
            Ok(Self(pid))
        }

        pub(super) fn terminate(&self) {
            // SAFETY: The runner leads the original group; stopping it prevents new agent launches.
            let _ = unsafe { kill(-self.0, 9) };
            // Agents use separate process groups in this dedicated session.
            for _ in 0..3 {
                let output = std::process::Command::new("ps")
                    .args(["-e", "-o", "pid=", "-o", "sess="])
                    .output();
                let Ok(output) = output else {
                    break;
                };
                let mut found = false;
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let mut fields = line.split_whitespace();
                    let (Some(pid), Some(sid)) = (fields.next(), fields.next()) else {
                        continue;
                    };
                    let (Ok(pid), Ok(sid)) = (pid.parse::<i32>(), sid.parse::<i32>()) else {
                        continue;
                    };
                    if sid == self.0 {
                        // SAFETY: getsid rechecks that this PID still belongs to the isolated session.
                        if unsafe { getsid(pid) } == self.0 {
                            // SAFETY: This PID was verified as a member of this test's session.
                            let _ = unsafe { kill(pid, 9) };
                            found = true;
                        }
                    }
                }
                if !found {
                    break;
                }
            }
        }
    }

    pub(super) fn is_alive(pid: u32) -> bool {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        // SAFETY: Signal zero probes an existing process without modifying it.
        if unsafe { kill(pid, 0) } != 0 {
            return false;
        }
        let output = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output();
        output.is_ok_and(|output| {
            let state = String::from_utf8_lossy(&output.stdout);
            output.status.success() && !state.trim().is_empty() && !state.trim_start().starts_with('Z')
        })
    }
}

#[cfg(windows)]
mod process_tree {
    use std::ffi::c_void;
    use std::ptr;

    use anyhow::ensure;

    type Handle = *mut c_void;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_SET_QUOTA: u32 = 0x0100;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
        fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    pub(super) struct RunnerTree(Handle);

    // SAFETY: The owned Windows job handle remains valid across threads.
    unsafe impl Send for RunnerTree {}

    impl RunnerTree {
        pub(super) fn attach(pid: u32) -> anyhow::Result<Self> {
            // SAFETY: Null security attributes and name create a private job.
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            ensure!(
                !handle.is_null(),
                "create runner job: {}",
                std::io::Error::last_os_error()
            );
            let job = Self(handle);
            // SAFETY: The PID is the runner process spawned by this test.
            let process = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA, 0, pid) };
            ensure!(
                !process.is_null(),
                "open runner process for job assignment: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: Both handles remain valid until the assignment completes.
            let assigned = unsafe { AssignProcessToJobObject(job.0, process) };
            let error = std::io::Error::last_os_error();
            // SAFETY: OpenProcess returned an owned handle.
            let _ = unsafe { CloseHandle(process) };
            ensure!(assigned != 0, "assign runner process to job: {error}");
            Ok(job)
        }

        pub(super) fn terminate(&self) {
            // SAFETY: This handle is the private job owned by the test.
            let _ = unsafe { TerminateJobObject(self.0, 1) };
        }
    }

    impl Drop for RunnerTree {
        fn drop(&mut self) {
            // SAFETY: CreateJobObjectW returned this owned handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn is_alive(pid: u32) -> bool {
        // SAFETY: This handle is opened for a process that this test spawned.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return false;
        }
        let mut code = 0;
        // SAFETY: The handle remains valid while Windows writes the exit code.
        let result = unsafe { GetExitCodeProcess(process, &mut code) };
        // SAFETY: OpenProcess returned an owned handle.
        let _ = unsafe { CloseHandle(process) };
        result != 0 && code == 259
    }
}

struct RunnerProcess {
    child: Child,
    tree: process_tree::RunnerTree,
}

impl RunnerProcess {
    async fn start(mut command: Command) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            // SAFETY: The pre-exec hook only calls the async-signal-safe setsid syscall.
            unsafe { command.as_std_mut().pre_exec(process_tree::start_session) };
        }
        let mut child = command.spawn().context("start Agent Identity conformance")?;
        let pid = child.id().context("runner has no process ID")?;
        let tree = match process_tree::RunnerTree::attach(pid) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                return Err(error.context("isolate conformance process tree"));
            }
        };
        Ok(Self { child, tree })
    }
}

impl Drop for RunnerProcess {
    fn drop(&mut self) {
        self.tree.terminate();
        let _ = self.child.start_kill();
        for _ in 0..100 {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
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
    let stdout_path = first_dir.path().join("runner-stdout.log");
    let stderr_path = first_dir.path().join("runner-stderr.log");
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
        .stdout(Stdio::from(std::fs::File::create(&stdout_path)?))
        .stderr(Stdio::from(std::fs::File::create(&stderr_path)?))
        .kill_on_drop(true);
    let mut runner = RunnerProcess::start(cmd).await?;
    let status = tokio::time::timeout(Duration::from_secs(15 * 60), runner.child.wait())
        .await
        .context("Agent Identity conformance exceeded 15 minutes")?;
    print!("{}", String::from_utf8_lossy(&std::fs::read(stdout_path)?));
    eprint!("{}", String::from_utf8_lossy(&std::fs::read(stderr_path)?));
    let status = status.context("wait for Agent Identity conformance")?;
    ensure!(status.success(), "Agent Identity conformance failed ({})", status);
    Ok(())
}

#[test]
#[ignore = "helper for the outer-timeout process-tree regression"]
fn outer_timeout_runner_helper() -> anyhow::Result<()> {
    let Some(pid_path) = std::env::var_os("AGENT_IDENTITY_TREE_PID_FILE") else {
        return Ok(());
    };
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["--ignored", "--exact", "agent_identity::outer_timeout_agent_helper"])
        .env("AGENT_IDENTITY_TREE_SLEEP", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut agent = command.spawn().context("spawn separate agent process group")?;
    std::fs::write(pid_path, agent.id().to_string())?;
    let _ = agent.wait();
    Ok(())
}

#[test]
#[ignore = "helper for the outer-timeout process-tree regression"]
fn outer_timeout_agent_helper() {
    if std::env::var_os("AGENT_IDENTITY_TREE_SLEEP").is_some() {
        std::thread::sleep(Duration::from_secs(30));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn outer_timeout_kills_agent_group() -> anyhow::Result<()> {
    let work_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?
        .join("target")
        .join("agent-identity-timeout-tests");
    std::fs::create_dir_all(&work_dir)?;
    let scratch = tempfile::Builder::new().prefix("tree-").tempdir_in(work_dir)?;
    let pid_file = scratch.path().join("agent.pid");
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--ignored", "--exact", "agent_identity::outer_timeout_runner_helper"])
        .env("AGENT_IDENTITY_TREE_PID_FILE", &pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut runner = RunnerProcess::start(command).await?;
    let agent_pid = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(contents) = std::fs::read_to_string(&pid_file)
                && let Ok(pid) = contents.parse::<u32>()
            {
                return Ok::<_, anyhow::Error>(pid);
            }
            ensure!(
                runner.child.try_wait()?.is_none(),
                "runner helper exited before starting an agent"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("agent helper did not start")??;
    ensure!(
        process_tree::is_alive(agent_pid),
        "agent helper exited before the timeout"
    );
    ensure!(
        tokio::time::timeout(Duration::from_millis(50), runner.child.wait())
            .await
            .is_err(),
        "runner did not outlive the outer timeout"
    );
    drop(runner);
    let started = std::time::Instant::now();
    while process_tree::is_alive(agent_pid) {
        ensure!(
            started.elapsed() < Duration::from_secs(5),
            "outer timeout left an agent process alive"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}
