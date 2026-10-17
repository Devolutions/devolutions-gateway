use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::{AgentCase, POLL, WAIT, new_token};
use crate::Context;
use crate::client::{Target, Token, count, expect_status, field};
use crate::system_probe::{Request, ResultFile};

const TASK_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const INSPECTION_TIMEOUT: Duration = Duration::from_secs(35);

fn task_output(output: Output, operation: &str) -> anyhow::Result<()> {
    ensure!(
        output.status.success(),
        "scheduled task {operation} failed ({}): {} {}",
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

async fn task_command_output(args: &[&str]) -> anyhow::Result<Output> {
    tokio::time::timeout(
        TASK_TIMEOUT,
        tokio::process::Command::new("schtasks.exe")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("scheduled task command timed out")?
    .context("execute schtasks.exe")
}

async fn task_command(args: &[&str]) -> anyhow::Result<()> {
    task_output(task_command_output(args).await?, args[0])
}

fn task_command_blocking_output(args: &[&str]) -> anyhow::Result<Output> {
    let mut child = std::process::Command::new("schtasks.exe")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("execute schtasks.exe for cleanup")?;
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map_err(Into::into);
        }
        if started.elapsed() >= TASK_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("scheduled task {} timed out during cleanup", args[0]);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn task_command_blocking(args: &[&str]) -> anyhow::Result<()> {
    task_output(task_command_blocking_output(args)?, args[0])
}

fn task_absent_from_query(output: &Output) -> anyhow::Result<bool> {
    if output.status.success() {
        return Ok(false);
    }
    let message = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        message.to_ascii_lowercase().contains("cannot find the file specified"),
        "cannot verify scheduled task absence: {message}"
    );
    Ok(true)
}

async fn task_absent(name: &str) -> anyhow::Result<bool> {
    task_absent_from_query(&task_command_output(&["/Query", "/TN", name, "/FO", "LIST"]).await?)
}

fn task_absent_blocking(name: &str) -> anyhow::Result<bool> {
    task_absent_from_query(&task_command_blocking_output(&["/Query", "/TN", name, "/FO", "LIST"])?)
}

async fn delete_task(name: &str) -> anyhow::Result<()> {
    let deleted = task_command(&["/Delete", "/TN", name, "/F"]).await;
    ensure!(
        task_absent(name).await?,
        "scheduled task {name} remains after deletion attempt: {}",
        deleted
            .err()
            .map_or_else(|| "delete returned success".to_owned(), |error| format!("{error:#}"))
    );
    Ok(())
}

fn delete_task_blocking(name: &str) -> anyhow::Result<()> {
    let deleted = task_command_blocking(&["/Delete", "/TN", name, "/F"]);
    ensure!(
        task_absent_blocking(name)?,
        "scheduled task {name} remains after deletion attempt: {}",
        deleted
            .err()
            .map_or_else(|| "delete returned success".to_owned(), |error| format!("{error:#}"))
    );
    Ok(())
}

async fn end_task(name: &str) -> anyhow::Result<()> {
    let result = task_command(&["/End", "/TN", name]).await;
    if result.is_ok() || task_absent(name).await? {
        return Ok(());
    }
    result
}

fn end_task_blocking(name: &str) -> anyhow::Result<()> {
    let result = task_command_blocking(&["/End", "/TN", name]);
    if result.is_ok() || task_absent_blocking(name)? {
        return Ok(());
    }
    result
}

fn powershell_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}

fn absolute(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn write_powershell_script(path: &Path, script: &str) -> anyhow::Result<()> {
    let mut bytes = vec![0xff, 0xfe];
    for code_unit in script.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    crate::windows::write_protected_file(path, &bytes)
}

fn task_action(script: &Path) -> String {
    format!("cmd.exe /d /s /c \"\"{}\"\"", script.display())
}

fn create_task_args<'a>(name: &'a str, action: &'a str) -> [&'a str; 14] {
    [
        "/Create", "/TN", name, "/TR", action, "/SC", "ONCE", "/ST", "23:59", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F",
    ]
}

fn cleanup_error(errors: &mut Vec<String>, action: &str, error: &anyhow::Error) {
    eprintln!("SYSTEM fixture cleanup: {action}: {error:#}");
    errors.push(format!("{action}: {error:#}"));
}

async fn serve_probe_token(listener: &TcpListener, nonce: uuid::Uuid, token: &str) -> anyhow::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut offered = [0u8; 16];
        let authenticated = tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut offered))
            .await
            .is_ok_and(|read| read.is_ok() && offered == *nonce.as_bytes());
        if !authenticated {
            continue;
        }
        stream.write_all(&u32::try_from(token.len())?.to_le_bytes()).await?;
        stream.write_all(token.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }
}

struct SystemFixture {
    case: AgentCase,
    pid_file: PathBuf,
    request: Request,
    request_path: PathBuf,
    result_path: PathBuf,
    agent_task: String,
    probe_task: String,
    agent_registered: bool,
    probe_registered: bool,
    agent_registration_attempted: bool,
    probe_registration_attempted: bool,
    agent_may_have_started: bool,
    cleanup_verified: bool,
    cleaned: bool,
}

impl SystemFixture {
    fn new(case: AgentCase) -> anyhow::Result<Self> {
        let task_base = format!("DevolutionsAgentIdentityConformance-{}", uuid::Uuid::new_v4());
        let request_path = case.path().join("system-probe-request.json");
        let result_path = case.path().join("system-probe-result.json");
        let pid_file = case.path().join("system-agent.pid");
        let system_agent_bin = case.path().join(
            case.ctx
                .agent_bin
                .file_name()
                .context("agent executable has no file name")?,
        );
        std::fs::copy(&case.ctx.agent_bin, &system_agent_bin)
            .context("copy agent for case-specific process cleanup")?;
        let request = Request {
            case_dir: case.path().to_path_buf(),
            agent_bin: system_agent_bin,
            key_name_prefix: case.ctx.key_name_prefix.clone(),
            device_id: None,
            token_port: None,
            token_nonce: None,
            cleanup_only: true,
        };
        let fixture = Self {
            case,
            pid_file,
            request,
            request_path,
            result_path,
            agent_task: format!("{task_base}-Agent"),
            probe_task: format!("{task_base}-Probe"),
            agent_registered: false,
            probe_registered: false,
            agent_registration_attempted: false,
            probe_registration_attempted: false,
            agent_may_have_started: false,
            cleanup_verified: false,
            cleaned: false,
        };
        fixture.write_wrappers()?;
        Ok(fixture)
    }

    fn write_wrappers(&self) -> anyhow::Result<()> {
        let dir = self.case.path();
        crate::windows::write_protected_file(&self.pid_file, b"")?;
        crate::windows::write_protected_file(&self.request_path, b"")?;
        crate::windows::write_protected_file(&self.result_path, b"")?;
        for name in [
            "agent-stdout.log",
            "agent-stderr.log",
            "system-agent-wrapper-stdout.log",
            "system-agent-wrapper-stderr.log",
            "system-agent-wrapper-error.log",
            "system-probe-stdout.log",
            "system-probe-stderr.log",
            "cli-stdout.log",
            "cli-stderr.log",
        ] {
            crate::windows::write_protected_file(&dir.join(name), b"")?;
        }
        let agent_script = dir.join("system-agent.ps1");
        let wrapper_error = dir.join("system-agent-wrapper-error.log");
        let original_bin_dir = self
            .case
            .ctx
            .agent_bin
            .parent()
            .context("agent executable has no parent directory")?;
        let script = format!(
            "\
$ErrorActionPreference = 'Stop'\r\n\
$env:DAGENT_CONFIG_PATH = {config}\r\n\
$env:PATH = {binary_dir} + [IO.Path]::PathSeparator + $env:PATH\r\n\
try {{\r\n\
    $agent = Start-Process -FilePath {binary} -ArgumentList 'run' -WorkingDirectory {config} -RedirectStandardOutput {stdout} -RedirectStandardError {stderr} -PassThru\r\n\
    [System.IO.File]::WriteAllText({pid}, $agent.Id.ToString())\r\n\
    $agent.WaitForExit()\r\n\
    exit $agent.ExitCode\r\n\
}} catch {{\r\n\
    [System.IO.File]::AppendAllText({error}, $_.ToString() + [Environment]::NewLine)\r\n\
    exit 1\r\n\
}}\r\n",
            config = powershell_literal(dir),
            binary_dir = powershell_literal(original_bin_dir),
            binary = powershell_literal(&self.request.agent_bin),
            stdout = powershell_literal(&dir.join("agent-stdout.log")),
            stderr = powershell_literal(&dir.join("agent-stderr.log")),
            pid = powershell_literal(&self.pid_file),
            error = powershell_literal(&wrapper_error),
        );
        write_powershell_script(&agent_script, &script)?;
        let cmd = format!(
            "@echo off\r\npowershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\" 1>> \"{}\" 2>> \"{}\"\r\n",
            agent_script.display(),
            dir.join("system-agent-wrapper-stdout.log").display(),
            dir.join("system-agent-wrapper-stderr.log").display()
        );
        crate::windows::write_protected_file(&dir.join("system-agent.cmd"), cmd.as_bytes())?;

        let probe_cmd = format!(
            "@echo off\r\n\"{}\" --system-probe \"{}\" \"{}\" 1>> \"{}\" 2>> \"{}\"\r\n",
            std::env::current_exe()?.display(),
            self.request_path.display(),
            self.result_path.display(),
            dir.join("system-probe-stdout.log").display(),
            dir.join("system-probe-stderr.log").display()
        );
        crate::windows::write_protected_file(&dir.join("system-probe.cmd"), probe_cmd.as_bytes())?;
        Ok(())
    }

    async fn register(&mut self) -> anyhow::Result<()> {
        let probe_action = task_action(&self.case.path().join("system-probe.cmd"));
        self.probe_registration_attempted = true;
        task_command(&create_task_args(&self.probe_task, &probe_action)).await?;
        self.probe_registered = true;
        let agent_action = task_action(&self.case.path().join("system-agent.cmd"));
        self.agent_registration_attempted = true;
        self.agent_may_have_started = true;
        task_command(&create_task_args(&self.agent_task, &agent_action)).await?;
        self.agent_registered = true;
        task_command(&["/Run", "/TN", &self.agent_task]).await
    }

    async fn wait_for_agent(&self) -> anyhow::Result<()> {
        let started = Instant::now();
        loop {
            match crate::windows::system_agent_running(&self.pid_file, &self.request.agent_bin)? {
                Some(true) => return Ok(()),
                Some(false) => anyhow::bail!("SYSTEM agent exited before the fixture was ready"),
                None => {}
            }
            ensure!(
                started.elapsed() < Duration::from_secs(15),
                "SYSTEM scheduled task did not start the agent within 15 seconds"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    async fn submit_token(&self, token: &str) -> anyhow::Result<()> {
        let started = Instant::now();
        loop {
            let output = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::process::Command::new(&self.request.agent_bin)
                    .args(["identity", "enroll", token])
                    .env("DAGENT_CONFIG_PATH", self.case.path())
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .context("identity enroll CLI timed out")?
            .context("run identity enroll CLI as administrator")?;
            for (name, contents) in [("cli-stdout.log", &output.stdout), ("cli-stderr.log", &output.stderr)] {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(self.case.path().join(name))?
                    .write_all(contents)?;
            }
            if output.status.success() {
                return Ok(());
            }
            ensure!(
                started.elapsed() < Duration::from_secs(30),
                "identity enroll CLI did not accept the token within 30 seconds"
            );
            ensure!(
                crate::windows::system_agent_running(&self.pid_file, &self.request.agent_bin)? == Some(true),
                "SYSTEM agent exited before identity enroll CLI succeeded"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn enrolled_device(&self, target: &Target, token: &Token) -> anyhow::Result<String> {
        let started = Instant::now();
        loop {
            let listing = target.devices_for(token, "&view=full").await?;
            expect_status(&listing, 200)?;
            let devices = count(&listing.body, "totalCount")?;
            ensure!(
                devices <= 1,
                "SYSTEM agent created multiple devices for a one-use token"
            );
            if devices == 1 {
                let device = &listing.body["data"][0];
                let id = field(device, "id")?.to_owned();
                self.case.observe_agent_metadata(device)?;
                let record = target.token_record(&token.id).await?;
                expect_status(&record, 200)?;
                ensure!(
                    count(&record.body, "usedCount")? == 1,
                    "SYSTEM agent did not consume its one-use token"
                );
                return Ok(id);
            }
            ensure!(
                crate::windows::system_agent_running(&self.pid_file, &self.request.agent_bin)? == Some(true),
                "SYSTEM agent exited before enrollment"
            );
            ensure!(
                started.elapsed() < WAIT,
                "SYSTEM agent did not enroll within 20 seconds"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    async fn signed_traffic(&mut self, target: &Target, id: &str) -> anyhow::Result<()> {
        let check_channel = self.case.ctx.channel_available;
        if !check_channel {
            self.case.set_metadata_hostname("system-acl-signing-probe")?;
        }
        let started = Instant::now();
        loop {
            let response = target.device(id).await?;
            expect_status(&response, 200)?;
            self.case.observe_agent_metadata(&response.body)?;
            if (check_channel && response.body["connected"] == true)
                || (!check_channel && response.body["metadata"]["hostname"] == "system-acl-signing-probe")
            {
                return Ok(());
            }
            ensure!(
                crate::windows::system_agent_running(&self.pid_file, &self.request.agent_bin)? == Some(true),
                "SYSTEM agent exited before signed Hello or check-in"
            );
            ensure!(
                started.elapsed() < WAIT,
                "SYSTEM agent did not send a signed Hello or check-in within 20 seconds"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    fn prepare_probe(&mut self, cleanup_only: bool) -> anyhow::Result<()> {
        self.request.cleanup_only = cleanup_only;
        std::fs::write(&self.request_path, serde_json::to_vec(&self.request)?)?;
        std::fs::write(&self.result_path, b"")?;
        Ok(())
    }

    fn probe_result(&self) -> anyhow::Result<Option<()>> {
        let bytes = std::fs::read(&self.result_path)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let Ok(result) = serde_json::from_slice::<ResultFile>(&bytes) else {
            return Ok(None);
        };
        ensure!(
            result.success,
            "SYSTEM probe failed: {}",
            result.error.as_deref().unwrap_or("no reason given")
        );
        Ok(Some(()))
    }

    async fn probe(&mut self, cleanup_only: bool) -> anyhow::Result<()> {
        let channel = if cleanup_only {
            self.request.token_port = None;
            self.request.token_nonce = None;
            None
        } else {
            // The full token only crosses this short-lived loopback channel; its nonce stays in the protected request.
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let nonce = uuid::Uuid::new_v4();
            self.request.token_port = Some(listener.local_addr()?.port());
            self.request.token_nonce = Some(nonce);
            Some((listener, nonce))
        };
        self.prepare_probe(cleanup_only)?;
        task_command(&["/Run", "/TN", &self.probe_task]).await?;
        if let Some((listener, nonce)) = channel {
            let token = self.case.tokens.last().context("SYSTEM probe has no enrolled token")?;
            tokio::time::timeout(PROBE_TIMEOUT, serve_probe_token(&listener, nonce, token))
                .await
                .context("SYSTEM probe token channel timed out")??;
        }
        let started = Instant::now();
        let timeout = if cleanup_only {
            PROBE_TIMEOUT
        } else {
            INSPECTION_TIMEOUT
        };
        loop {
            if self.probe_result()?.is_some() {
                return Ok(());
            }
            ensure!(
                started.elapsed() < timeout,
                "SYSTEM probe returned no readable result within {} seconds",
                timeout.as_secs()
            );
            tokio::time::sleep(POLL).await;
        }
    }

    fn probe_blocking(&mut self) -> anyhow::Result<()> {
        self.request.token_port = None;
        self.request.token_nonce = None;
        self.prepare_probe(true)?;
        task_command_blocking(&["/Run", "/TN", &self.probe_task])?;
        let started = Instant::now();
        loop {
            if self.probe_result()?.is_some() {
                return Ok(());
            }
            ensure!(
                started.elapsed() < PROBE_TIMEOUT,
                "SYSTEM cleanup probe returned no readable result within 20 seconds"
            );
            std::thread::sleep(POLL);
        }
    }

    async fn execute(&mut self) -> anyhow::Result<()> {
        let target = self.case.ctx.target.clone();
        let token = new_token(&self.case, 1).await?;
        self.case.add_token(&token.text);
        self.register().await?;
        self.wait_for_agent().await?;
        self.submit_token(&token.text).await?;
        let id = self.enrolled_device(&target, &token).await?;
        self.signed_traffic(&target, &id).await?;
        self.request.device_id = Some(id);
        self.probe(false).await
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        let mut errors = Vec::new();
        if let Err(error) = end_task(&self.agent_task).await {
            eprintln!("SYSTEM fixture cleanup: end agent task: {error:#}");
        }
        if self.agent_may_have_started {
            if self.probe_registered {
                if self.request.device_id.is_some() {
                    let _ = end_task(&self.probe_task).await;
                }
                for attempt in 1..=2 {
                    match self.probe(true).await {
                        Ok(()) => {
                            self.cleanup_verified = true;
                            break;
                        }
                        Err(error) => {
                            eprintln!("SYSTEM fixture cleanup: probe attempt {attempt}: {error:#}");
                            let _ = end_task(&self.probe_task).await;
                            if attempt == 2 {
                                errors.push(format!("remove key and stop agent through probe: {error:#}"));
                            }
                        }
                    }
                }
            } else {
                errors.push("SYSTEM cleanup probe task was not registered".to_owned());
            }
        } else {
            self.cleanup_verified = true;
        }
        if let Err(error) = end_task(&self.probe_task).await {
            eprintln!("SYSTEM fixture cleanup: end probe task: {error:#}");
        }
        for (attempted, registered, name) in [
            (
                &mut self.agent_registration_attempted,
                &mut self.agent_registered,
                &self.agent_task,
            ),
            (
                &mut self.probe_registration_attempted,
                &mut self.probe_registered,
                &self.probe_task,
            ),
        ] {
            match delete_task(name).await {
                Ok(()) => {
                    *attempted = false;
                    *registered = false;
                }
                Err(error) => cleanup_error(&mut errors, &format!("delete task {name}"), &error),
            }
        }
        if let Err(error) = crate::windows::stop_system_agent(&self.request.agent_bin) {
            cleanup_error(&mut errors, "stop case agent by exact image", &error);
        }
        match crate::windows::case_agent_processes(&self.request.agent_bin) {
            Ok(pids) if !pids.is_empty() => {
                self.cleanup_verified = false;
                errors.push(format!("SYSTEM agent PIDs still running: {pids:?}"));
            }
            Ok(_) => {}
            Err(error) => {
                self.cleanup_verified = false;
                cleanup_error(&mut errors, "verify agent exit", &error);
            }
        }
        self.cleaned = self.cleanup_verified
            && !self.agent_registration_attempted
            && !self.probe_registration_attempted
            && errors.is_empty();
        ensure!(
            errors.is_empty(),
            "SYSTEM fixture cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }

    fn cleanup_blocking(&mut self) {
        let mut errors = Vec::new();
        if let Err(error) = end_task_blocking(&self.agent_task) {
            eprintln!("SYSTEM fixture cleanup: end agent task: {error:#}");
        }
        if self.agent_may_have_started && !self.cleanup_verified {
            if !self.probe_registered {
                let action = task_action(&self.case.path().join("system-probe.cmd"));
                self.probe_registration_attempted = true;
                match task_command_blocking(&create_task_args(&self.probe_task, &action)) {
                    Ok(()) => self.probe_registered = true,
                    Err(error) => cleanup_error(&mut errors, "register fallback probe task", &error),
                }
            }
            if self.probe_registered {
                let _ = end_task_blocking(&self.probe_task);
                for attempt in 1..=2 {
                    match self.probe_blocking() {
                        Ok(()) => {
                            self.cleanup_verified = true;
                            break;
                        }
                        Err(error) => {
                            eprintln!("SYSTEM fixture cleanup: blocking probe attempt {attempt}: {error:#}");
                            let _ = end_task_blocking(&self.probe_task);
                            if attempt == 2 {
                                errors.push(format!("remove key and stop agent through probe: {error:#}"));
                            }
                        }
                    }
                }
            }
        }
        if let Err(error) = end_task_blocking(&self.probe_task) {
            eprintln!("SYSTEM fixture cleanup: end probe task: {error:#}");
        }
        for (attempted, registered, name) in [
            (
                &mut self.agent_registration_attempted,
                &mut self.agent_registered,
                &self.agent_task,
            ),
            (
                &mut self.probe_registration_attempted,
                &mut self.probe_registered,
                &self.probe_task,
            ),
        ] {
            match delete_task_blocking(name) {
                Ok(()) => {
                    *attempted = false;
                    *registered = false;
                }
                Err(error) => cleanup_error(&mut errors, &format!("delete task {name}"), &error),
            }
        }
        if let Err(error) = crate::windows::stop_system_agent(&self.request.agent_bin) {
            cleanup_error(&mut errors, "stop case agent by exact image", &error);
        }
        match crate::windows::case_agent_processes(&self.request.agent_bin) {
            Ok(pids) if !pids.is_empty() => errors.push(format!("SYSTEM agent PIDs still running: {pids:?}")),
            Ok(_) => {}
            Err(error) => cleanup_error(&mut errors, "verify agent exit", &error),
        }
        for error in errors {
            eprintln!("SYSTEM fixture cleanup remains incomplete: {error}");
        }
    }
}

impl Drop for SystemFixture {
    fn drop(&mut self) {
        if !self.cleaned {
            self.cleanup_blocking();
        }
    }
}

pub(super) async fn run(mut ctx: Context) -> anyhow::Result<()> {
    ctx.key_name_prefix = format!("{}{}-", ctx.key_name_prefix, uuid::Uuid::new_v4());
    ctx.work_dir = absolute(&ctx.work_dir)?;
    ctx.agent_bin = absolute(&ctx.agent_bin)?;
    if let Some(path) = ctx.target.ca_path.as_mut() {
        *path = absolute(path)?;
    }
    if let Some(path) = ctx.second.as_mut().and_then(|target| target.ca_path.as_mut()) {
        *path = absolute(path)?;
    }
    let mut case = AgentCase::new(ctx, None, false).await?;
    case.set_acl_grant_current_user(false)?;
    case.cleaned = true;
    let mut fixture = SystemFixture::new(case)?;
    let result = fixture.execute().await;
    let cleanup = fixture.cleanup().await;
    let audit = fixture.case.audit_tokens_excluding(Some(&fixture.request.agent_bin));
    if let Err(error) = &audit {
        eprintln!("SYSTEM fixture token audit failed: {error:#}");
    }
    match (result, cleanup, audit) {
        (Err(error), _, _) => Err(error),
        (Ok(()), Err(error), _) => Err(error),
        (Ok(()), Ok(()), audit) => audit,
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::process::ExitStatusExt as _;

    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[test]
    fn task_absence_requires_a_specific_not_found_result() -> anyhow::Result<()> {
        let missing = Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: Vec::new(),
            stderr: b"ERROR: The system cannot find the file specified.".to_vec(),
        };
        assert!(task_absent_from_query(&missing)?);
        let denied = Output {
            stderr: b"ERROR: Access is denied.".to_vec(),
            ..missing
        };
        assert!(task_absent_from_query(&denied).is_err());
        let present = Output {
            status: std::process::ExitStatus::from_raw(0),
            stderr: Vec::new(),
            ..denied
        };
        assert!(!task_absent_from_query(&present)?);
        Ok(())
    }

    #[tokio::test]
    async fn token_channel_filters_nonce_and_serves_once() -> anyhow::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let nonce = uuid::Uuid::new_v4();
        let token = format!("dvaet1.bag.{}", "B".repeat(43));
        let request = Request {
            case_dir: PathBuf::new(),
            agent_bin: PathBuf::new(),
            key_name_prefix: String::new(),
            device_id: None,
            token_port: Some(address.port()),
            token_nonce: Some(nonce),
            cleanup_only: false,
        };
        let encoded = serde_json::to_string(&request)?;
        ensure!(
            !encoded.contains(&token) && !encoded.contains(&"B".repeat(12)),
            "probe request included token material"
        );
        let served_token = token.clone();
        let server = tokio::spawn(async move { serve_probe_token(&listener, nonce, &served_token).await });
        let mut wrong = tokio::net::TcpStream::connect(address).await?;
        let mut wrong_nonce = *nonce.as_bytes();
        wrong_nonce[0] ^= 1;
        wrong.write_all(&wrong_nonce).await?;
        drop(wrong);
        tokio::time::sleep(Duration::from_millis(20)).await;
        ensure!(!server.is_finished(), "token channel accepted a wrong nonce");
        let received = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || crate::system_probe::read_token(&request)),
        )
        .await
        .context("probe token reader timed out")???;
        let outcome = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .context("token channel server timed out")??;
        outcome?;
        ensure!(received == token, "token channel changed the token");
        ensure!(
            tokio::net::TcpStream::connect(address).await.is_err(),
            "token channel accepted a second connection"
        );
        Ok(())
    }
}
