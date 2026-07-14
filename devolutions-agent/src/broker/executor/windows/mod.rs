//! Windows command executor.
//!
//! Uses a unified `CreateProcessAsUserW` code path for both SYSTEM (service) and
//! current-user (development) modes.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use devolutions_agent_shared::temp_file::{BATCH_UTF8_PREAMBLE, POWERSHELL_UTF8_ENCODING_PREAMBLE, TmpFileGuard};
use now_policy_api::{Elevation, Scope};
use tracing::{debug, info, warn};
use win_api_wrappers::process::Process;
use win_api_wrappers::security::privilege::{self, ScopedPrivileges};
use win_api_wrappers::token::Token;
use win_api_wrappers::utils;
use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_QUERY};

use super::{CommandExecutor, ExecutionContext, ExecutionOutput};

mod process;
mod token;

use process::create_process;
use token::{detect_running_as_system, find_user_session, get_elevated_token};

/// Windows command executor using `win-api-wrappers` safe abstractions.
///
/// Detects whether it runs as SYSTEM (service mode) or as a normal user (dev mode).
/// Both modes use a unified `create_process_as_user` code path.
pub struct WindowsExecutor {
    is_system: bool,
}

impl Default for WindowsExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsExecutor {
    pub fn new() -> Self {
        let is_system = detect_running_as_system();
        if is_system {
            info!("Executor initialized in SYSTEM (service) mode");
        } else {
            info!("Executor initialized in user (development) mode");
        }
        Self { is_system }
    }
}

#[async_trait]
impl CommandExecutor for WindowsExecutor {
    async fn execute(&self, ctx: &ExecutionContext) -> anyhow::Result<ExecutionOutput> {
        let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine);

        if !self.is_system && requires_elevation {
            bail!(
                "elevated execution requested but broker is not running as SYSTEM; \
                 elevation is only supported in service mode"
            );
        }

        let is_system = self.is_system;
        let ctx = ctx.clone();

        // All Win32 calls are blocking — run in a blocking thread.
        tokio::task::spawn_blocking(move || {
            if is_system {
                execute_as_system(&ctx)
            } else {
                execute_as_current_user(&ctx)
            }
        })
        .await
        .context("blocking task panicked")?
    }
}

/// Execute a command in the context of the target user's session (SYSTEM mode).
///
/// Steps:
/// 1. Find the user's active session via WTS enumeration.
/// 2. Get the session token.
/// 3. If elevated execution is requested, obtain the linked elevated token.
/// 4. Set the token session ID and create the process.
/// 5. Wait for the process to exit and return the exit code.
fn execute_as_system(ctx: &ExecutionContext) -> anyhow::Result<ExecutionOutput> {
    let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine);

    info!(
        effective_user = %ctx.effective_user,
        command = %ctx.command.join(" "),
        requires_elevation,
        "Starting SYSTEM-mode execution"
    );

    // Enable privileges required by CreateProcessAsUserW when running as SYSTEM.
    // These are held by SYSTEM but not enabled by default.
    let mut process_token = Process::current_process()
        .token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
        .context("failed to open process token for privilege adjustment")?;

    debug!("Enabling SeTcb privilege");
    let mut _priv_tcb =
        ScopedPrivileges::enter(&mut process_token, &[privilege::SE_TCB_NAME]).context("failed to enable SeTcb")?;

    debug!("Enabling SeAssignPrimaryToken privilege");
    let mut _priv_primary = ScopedPrivileges::enter(_priv_tcb.token_mut(), &[privilege::SE_ASSIGNPRIMARYTOKEN_NAME])
        .context("failed to enable SeAssignPrimaryToken")?;

    debug!("Enabling SeIncreaseQuota privilege");
    let _priv_quota = ScopedPrivileges::enter(_priv_primary.token_mut(), &[privilege::SE_INCREASE_QUOTA_NAME])
        .context("failed to enable SeIncreaseQuota")?;

    debug!("All privileges enabled, finding user session");

    let session_id = find_user_session(&ctx.effective_user).context("failed to find active session for user")?;

    info!(
        effective_user = %ctx.effective_user,
        session_id,
        "Found user session"
    );

    debug!(session_id, "Calling Token::for_session");
    let user_token = Token::for_session(session_id).context("failed to obtain user token for session")?;

    debug!("Duplicating user token as primary");
    let primary_token = token::duplicate_as_primary(&user_token).context("failed to duplicate token as primary")?;

    let mut execution_token = if requires_elevation {
        debug!("Attempting to get elevated token");
        match get_elevated_token(&primary_token) {
            Ok(elevated) => {
                info!("Using elevated (linked) token");
                elevated
            }
            Err(error) => {
                warn!(%error, "Could not obtain elevated token, using primary");
                primary_token
            }
        }
    } else {
        debug!("Using non-elevated primary token");
        primary_token
    };

    // Assign the target session to the token before process creation.
    debug!(session_id, "Setting token session ID");
    execution_token
        .set_session_id(session_id)
        .context("failed to set token session ID")?;

    info!(
        command = %ctx.command.join(" "),
        session_id,
        "Running execution plan"
    );

    let output = run_plan(&execution_token, ctx, session_id)?;

    info!(
        effective_user = %ctx.effective_user,
        command = %ctx.command.join(" "),
        exit_code = output.exit_code,
        "Plan completed under user token"
    );

    Ok(output)
}

/// Execute a command as the current user (development mode).
///
/// Opens the current process token and uses the same `create_process_as_user`
/// code path as SYSTEM mode, ensuring consistent behavior (environment, desktop, flags).
fn execute_as_current_user(ctx: &ExecutionContext) -> anyhow::Result<ExecutionOutput> {
    info!(
        effective_user = %ctx.effective_user,
        command = %ctx.command.join(" "),
        "Executing command as current user (dev mode)"
    );

    let token = Process::current_process()
        .token(TOKEN_ALL_ACCESS)
        .context("failed to open current process token")?;

    let session_id = token.session_id().context("failed to query token session ID")?;

    let output = run_plan(&token, ctx, session_id)?;

    info!(
        command = %ctx.command.join(" "),
        exit_code = output.exit_code,
        "Plan completed under current user token"
    );

    Ok(output)
}

/// Run the full execution plan under `token`: best-effort process kills, an
/// optional pre-operation command (must succeed), the main package-manager
/// command, then an optional post-operation command (failures are logged).
///
/// Returns the exit code and captured output of the main command.
fn run_plan(token: &Token, ctx: &ExecutionContext, session_id: u32) -> anyhow::Result<ExecutionOutput> {
    // 1. Kill requested processes (best-effort; a missing process is not an error).
    for process_name in &ctx.kill_processes {
        let kill_cmd = vec![
            "taskkill.exe".to_owned(),
            "/F".to_owned(),
            "/IM".to_owned(),
            process_name.clone(),
        ];
        match create_process(token, &kill_cmd, session_id, false) {
            Ok(out) => info!(%process_name, exit_code = out.exit_code, "Kill-before-operation completed"),
            Err(error) => warn!(%process_name, %error, "Kill-before-operation failed (ignored)"),
        }
    }

    // 2. Pre-operation command — must succeed before the main operation runs.
    if let Some(pre) = &ctx.pre_command {
        info!(command = %pre, "Running pre-operation command");
        let command = prepare_shell_command(token, pre)?;
        let out = create_process(token, command.args(), session_id, ctx.capture_output)
            .context("failed to run pre-operation command")?;
        if out.exit_code != 0 {
            bail!(
                "pre-operation command exited with code {}: {}",
                out.exit_code,
                out.stdout.trim()
            );
        }
    }

    // 3. Main package-manager command.
    let command = prepare_main_command(token, &ctx.command)?;
    let output = create_process(token, command.args(), session_id, ctx.capture_output)?;

    // 4. Post-operation command — runs after the main command; failures are logged only.
    if let Some(post) = &ctx.post_command {
        info!(command = %post, "Running post-operation command");
        let command = prepare_shell_command(token, post)?;
        match create_process(token, command.args(), session_id, false) {
            Ok(out) if out.exit_code == 0 => {}
            Ok(out) => warn!(exit_code = out.exit_code, "Post-operation command exited non-zero"),
            Err(error) => warn!(%error, "Post-operation command failed"),
        }
    }

    Ok(output)
}

fn prepare_main_command(token: &Token, command: &[String]) -> anyhow::Result<PreparedCommand> {
    let temp_dir = user_temp_dir(token);
    prepare_main_command_in(command, temp_dir.as_deref())
}

fn prepare_main_command_in(command: &[String], temp_dir: Option<&Path>) -> anyhow::Result<PreparedCommand> {
    if let Some(script) = powershell_inline_script(command) {
        return prepare_powershell_script(command, script, temp_dir);
    }

    if executable_is(command, "winget.exe") {
        return prepare_winget_script(command, temp_dir);
    }

    Ok(PreparedCommand::raw(command))
}

fn prepare_shell_command(token: &Token, payload: &str) -> anyhow::Result<PreparedCommand> {
    let temp_dir = user_temp_dir(token);
    prepare_shell_command_in(payload, temp_dir.as_deref())
}

/// Build a `cmd.exe` invocation for a client-supplied shell payload using a temporary batch file.
///
/// The code page is switched to UTF-8 so captured output can be decoded consistently.
fn prepare_shell_command_in(payload: &str, temp_dir: Option<&Path>) -> anyhow::Result<PreparedCommand> {
    let script = format!("{BATCH_UTF8_PREAMBLE}\r\n{payload}");
    let temp_script = broker_temp_script("bat", temp_dir)?;
    temp_script.write_content(&script).with_context(|| {
        format!(
            "failed to write broker temporary script at {}",
            temp_script.path().display()
        )
    })?;

    let command = vec![
        "cmd.exe".to_owned(),
        "/D".to_owned(),
        "/V:OFF".to_owned(),
        "/Q".to_owned(),
        "/C".to_owned(),
        temp_script.path_string(),
    ];

    Ok(PreparedCommand::with_script(command, temp_script))
}

fn prepare_powershell_script(
    command: &[String],
    script: &str,
    temp_dir: Option<&Path>,
) -> anyhow::Result<PreparedCommand> {
    command.first().context("empty PowerShell command")?;
    let is_windows_powershell = executable_is(command, "powershell.exe");
    let script = powershell_script_with_utf8_preamble(script);
    let temp_script = broker_temp_script("ps1", temp_dir)?;
    if is_windows_powershell {
        temp_script.write_content_utf8_bom(&script).with_context(|| {
            format!(
                "failed to write broker temporary script at {}",
                temp_script.path().display()
            )
        })?;
    } else {
        temp_script.write_content(&script).with_context(|| {
            format!(
                "failed to write broker temporary script at {}",
                temp_script.path().display()
            )
        })?;
    }

    let mut prepared = command[..2].to_vec();
    prepared.push("-Command".to_owned());
    prepared.push(format!("& {}", quote_powershell_literal(&temp_script.path_string())));

    Ok(PreparedCommand::with_script(prepared, temp_script))
}

fn powershell_script_with_utf8_preamble(script: &str) -> String {
    format!("{POWERSHELL_UTF8_ENCODING_PREAMBLE}\r\n{script}")
}

fn prepare_winget_script(command: &[String], temp_dir: Option<&Path>) -> anyhow::Result<PreparedCommand> {
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str(BATCH_UTF8_PREAMBLE);
    script.push_str("\r\nset \"NO_COLOR=1\"\r\n");

    let (executable, args) = command.split_first().context("empty WinGet command")?;
    append_batch_argument(&mut script, executable)?;
    for arg in args {
        script.push(' ');
        append_batch_argument(&mut script, arg)?;
    }
    script.push_str("\r\nexit /b %ERRORLEVEL%\r\n");

    let temp_script = broker_temp_script("bat", temp_dir)?;
    temp_script.write_content(&script).with_context(|| {
        format!(
            "failed to write broker temporary script at {}",
            temp_script.path().display()
        )
    })?;

    let prepared = vec![
        "cmd.exe".to_owned(),
        "/D".to_owned(),
        "/V:OFF".to_owned(),
        "/Q".to_owned(),
        "/C".to_owned(),
        temp_script.path_string(),
    ];

    Ok(PreparedCommand::with_script(prepared, temp_script))
}

fn powershell_inline_script(command: &[String]) -> Option<&str> {
    if command.len() == 4
        && (executable_is(command, "powershell.exe") || executable_is(command, "pwsh.exe"))
        && command[2].eq_ignore_ascii_case("-Command")
    {
        Some(command[3].as_str())
    } else {
        None
    }
}

fn broker_temp_script(extension: &str, temp_dir: Option<&Path>) -> anyhow::Result<TmpFileGuard> {
    TmpFileGuard::with_prefix_in("devolutions-broker-", extension, temp_dir)
        .context("failed to create broker temporary script")
}

fn executable_is(command: &[String], expected_name: &str) -> bool {
    command.first().is_some_and(|executable| {
        Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
    })
}

fn user_temp_dir(token: &Token) -> Option<PathBuf> {
    let user_env = match utils::environment_block(Some(token), false) {
        Ok(user_env) => user_env,
        Err(error) => {
            warn!(%error, "Failed to load user environment block for broker script temp path");
            return None;
        }
    };

    let temp_dir = user_env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("TEMP"))
        .or_else(|| user_env.iter().find(|(key, _)| key.eq_ignore_ascii_case("TMP")))
        .map(|(_, value)| PathBuf::from(value));

    match temp_dir {
        Some(path) if path.is_dir() => Some(path),
        Some(path) => {
            warn!(path = %path.display(), "User temp path is not a directory; using default temp path");
            None
        }
        None => {
            warn!("User environment does not define TEMP or TMP; using default temp path");
            None
        }
    }
}

fn quote_powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn append_batch_argument(script: &mut String, value: &str) -> anyhow::Result<()> {
    if value.contains(['\0', '\r', '\n']) {
        bail!("winget command arguments cannot contain control line separators");
    }

    script.push('"');

    let mut backslashes = 0;
    for c in value.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..=(backslashes * 2) {
                    script.push('\\');
                }
                script.push('"');
                backslashes = 0;
            }
            '%' => {
                for _ in 0..backslashes {
                    script.push('\\');
                }
                script.push_str("%%");
                backslashes = 0;
            }
            c => {
                for _ in 0..backslashes {
                    script.push('\\');
                }
                script.push(c);
                backslashes = 0;
            }
        }
    }

    for _ in 0..(backslashes * 2) {
        script.push('\\');
    }
    script.push('"');

    Ok(())
}

struct PreparedCommand {
    command: Vec<String>,
    _script: Option<TmpFileGuard>,
}

impl PreparedCommand {
    fn raw(command: &[String]) -> Self {
        Self {
            command: command.to_vec(),
            _script: None,
        }
    }

    fn with_script(command: Vec<String>, script: TmpFileGuard) -> Self {
        Self {
            command,
            _script: Some(script),
        }
    }

    fn args(&self) -> &[String] {
        &self.command
    }
}

#[cfg(test)]
mod tests {
    use super::{POWERSHELL_UTF8_ENCODING_PREAMBLE, prepare_main_command_in, prepare_shell_command_in};

    #[test]
    fn shell_command_uses_utf8_temp_batch_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = prepare_shell_command_in("echo héllo", Some(temp_dir.path())).expect("prepare shell command");

        assert_eq!(command.args()[0], "cmd.exe");
        assert_eq!(command.args()[1], "/D");
        assert_eq!(command.args()[2], "/V:OFF");
        assert_eq!(command.args()[3], "/Q");
        assert_eq!(command.args()[4], "/C");
        assert!(command.args()[5].ends_with(".bat"));

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert_eq!(script, "@chcp 65001 > nul\r\necho héllo");
    }

    #[test]
    fn powershell_command_uses_temp_script_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = vec![
            "powershell.exe".to_owned(),
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "Write-Output 'héllo'".to_owned(),
        ];
        let command = prepare_main_command_in(&command, Some(temp_dir.path())).expect("prepare PowerShell command");

        assert_eq!(command.args()[0], "powershell.exe");
        assert_eq!(command.args()[1], "-NoProfile");
        assert_eq!(command.args()[2], "-Command");
        assert!(command.args()[3].starts_with("& '"));

        let script = std::fs::read(&command.args()[3][3..command.args()[3].len() - 1]).expect("read temp script");
        assert!(script.starts_with(b"\xEF\xBB\xBF"));
        let script = String::from_utf8_lossy(&script);
        assert!(script.contains(POWERSHELL_UTF8_ENCODING_PREAMBLE));
        assert!(script.contains("\r\nWrite-Output 'héllo'"));
    }

    #[test]
    fn powershell7_command_uses_bomless_utf8_temp_script_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = vec![
            "pwsh.exe".to_owned(),
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "Write-Output 'héllo'".to_owned(),
        ];
        let command = prepare_main_command_in(&command, Some(temp_dir.path())).expect("prepare PowerShell command");

        assert_eq!(command.args()[0], "pwsh.exe");
        assert_eq!(command.args()[1], "-NoProfile");
        assert_eq!(command.args()[2], "-Command");
        assert!(command.args()[3].starts_with("& '"));

        let script = std::fs::read(&command.args()[3][3..command.args()[3].len() - 1]).expect("read temp script");
        assert!(!script.starts_with(b"\xEF\xBB\xBF"));
        let script = String::from_utf8(script).expect("script is UTF-8");
        assert!(script.starts_with(POWERSHELL_UTF8_ENCODING_PREAMBLE));
        assert!(script.contains("\r\nWrite-Output 'héllo'"));
    }

    #[test]
    fn winget_command_uses_batch_wrapper_for_utf8_output() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = vec![
            "winget.exe".to_owned(),
            "install".to_owned(),
            "--id".to_owned(),
            "Vendor.Package&Name".to_owned(),
            "100%".to_owned(),
            "Quoted\"Value".to_owned(),
        ];
        let command = prepare_main_command_in(&command, Some(temp_dir.path())).expect("prepare WinGet command");

        assert_eq!(command.args()[0], "cmd.exe");
        assert_eq!(command.args()[1], "/D");
        assert_eq!(command.args()[2], "/V:OFF");
        assert_eq!(command.args()[3], "/Q");
        assert_eq!(command.args()[4], "/C");

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert!(script.starts_with("@echo off\r\n@chcp 65001 > nul\r\nset \"NO_COLOR=1\""));
        assert!(
            script
                .contains("\"winget.exe\" \"install\" \"--id\" \"Vendor.Package&Name\" \"100%%\" \"Quoted\\\"Value\"")
        );
        assert!(script.contains("exit /b %ERRORLEVEL%"));
    }
}
