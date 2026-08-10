//! Windows command executor.
//!
//! Uses a unified `CreateProcessAsUserW` code path for both SYSTEM (service) and
//! current-user (development) modes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use devolutions_agent_shared::temp_file::{BATCH_UTF8_PREAMBLE, POWERSHELL_UTF8_ENCODING_PREAMBLE, TmpFileGuard};
use now_policy_api::{Elevation, ManagerName, Scope};
use tracing::{debug, info, warn};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use win_api_wrappers::security::privilege;
use win_api_wrappers::token::Token;
use win_api_wrappers::utils::WideString;
use windows::Win32::Security::TOKEN_ALL_ACCESS;

use super::{
    BROKER_SUPPORTED_MANAGERS, CommandExecutor, ExecutionContext, ExecutionOutput, OperationCanceled,
    ProcessStartedCallback, is_canceled_error,
};
use crate::broker::policy_security;

mod privileges;
mod process;
mod token;

use privileges::SharedPrivileges;
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
    async fn execute(
        &self,
        ctx: &ExecutionContext,
        process_started: Option<ProcessStartedCallback>,
    ) -> anyhow::Result<ExecutionOutput> {
        let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine);
        reject_unsupported_vcpkg_elevation(ctx)?;

        // SECURITY: Defense in depth — the broker server already rejects such
        // requests, and `run_plan` re-checks the actual execution token; never
        // run policy-ungoverned pre/post commands elevated.
        if requires_elevation && (ctx.pre_command.is_some() || ctx.post_command.is_some()) {
            bail!("pre/post operation commands are only allowed for non-elevated execution");
        }

        if !self.is_system && requires_elevation {
            bail!(
                "elevated execution requested but broker is not running as SYSTEM; \
                 elevation is only supported in service mode"
            );
        }

        let is_system = self.is_system;
        let ctx = ctx.clone();
        let process_started = process_started.clone();

        // All Win32 calls are blocking — run in a blocking thread.
        tokio::task::spawn_blocking(move || {
            if is_system {
                execute_as_system(&ctx, process_started)
            } else {
                execute_as_current_user(&ctx, process_started)
            }
        })
        .await
        .context("blocking task panicked")?
    }

    async fn probe_managers(&self, user_sid: &Sid) -> Vec<ManagerName> {
        let is_system = self.is_system;
        let user_sid = user_sid.clone();

        // All Win32 calls are blocking — run in a blocking thread.
        let probed = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<ManagerName>> {
            let user_env = probe_user_environment(is_system, &user_sid)?;
            Ok(BROKER_SUPPORTED_MANAGERS
                .into_iter()
                .filter(|manager| manager_is_available(*manager, &user_env))
                .collect())
        })
        .await
        .context("blocking task panicked")
        .and_then(std::convert::identity);

        match probed {
            Ok(managers) => managers,
            Err(error) => {
                // Fail closed: the same session/environment lookup is required for execution,
                // so a manager that cannot be verified cannot run either.
                warn!(
                    error = format!("{error:#}"),
                    "Failed to probe package manager availability; advertising no managers"
                );
                Vec::new()
            }
        }
    }
}

/// Load the environment block of the target user identified by `user_sid`.
///
/// In SYSTEM (service) mode the token comes from the user's active session, matching the
/// token later used for execution. In user (development) mode the current process token is used.
fn probe_user_environment(is_system: bool, user_sid: &Sid) -> anyhow::Result<HashMap<String, String>> {
    let token = if is_system {
        // WTSQueryUserToken (used by find_user_session) requires the SeTcb privilege.
        let _privileges = SharedPrivileges::acquire(&[privilege::SE_TCB_NAME]).context("failed to enable SeTcb")?;

        let (_session_id, user_token) =
            find_user_session(user_sid).context("failed to find active session for user")?;
        user_token
    } else {
        Process::current_process()
            .token(TOKEN_ALL_ACCESS)
            .context("failed to open current process token")?
    };

    win_api_wrappers::utils::environment_block(Some(&token), false).context("failed to load user environment block")
}

/// Check whether a package manager is usable for the target user, mirroring the executable
/// resolution rules the execution path applies for that manager.
fn manager_is_available(manager: ManagerName, user_env: &HashMap<String, String>) -> bool {
    match manager {
        // Probing is not an elevated execution, so no executable ACL verification is needed.
        ManagerName::Winget => resolve_winget_executable(user_env, false).is_ok(),
        ManagerName::Chocolatey => default_chocolatey_install_dir()
            .and_then(|root| resolve_trusted_chocolatey_executable(Some(user_env), &root, false))
            .is_ok(),
        ManagerName::Bun => resolve_bun_executable("bun", user_env).is_ok(),
        ManagerName::Cargo => resolve_cargo_executable(user_env).is_ok(),
        ManagerName::Dotnet => {
            Path::new(&crate::broker::command_builder::dotnet::trusted_dotnet_executable()).is_file()
        }
        ManagerName::Pip => resolve_python_executable("python.exe", user_env).is_ok(),
        // npm runs through the user PATH `npm` shim inside the trusted Windows PowerShell wrapper,
        // so both the shim and the host must exist.
        ManagerName::Npm => {
            Path::new(&trusted_windows_powershell_executable()).is_file()
                && path_contains_executable(user_env, &["npm.cmd", "npm.exe"])
        }
        ManagerName::PowerShell => Path::new(&trusted_windows_powershell_executable()).is_file(),
        ManagerName::PowerShell7 => Path::new(&trusted_powershell7_executable()).is_file(),
        // Scoop is driven through the user's `scoop.ps1` shim (resolved via `Get-Command
        // -CommandType ExternalScript`) inside the trusted Windows PowerShell wrapper.
        ManagerName::Scoop => {
            Path::new(&trusted_windows_powershell_executable()).is_file()
                && path_contains_executable(user_env, &["scoop.ps1"])
        }
        ManagerName::Vcpkg => resolve_vcpkg_executable(user_env).is_ok(),
        _ => false,
    }
}

/// Return true when any of `names` exists as a file in a directory listed in the environment PATH.
fn path_contains_executable(env: &HashMap<String, String>, names: &[&str]) -> bool {
    let path_var = env_value_ignore_case(env, "PATH").unwrap_or_default();
    path_var
        .split(';')
        .map(str::trim)
        .filter(|dir| !dir.is_empty())
        .any(|dir| names.iter().any(|name| PathBuf::from(dir).join(name).is_file()))
}

/// Execute a command in the context of the target user's session (SYSTEM mode).
///
/// Steps:
/// 1. Find the user's active session (and its token) by matching the session token SID.
/// 2. If elevated execution is requested, obtain the linked elevated token.
/// 3. Set the token session ID and create the process.
/// 4. Wait for the process to exit and return the exit code.
fn execute_as_system(
    ctx: &ExecutionContext,
    process_started: Option<ProcessStartedCallback>,
) -> anyhow::Result<ExecutionOutput> {
    let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine);

    info!(
        effective_user = %ctx.effective_user,
        requires_elevation,
        "Starting SYSTEM-mode execution"
    );

    // Enable privileges required by CreateProcessAsUserW when running as SYSTEM.
    // These are held by SYSTEM but not enabled by default. The guard is reference-counted
    // process-wide so concurrent requests (and availability probes) cannot disable a
    // privilege out from under one another.
    debug!("Enabling SeTcb, SeAssignPrimaryToken and SeIncreaseQuota privileges");
    let _privileges = SharedPrivileges::acquire(&[
        privilege::SE_TCB_NAME,
        privilege::SE_ASSIGNPRIMARYTOKEN_NAME,
        privilege::SE_INCREASE_QUOTA_NAME,
    ])
    .context("failed to enable privileges required for SYSTEM-mode execution")?;

    debug!("All privileges enabled, finding user session");

    let (session_id, user_token) = find_user_session(&ctx.user_sid).context(
        "failed to find an active logon session for the target user; \
         user-scope and interactive operations require the user to be logged on",
    )?;

    info!(
        effective_user = %ctx.effective_user,
        user_sid = %ctx.user_sid,
        session_id,
        "Found user session"
    );

    debug!("Duplicating user token as primary");
    let primary_token = token::duplicate_as_primary(&user_token).context("failed to duplicate token as primary")?;

    let mut execution_token = if requires_elevation {
        debug!("Attempting to get elevated token");
        let elevated = get_elevated_token(&primary_token).context("failed to obtain elevated token")?;
        info!("Using elevated (linked) token");
        elevated
    } else {
        debug!("Using non-elevated primary token");
        primary_token
    };

    // Assign the target session to the token before process creation.
    debug!(session_id, "Setting token session ID");
    execution_token
        .set_session_id(session_id)
        .context("failed to set token session ID")?;

    info!(session_id, "Running execution plan");

    let output = run_plan(&execution_token, ctx, session_id, process_started)?;

    info!(
        effective_user = %ctx.effective_user,
        exit_code = output.exit_code,
        "Plan completed under user token"
    );

    Ok(output)
}

/// Execute a command as the current user (non-SYSTEM mode).
///
/// This path is taken whenever the broker does not run as SYSTEM, regardless of build
/// profile — e.g. when the agent binary is launched manually as a regular user instead
/// of as the Windows service.
///
/// Opens the current process token and uses the same `create_process_as_user`
/// code path as SYSTEM mode, ensuring consistent behavior (environment, desktop, flags).
///
/// The client identity must match the broker process user: the process token defines
/// the target profile (`%LOCALAPPDATA%`, HKCU) and desktop session, so executing on
/// behalf of a different pipe client would put user-scope installs into the wrong
/// profile and interactive UIs on the wrong desktop.
fn execute_as_current_user(
    ctx: &ExecutionContext,
    process_started: Option<ProcessStartedCallback>,
) -> anyhow::Result<ExecutionOutput> {
    info!(
        effective_user = %ctx.effective_user,
        "Executing command as current user (non-SYSTEM mode)"
    );

    let token = Process::current_process()
        .token(TOKEN_ALL_ACCESS)
        .context("failed to open current process token")?;

    let process_user_sid = token
        .sid_and_attributes()
        .context("failed to query current process token user SID")?
        .sid;
    if process_user_sid != ctx.user_sid {
        bail!(
            "pipe client user SID '{}' does not match broker process user SID '{}'; \
             user-scope execution is only supported when the client \
             and the broker run as the same user (broker is not running as SYSTEM)",
            ctx.user_sid,
            process_user_sid,
        );
    }

    let session_id = token.session_id().context("failed to query token session ID")?;

    let output = run_plan(&token, ctx, session_id, process_started)?;

    info!(exit_code = output.exit_code, "Plan completed under current user token");

    Ok(output)
}

/// Run the full execution plan under `token`: best-effort process kills, an
/// optional pre-operation command (must succeed), the main package-manager
/// command, then an optional post-operation command (failures are logged).
///
/// Returns the exit code and captured output of the main command.
fn run_plan(
    token: &Token,
    ctx: &ExecutionContext,
    session_id: u32,
    process_started: Option<ProcessStartedCallback>,
) -> anyhow::Result<ExecutionOutput> {
    if ctx.cancel_token.is_cancelled() {
        return Err(anyhow::Error::new(OperationCanceled));
    }

    let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine);
    if requires_elevation && command_is_bun(&ctx.command) {
        bail!("elevated Bun package operations are not supported by the broker");
    }

    // SECURITY: Pre/post commands are raw strings whose content is not governed by
    // the policy, so they must never run elevated. The request flags are already
    // checked upstream, but the token actually running the plan is what matters
    // (e.g. a broker launched from an elevated shell, or a full session token when
    // UAC is disabled), so query the token itself right before running.
    if ctx.pre_command.is_some() || ctx.post_command.is_some() {
        let is_elevated = token
            .is_elevated()
            .context("failed to query execution token elevation")?;
        if is_elevated {
            bail!("pre/post operation commands are only allowed for non-elevated execution");
        }
    }

    // 1. Kill requested processes (best-effort; a missing process is not an error,
    //    but a cancellation request must still be honored).
    for process_name in &ctx.kill_processes {
        let kill_cmd = vec![
            trusted_system32_executable("taskkill.exe"),
            "/F".to_owned(),
            "/IM".to_owned(),
            process_name.clone(),
        ];
        match create_process(
            token,
            &kill_cmd,
            session_id,
            false,
            requires_elevation,
            None,
            Some(&ctx.cancel_token),
        ) {
            Ok(out) => info!(%process_name, exit_code = out.exit_code, "Kill-before-operation completed"),
            Err(error) if is_canceled_error(&error) => return Err(error),
            Err(error) => warn!(%process_name, %error, "Kill-before-operation failed (ignored)"),
        }
    }

    // 2. Pre-operation command — must succeed before the main operation runs.
    if let Some(pre) = &ctx.pre_command {
        info!("Running pre-operation command");
        let command = prepare_shell_command(token, pre)?;
        let out = create_process(
            token,
            command.args(),
            session_id,
            ctx.capture_output,
            requires_elevation,
            None,
            Some(&ctx.cancel_token),
        )
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
    let command = prepare_main_command(token, &ctx.command, requires_elevation)?;
    let output = create_process(
        token,
        command.args(),
        session_id,
        ctx.capture_output,
        requires_elevation,
        process_started,
        Some(&ctx.cancel_token),
    )?;

    // 4. Post-operation command — runs after the main command; failures are logged only
    //    so a completed main operation is never reported as failed by its post-hook.
    //    Skipped when cancellation was requested, and cancellable while it runs.
    if let Some(post) = &ctx.post_command {
        if ctx.cancel_token.is_cancelled() {
            info!("Skipping post-operation command: operation was canceled");
        } else {
            info!("Running post-operation command");
            match prepare_shell_command(token, post) {
                Ok(command) => {
                    match create_process(
                        token,
                        command.args(),
                        session_id,
                        false,
                        requires_elevation,
                        None,
                        Some(&ctx.cancel_token),
                    ) {
                        Ok(out) if out.exit_code == 0 => {}
                        Ok(out) => warn!(exit_code = out.exit_code, "Post-operation command exited non-zero"),
                        Err(error) => warn!(%error, "Post-operation command failed"),
                    }
                }
                Err(error) => warn!(%error, "Failed to prepare post-operation command"),
            }
        }
    }

    Ok(output)
}

fn prepare_main_command(
    token: &Token,
    command: &[String],
    requires_elevation: bool,
) -> anyhow::Result<PreparedCommand> {
    let user_env = win_api_wrappers::utils::environment_block(Some(token), false)
        .context("failed to load user environment block")?;
    prepare_main_command_in(command, None, Some(&user_env), requires_elevation)
}

fn prepare_main_command_in(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
    requires_elevation: bool,
) -> anyhow::Result<PreparedCommand> {
    if let Some((script, command_arg_index)) = powershell_inline_script(command) {
        return prepare_powershell_script(command, command_arg_index, script, temp_dir);
    }

    if executable_is(command, "winget.exe") {
        return prepare_winget_script(command, temp_dir, user_env, requires_elevation);
    }

    if executable_is(command, "choco.exe") {
        return prepare_chocolatey_script(command, temp_dir, user_env, requires_elevation);
    }

    if executable_is(command, "cargo.exe") {
        return prepare_cargo_script(command, temp_dir, user_env);
    }

    if executable_is(command, "vcpkg.exe") {
        return prepare_vcpkg_script(command, temp_dir, user_env);
    }

    if is_pip_python_command(command) {
        return prepare_pip_command(command, temp_dir, user_env);
    }

    if command_is_bun(command) {
        return prepare_bun_command(command, temp_dir, user_env);
    }

    Ok(PreparedCommand::raw(command))
}

fn reject_unsupported_vcpkg_elevation(ctx: &ExecutionContext) -> anyhow::Result<()> {
    if executable_is(&ctx.command, "vcpkg.exe")
        && (ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine))
    {
        bail!("vcpkg elevated or machine-scope operations are not supported by the broker");
    }

    Ok(())
}

fn prepare_shell_command(_token: &Token, payload: &str) -> anyhow::Result<PreparedCommand> {
    prepare_shell_command_in(payload, None)
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
        trusted_system32_executable("cmd.exe"),
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
    command_arg_index: usize,
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

    let mut prepared = command[..command_arg_index].to_vec();
    prepared[0] = if is_windows_powershell {
        trusted_windows_powershell_executable()
    } else {
        trusted_powershell7_executable()
    };
    prepared.push("-Command".to_owned());
    prepared.push(format!("& {}", quote_powershell_literal(&temp_script.path_string())));

    Ok(PreparedCommand::with_script(prepared, temp_script))
}

fn powershell_script_with_utf8_preamble(script: &str) -> String {
    format!("{POWERSHELL_UTF8_ENCODING_PREAMBLE}\r\n{script}")
}

fn prepare_winget_script(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
    requires_elevation: bool,
) -> anyhow::Result<PreparedCommand> {
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str(BATCH_UTF8_PREAMBLE);
    script.push_str("\r\nset \"NO_COLOR=1\"\r\n");

    let (executable, args) = command.split_first().context("empty WinGet command")?;
    let (executable, exe_guard) = user_env.map_or_else(
        || Ok((executable.clone(), None)),
        |env| {
            resolve_winget_executable(env, requires_elevation).map(|(path, guard)| (path.display().to_string(), guard))
        },
    )?;
    append_batch_argument(&mut script, &executable)?;
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
        trusted_system32_executable("cmd.exe"),
        "/D".to_owned(),
        "/V:OFF".to_owned(),
        "/Q".to_owned(),
        "/C".to_owned(),
        temp_script.path_string(),
    ];

    Ok(PreparedCommand::with_script(prepared, temp_script).with_exe_guard(exe_guard))
}

fn prepare_chocolatey_script(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
    requires_elevation: bool,
) -> anyhow::Result<PreparedCommand> {
    prepare_chocolatey_script_in(command, temp_dir, user_env, requires_elevation)
}

fn prepare_chocolatey_script_in(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
    requires_elevation: bool,
) -> anyhow::Result<PreparedCommand> {
    let default_install_root = default_chocolatey_install_dir()?;
    prepare_chocolatey_script_in_with_default_install_root(
        command,
        temp_dir,
        user_env,
        &default_install_root,
        requires_elevation,
    )
}

fn prepare_chocolatey_script_in_with_default_install_root(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
    default_install_root: &Path,
    requires_elevation: bool,
) -> anyhow::Result<PreparedCommand> {
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str(BATCH_UTF8_PREAMBLE);
    script.push_str("\r\nset \"NO_COLOR=1\"\r\n");

    let (_executable, args) = command.split_first().context("empty Chocolatey command")?;
    let (executable, install_root, exe_guard) =
        resolve_trusted_chocolatey_executable(user_env, default_install_root, requires_elevation)?;
    append_batch_set_value(&mut script, "ChocolateyInstall", &install_root.display().to_string())?;
    script.push_str("\r\n");
    append_batch_argument(&mut script, &executable.display().to_string())?;
    for arg in args {
        script.push(' ');
        append_batch_argument(&mut script, arg)?;
    }
    script.push_str("\r\nset \"CHOCO_EXIT_CODE=%ERRORLEVEL%\"");
    script.push_str("\r\nif \"%CHOCO_EXIT_CODE%\"==\"1605\" exit /b 0");
    script.push_str("\r\nif \"%CHOCO_EXIT_CODE%\"==\"1614\" exit /b 0");
    script.push_str("\r\nif \"%CHOCO_EXIT_CODE%\"==\"1641\" exit /b 0");
    script.push_str("\r\nif \"%CHOCO_EXIT_CODE%\"==\"3010\" exit /b 0");
    script.push_str("\r\nexit /b %CHOCO_EXIT_CODE%\r\n");

    let temp_script = broker_temp_script("bat", temp_dir)?;
    temp_script.write_content(&script).with_context(|| {
        format!(
            "failed to write broker temporary script at {}",
            temp_script.path().display()
        )
    })?;

    let prepared = vec![
        trusted_system32_executable("cmd.exe"),
        "/D".to_owned(),
        "/V:OFF".to_owned(),
        "/Q".to_owned(),
        "/C".to_owned(),
        temp_script.path_string(),
    ];

    Ok(PreparedCommand::with_script(prepared, temp_script).with_exe_guard(exe_guard))
}

fn prepare_vcpkg_script(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
) -> anyhow::Result<PreparedCommand> {
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str(BATCH_UTF8_PREAMBLE);
    script.push_str("\r\nset \"NO_COLOR=1\"\r\n");

    let (executable, args) = command.split_first().context("empty vcpkg command")?;
    let executable = user_env.map_or_else(
        || Ok(executable.clone()),
        |env| resolve_vcpkg_executable(env).map(|path| path.display().to_string()),
    )?;
    append_batch_argument(&mut script, &executable)?;
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
        trusted_system32_executable("cmd.exe"),
        "/D".to_owned(),
        "/V:OFF".to_owned(),
        "/Q".to_owned(),
        "/C".to_owned(),
        temp_script.path_string(),
    ];

    Ok(PreparedCommand::with_script(prepared, temp_script))
}

fn prepare_cargo_script(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
) -> anyhow::Result<PreparedCommand> {
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str(BATCH_UTF8_PREAMBLE);
    script.push_str("\r\nset \"NO_COLOR=1\"\r\n");

    let (executable, args) = command.split_first().context("empty Cargo command")?;
    let executable = user_env.map_or_else(
        || Ok(executable.clone()),
        |env| resolve_cargo_executable(env).map(|path| path.display().to_string()),
    )?;
    append_cargo_batch_argument(&mut script, &executable)?;
    for arg in args {
        script.push(' ');
        append_cargo_batch_argument(&mut script, arg)?;
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
        trusted_system32_executable("cmd.exe"),
        "/D".to_owned(),
        "/V:OFF".to_owned(),
        "/Q".to_owned(),
        "/C".to_owned(),
        temp_script.path_string(),
    ];

    Ok(PreparedCommand::with_script(prepared, temp_script))
}

fn prepare_pip_command(
    command: &[String],
    _temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
) -> anyhow::Result<PreparedCommand> {
    let (executable, args) = command.split_first().context("empty pip command")?;
    let executable = user_env
        .context("target user environment is required to resolve python.exe")
        .and_then(|env| resolve_python_executable(executable, env))?;
    let mut prepared = Vec::with_capacity(command.len());
    prepared.push(executable.display().to_string());
    prepared.extend_from_slice(args);

    Ok(PreparedCommand::raw(&prepared))
}

fn powershell_inline_script(command: &[String]) -> Option<(&str, usize)> {
    if !(executable_is(command, "powershell.exe") || executable_is(command, "pwsh.exe")) {
        return None;
    }

    let command_arg_index = command.iter().position(|arg| arg.eq_ignore_ascii_case("-Command"))?;
    if command_arg_index + 2 == command.len() {
        Some((command[command_arg_index + 1].as_str(), command_arg_index))
    } else {
        None
    }
}

fn prepare_bun_command(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&HashMap<String, String>>,
) -> anyhow::Result<PreparedCommand> {
    let (executable, args) = command.split_first().context("empty Bun command")?;
    let executable = user_env.map_or_else(
        || Ok(PathBuf::from(executable)),
        |env| resolve_bun_executable(executable, env),
    )?;

    if executable
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("cmd"))
    {
        return prepare_bun_cmd_script(&executable.display().to_string(), args, temp_dir);
    }

    let mut prepared = Vec::with_capacity(command.len());
    prepared.push(executable.display().to_string());
    prepared.extend_from_slice(args);

    Ok(PreparedCommand::raw(&prepared))
}

fn prepare_bun_cmd_script(
    executable: &str,
    args: &[String],
    temp_dir: Option<&Path>,
) -> anyhow::Result<PreparedCommand> {
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str(BATCH_UTF8_PREAMBLE);
    script.push_str("\r\ncall ");
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
        trusted_system32_executable("cmd.exe"),
        "/D".to_owned(),
        "/V:OFF".to_owned(),
        "/Q".to_owned(),
        "/C".to_owned(),
        temp_script.path_string(),
    ];

    Ok(PreparedCommand::with_script(prepared, temp_script))
}

// Owner keeps full control; interactive users only need read access to execute the script.
// The DACL is protected (`P`) so permissive entries are never inherited from the parent directory.
const SCRIPT_DACL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;BU)";

/// Creates the broker temporary script atomically with [`SCRIPT_DACL`].
///
/// The security descriptor is supplied at creation time (`SECURITY_ATTRIBUTES`), so the file
/// never exists with permissions inherited from the parent directory.
fn broker_temp_script(extension: &str, temp_dir: Option<&Path>) -> anyhow::Result<TmpFileGuard> {
    let security_descriptor =
        OwnedSecurityDescriptor::from_sddl(SCRIPT_DACL).context("failed to build broker script security descriptor")?;

    TmpFileGuard::with_prefix_in_using("devolutions-broker-", extension, temp_dir, |path| {
        create_file_with_security_descriptor(path, &security_descriptor)
    })
    .context("failed to create broker temporary script")
}

/// A self-relative security descriptor allocated with `LocalAlloc`, freed on drop.
struct OwnedSecurityDescriptor(windows::Win32::Security::PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    fn from_sddl(sddl: &str) -> anyhow::Result<Self> {
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::PSECURITY_DESCRIPTOR;

        let sddl = WideString::from(sddl);
        let mut descriptor = Self(PSECURITY_DESCRIPTOR::default());

        // SAFETY: `sddl` is a valid null-terminated UTF-16 string and the output pointer is valid.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_pcwstr(),
                SDDL_REVISION_1,
                &mut descriptor.0 as *mut PSECURITY_DESCRIPTOR,
                None,
            )
        }
        .context("failed to convert SDDL string to security descriptor")?;

        Ok(descriptor)
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};

        if self.0.0.is_null() {
            return;
        }
        // SAFETY: The descriptor pointer is returned by `ConvertStringSecurityDescriptorToSecurityDescriptorW`,
        // which allocates it with `LocalAlloc`.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// Creates a new file at `path` with the provided security descriptor applied atomically.
///
/// Fails with `io::ErrorKind::AlreadyExists` if the file already exists (`CREATE_NEW`), which
/// lets the caller retry with a different random name.
fn create_file_with_security_descriptor(
    path: &Path,
    descriptor: &OwnedSecurityDescriptor,
) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::{FromRawHandle as _, OwnedHandle};

    use windows::Win32::Foundation::FALSE;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    };

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("SECURITY_ATTRIBUTES size fits in u32"),
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: FALSE,
    };

    let path = WideString::from(path);

    // SAFETY: `path` is a valid null-terminated UTF-16 path and `security_attributes` points to
    // a valid structure that outlives the call; the kernel copies the descriptor at creation.
    let handle = unsafe {
        CreateFileW(
            path.as_pcwstr(),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            Some(&security_attributes as *const SECURITY_ATTRIBUTES),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|error| std::io::Error::from_raw_os_error(error.code().0 & 0xFFFF))?;

    // SAFETY: `CreateFileW` succeeded and returned a valid file handle that we now own.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };

    Ok(std::fs::File::from(handle))
}

fn executable_is(command: &[String], expected_name: &str) -> bool {
    command.first().is_some_and(|executable| {
        Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
    })
}

fn is_pip_python_command(command: &[String]) -> bool {
    command.len() >= 4
        && executable_is(command, "python.exe")
        && command[1] == "-m"
        && command[2].eq_ignore_ascii_case("pip")
}

fn command_is_bun(command: &[String]) -> bool {
    executable_is(command, "bun") || executable_is(command, "bun.exe") || executable_is(command, "bun.cmd")
}

fn quote_powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn trusted_system32_executable(name: &str) -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    PathBuf::from(system_root)
        .join("System32")
        .join(name)
        .display()
        .to_string()
}

fn trusted_windows_powershell_executable() -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
        .display()
        .to_string()
}

fn trusted_powershell7_executable() -> String {
    let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_owned());
    PathBuf::from(program_files)
        .join("PowerShell")
        .join("7")
        .join("pwsh.exe")
        .display()
        .to_string()
}

fn system_program_data_dir() -> anyhow::Result<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

    // SAFETY: The known-folder ID is valid and no token handle is supplied.
    let raw_path = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .context("failed to resolve system ProgramData folder")?;

    // SAFETY: `SHGetKnownFolderPath` returns a valid null-terminated UTF-16 string on success.
    let path = unsafe { raw_path.to_string() }.context("system ProgramData folder is not valid UTF-16")?;

    // SAFETY: The returned string is allocated by the shell with `CoTaskMemAlloc`.
    unsafe { CoTaskMemFree(Some(raw_path.as_ptr().cast())) };

    Ok(PathBuf::from(path))
}

fn default_chocolatey_install_dir() -> anyhow::Result<PathBuf> {
    Ok(system_program_data_dir()?.join("chocolatey"))
}

fn resolve_trusted_chocolatey_executable(
    user_env: Option<&HashMap<String, String>>,
    default_install_root: &Path,
    requires_elevation: bool,
) -> anyhow::Result<(PathBuf, PathBuf, Option<policy_security::VerifiedExecutable>)> {
    let install_root = user_env
        .and_then(|env| env_value_ignore_case(env, "ChocolateyInstall"))
        .filter(|value| !value.trim().is_empty())
        .map_or_else(|| default_install_root.to_owned(), PathBuf::from);
    let executable = install_root.join("bin").join("choco.exe");
    if !executable.is_file() {
        bail!(
            "Chocolatey executable was not found at {}; set ChocolateyInstall to the Chocolatey installation root",
            executable.display()
        );
    }

    if !is_trusted_chocolatey_install_dir(&install_root, default_install_root) {
        bail!(
            "ChocolateyInstall points to {}; only the trusted system Chocolatey folder at {} is supported by the broker",
            install_root.display(),
            default_install_root.display()
        );
    }

    let guard = policy_security::verify_elevated_executable_security(&executable, requires_elevation)?;
    let executable = guard.as_ref().map_or(executable, |g| g.path().to_owned());

    Ok((executable, install_root, guard))
}

fn is_trusted_chocolatey_install_dir(install_root: &Path, default_install_root: &Path) -> bool {
    paths_eq_ignore_ascii_case(install_root, default_install_root)
}

fn paths_eq_ignore_ascii_case(lhs: &Path, rhs: &Path) -> bool {
    lhs.as_os_str()
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .eq_ignore_ascii_case(rhs.as_os_str().to_string_lossy().trim_end_matches(['\\', '/']))
}

fn env_value_ignore_case<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

fn resolve_winget_executable(
    env: &HashMap<String, String>,
    requires_elevation: bool,
) -> anyhow::Result<(PathBuf, Option<policy_security::VerifiedExecutable>)> {
    let path_var = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    for dir in path_var.split(';') {
        let candidate = PathBuf::from(dir).join("winget.exe");
        if candidate.exists() && is_trusted_winget_path(&candidate, env) {
            let guard = policy_security::verify_elevated_executable_security(&candidate, requires_elevation)?;
            let candidate = guard.as_ref().map_or(candidate, |g| g.path().to_owned());
            return Ok((candidate, guard));
        }
    }
    bail!("trusted winget.exe not found in target user PATH");
}

fn resolve_vcpkg_executable(env: &HashMap<String, String>) -> anyhow::Result<PathBuf> {
    if let Some(root) = env_value_ignore_case(env, "VCPKG_ROOT")
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let candidate = PathBuf::from(root).join("vcpkg.exe");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let path_var = env_value_ignore_case(env, "PATH").unwrap_or_default();
    for dir in path_var.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(dir).join("vcpkg.exe");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("vcpkg.exe not found in target user VCPKG_ROOT or PATH");
}

fn resolve_cargo_executable(env: &HashMap<String, String>) -> anyhow::Result<PathBuf> {
    let path_var = env_value_ignore_case(env, "PATH").unwrap_or_default();
    for dir in path_var.split(';') {
        let candidate = PathBuf::from(dir).join("cargo.exe");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("cargo.exe not found in target user PATH");
}

fn resolve_python_executable(exe_name: &str, env: &HashMap<String, String>) -> anyhow::Result<PathBuf> {
    if !Path::new(exe_name)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("python.exe"))
    {
        bail!("pip command executable must be python.exe");
    }

    let path_var = env_value_ignore_case(env, "PATH").unwrap_or_default();
    for dir in path_var.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(dir).join("python.exe");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("python.exe not found in target user PATH");
}

fn resolve_bun_executable(executable: &str, env: &HashMap<String, String>) -> anyhow::Result<PathBuf> {
    let executable_path = Path::new(executable);
    if executable_path.is_absolute() {
        if executable_path.exists() {
            return Ok(executable_path.to_owned());
        }
        bail!(
            "bun executable not found at absolute path: {}",
            executable_path.display()
        );
    }

    let Some(file_name) = executable_path.file_name().and_then(|name| name.to_str()) else {
        bail!("invalid Bun executable name: {executable}");
    };

    let candidate_names: &[&str] = match file_name.to_ascii_lowercase().as_str() {
        "bun" => &["bun.exe", "bun.cmd"],
        "bun.exe" => &["bun.exe"],
        "bun.cmd" => &["bun.cmd"],
        _ => bail!("invalid Bun executable name: {executable}"),
    };

    let path_var = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    for dir in path_var.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        for candidate_name in candidate_names {
            let candidate = PathBuf::from(dir).join(candidate_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    bail!("bun executable not found in target user PATH");
}

fn is_trusted_winget_path(candidate: &Path, env: &HashMap<String, String>) -> bool {
    let candidate = candidate.as_os_str().to_string_lossy().to_lowercase();
    let program_files = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("ProgramFiles"))
        .map(|(_, value)| value)
        .map_or(r"C:\Program Files", |value| value)
        .to_lowercase();
    let local_app_data = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("LOCALAPPDATA"))
        .map(|(_, value)| value.to_lowercase());

    candidate.starts_with(&format!("{program_files}\\windowsapps\\"))
        || local_app_data.is_some_and(|path| candidate == format!("{path}\\microsoft\\windowsapps\\winget.exe"))
}

fn append_batch_argument(script: &mut String, value: &str) -> anyhow::Result<()> {
    if value.contains(['\0', '\r', '\n']) {
        bail!("package manager command arguments cannot contain control line separators");
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

fn append_cargo_batch_argument(script: &mut String, value: &str) -> anyhow::Result<()> {
    if value.contains('"') {
        bail!("broker command arguments cannot contain double quotes");
    }

    append_batch_argument(script, value)
}

fn append_batch_set_value(script: &mut String, name: &str, value: &str) -> anyhow::Result<()> {
    if value.contains(['\0', '\r', '\n', '"']) {
        bail!("batch environment values cannot contain control line separators or quotes");
    }

    script.push_str("set \"");
    script.push_str(name);
    script.push('=');
    script.push_str(&value.replace('%', "%%"));
    script.push('"');

    Ok(())
}

struct PreparedCommand {
    command: Vec<String>,
    _script: Option<TmpFileGuard>,
    /// Keeps a verified elevated executable embedded in the generated script locked
    /// against modification and replacement until the command has finished running.
    _exe_guard: Option<policy_security::VerifiedExecutable>,
}

impl PreparedCommand {
    fn raw(command: &[String]) -> Self {
        Self {
            command: command.to_vec(),
            _script: None,
            _exe_guard: None,
        }
    }

    fn with_script(command: Vec<String>, script: TmpFileGuard) -> Self {
        Self {
            command,
            _script: Some(script),
            _exe_guard: None,
        }
    }

    fn with_exe_guard(mut self, exe_guard: Option<policy_security::VerifiedExecutable>) -> Self {
        self._exe_guard = exe_guard;
        self
    }

    fn args(&self) -> &[String] {
        &self.command
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use now_policy_api::{Elevation, Scope};
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::security::acl::{
        Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee, set_named_security_info,
    };
    use win_api_wrappers::str::U16CString;
    use windows::Win32::Foundation::GENERIC_ALL;
    use windows::Win32::Security::Authorization::{GRANT_ACCESS, SE_FILE_OBJECT};
    use windows::Win32::Security::{NO_INHERITANCE, WinWorldSid};

    use super::{
        POWERSHELL_UTF8_ENCODING_PREAMBLE, WindowsExecutor, execute_as_current_user,
        prepare_chocolatey_script_in_with_default_install_root, prepare_main_command_in, prepare_shell_command_in,
        reject_unsupported_vcpkg_elevation, resolve_trusted_chocolatey_executable, resolve_winget_executable,
    };
    use crate::broker::executor::{CommandExecutor as _, ExecutionContext};

    fn grant(permissions: u32, sid: Sid) -> ExplicitAccess {
        ExplicitAccess {
            access_permissions: permissions,
            access_mode: GRANT_ACCESS,
            inheritance: NO_INHERITANCE,
            trustee: Trustee::Sid(sid),
        }
    }

    fn make_everyone_writable(path: &Path) {
        let everyone = Sid::from_well_known(WinWorldSid, None).expect("well-known Everyone SID");
        let dacl = InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: Acl::new()
                .and_then(|acl| acl.set_entries(&[grant(GENERIC_ALL.0, everyone)]))
                .expect("build ACL with Everyone full-control entry"),
        };
        let name = U16CString::from_os_str(path.as_os_str()).expect("no interior NUL in temp path");
        set_named_security_info(&name, SE_FILE_OBJECT, None, None, Some(&dacl), None)
            .expect("set everyone-writable DACL");
    }

    #[test]
    fn shell_command_uses_utf8_temp_batch_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = prepare_shell_command_in("echo héllo", Some(temp_dir.path())).expect("prepare shell command");

        assert!(command.args()[0].ends_with(r"\System32\cmd.exe"));
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
        let command =
            prepare_main_command_in(&command, Some(temp_dir.path()), None, false).expect("prepare PowerShell command");

        assert!(command.args()[0].ends_with(r"\System32\WindowsPowerShell\v1.0\powershell.exe"));
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
    fn powershell_command_preserves_host_flags_before_command() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = vec![
            "powershell.exe".to_owned(),
            "-NoProfile".to_owned(),
            "-ExecutionPolicy".to_owned(),
            "Bypass".to_owned(),
            "-Command".to_owned(),
            "Write-Output 'héllo'".to_owned(),
        ];
        let command =
            prepare_main_command_in(&command, Some(temp_dir.path()), None, false).expect("prepare PowerShell command");

        assert!(command.args()[0].ends_with(r"\System32\WindowsPowerShell\v1.0\powershell.exe"));
        assert_eq!(command.args()[1], "-NoProfile");
        assert_eq!(command.args()[2], "-ExecutionPolicy");
        assert_eq!(command.args()[3], "Bypass");
        assert_eq!(command.args()[4], "-Command");
        assert!(command.args()[5].starts_with("& '"));
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
        let command =
            prepare_main_command_in(&command, Some(temp_dir.path()), None, false).expect("prepare PowerShell command");

        assert!(command.args()[0].ends_with(r"\PowerShell\7\pwsh.exe"));
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
        ];
        let command =
            prepare_main_command_in(&command, Some(temp_dir.path()), None, false).expect("prepare WinGet command");

        assert!(command.args()[0].ends_with(r"\System32\cmd.exe"));
        assert_eq!(command.args()[1], "/D");
        assert_eq!(command.args()[2], "/V:OFF");
        assert_eq!(command.args()[3], "/Q");
        assert_eq!(command.args()[4], "/C");

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert!(script.starts_with("@echo off\r\n@chcp 65001 > nul\r\nset \"NO_COLOR=1\""));
        assert!(script.contains("\"winget.exe\" \"install\" \"--id\" \"Vendor.Package&Name\" \"100%%\""));
        assert!(script.contains("exit /b %ERRORLEVEL%"));
    }

    #[test]
    fn winget_elevated_execution_rejects_everyone_writable_executable() {
        let program_files = tempfile::tempdir().expect("create fake ProgramFiles");
        let windows_apps = program_files.path().join("WindowsApps");
        std::fs::create_dir_all(&windows_apps).expect("create fake WindowsApps dir");
        let winget_path = windows_apps.join("winget.exe");
        std::fs::write(&winget_path, b"").expect("write winget placeholder");
        make_everyone_writable(&winget_path);

        let env = HashMap::from([
            ("PATH".to_owned(), windows_apps.display().to_string()),
            ("ProgramFiles".to_owned(), program_files.path().display().to_string()),
        ]);

        let error = resolve_winget_executable(&env, true)
            .expect_err("an everyone-writable winget.exe must be rejected for elevated execution");
        assert!(
            error.to_string().contains("elevated package-manager executable"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn winget_non_elevated_execution_allows_everyone_writable_executable() {
        let program_files = tempfile::tempdir().expect("create fake ProgramFiles");
        let windows_apps = program_files.path().join("WindowsApps");
        std::fs::create_dir_all(&windows_apps).expect("create fake WindowsApps dir");
        let winget_path = windows_apps.join("winget.exe");
        std::fs::write(&winget_path, b"").expect("write winget placeholder");
        make_everyone_writable(&winget_path);

        let env = HashMap::from([
            ("PATH".to_owned(), windows_apps.display().to_string()),
            ("ProgramFiles".to_owned(), program_files.path().display().to_string()),
        ]);

        let (resolved, guard) =
            resolve_winget_executable(&env, false).expect("non-elevated resolution is not subject to the ACL check");
        assert_eq!(resolved, winget_path);
        assert!(guard.is_none(), "no guard is produced for non-elevated executions");
    }

    #[test]
    fn bun_cmd_command_uses_trusted_cmd_batch_wrapper() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let bun_path = temp_dir.path().join("bun.cmd");
        std::fs::write(&bun_path, "@echo off\r\n").expect("write bun wrapper");
        let mut user_env = HashMap::new();
        user_env.insert("PATH".to_owned(), temp_dir.path().display().to_string());
        let command = vec![
            "bun".to_owned(),
            "add".to_owned(),
            "typescript@5.7.3".to_owned(),
            "--global".to_owned(),
        ];

        let command = prepare_main_command_in(&command, Some(temp_dir.path()), Some(&user_env), false)
            .expect("prepare Bun command");

        assert!(command.args()[0].ends_with(r"\System32\cmd.exe"));
        assert_eq!(command.args()[1], "/D");
        assert_eq!(command.args()[2], "/V:OFF");
        assert_eq!(command.args()[3], "/Q");
        assert_eq!(command.args()[4], "/C");

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert!(script.starts_with("@echo off\r\n@chcp 65001 > nul\r\ncall "));
        assert!(script.contains(&format!(
            "\"{}\" \"add\" \"typescript@5.7.3\" \"--global\"",
            bun_path.display()
        )));
        assert!(script.contains("exit /b %ERRORLEVEL%"));
    }

    #[test]
    fn bun_exe_command_resolves_from_user_path_without_script_wrapper() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let bun_path = temp_dir.path().join("bun.exe");
        std::fs::write(&bun_path, b"").expect("write bun exe placeholder");
        let mut user_env = HashMap::new();
        user_env.insert("PATH".to_owned(), temp_dir.path().display().to_string());
        let command = vec![
            "bun".to_owned(),
            "add".to_owned(),
            "typescript@5.7.3".to_owned(),
            "--global".to_owned(),
        ];

        let command = prepare_main_command_in(&command, None, Some(&user_env), false).expect("prepare Bun command");

        assert_eq!(command.args()[0], bun_path.display().to_string());
        assert_eq!(command.args()[1], "add");
        assert_eq!(command.args()[2], "typescript@5.7.3");
        assert_eq!(command.args()[3], "--global");
    }

    #[test]
    fn temp_script_is_created_with_target_dacl() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let temp_script = super::broker_temp_script("bat", Some(temp_dir.path())).expect("create temp script");

        let dacl = read_file_dacl_sddl(temp_script.path());
        assert_eq!(dacl, super::SCRIPT_DACL);
    }

    /// Verifies that a non-admin user token can read the broker temporary script from the
    /// broker's temporary directory in real SYSTEM mode.
    ///
    /// Requires running as SYSTEM with at least one active interactive user session:
    ///
    /// ```text
    /// psexec -s cargo test -p devolutions-agent temp_script_is_readable_by_user_token_in_system_mode -- --ignored
    /// ```
    #[test]
    #[ignore = "requires running as SYSTEM with an active interactive user session"]
    fn temp_script_is_readable_by_user_token_in_system_mode() {
        use win_api_wrappers::process::Process;
        use win_api_wrappers::security::privilege::{self, ScopedPrivileges};
        use win_api_wrappers::token::Token;
        use win_api_wrappers::wts;
        use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};

        assert!(
            super::token::detect_running_as_system(),
            "this test must run under the SYSTEM account"
        );

        // Create and populate the script exactly as the broker does in SYSTEM mode
        // (default temporary directory).
        let temp_script = super::broker_temp_script("ps1", None).expect("create temp script");
        temp_script
            .write_content("Write-Output 'hello'")
            .expect("write temp script");

        // Find an active interactive user session.
        let sessions = wts::get_sessions().expect("enumerate WTS sessions");
        let session_id = sessions
            .iter()
            .find(|session| session.session_id != 0 && session.state == wts::WTSConnectState::Active)
            .map(|session| session.session_id)
            .expect("no active interactive user session found");

        // Grab the session's (non-elevated) user token and impersonate it while reading.
        let mut process_token = Process::current_process()
            .token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
            .expect("open process token");
        let _priv_tcb = ScopedPrivileges::enter(&mut process_token, &[privilege::SE_TCB_NAME]).expect("enable SeTcb");

        let user_token = Token::for_session(session_id).expect("query user token for session");
        let _impersonation = user_token.impersonate().expect("impersonate user token");

        let content =
            std::fs::read_to_string(temp_script.path()).expect("user token failed to read broker temp script");
        assert_eq!(content, "Write-Output 'hello'");
    }

    /// Reads back the DACL of `path` as an SDDL string (`D:...`).
    fn read_file_dacl_sddl(path: &Path) -> String {
        use win_api_wrappers::utils::WideString;
        use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
            SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
        use windows::core::PWSTR;

        let path = WideString::from(path);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();

        // SAFETY: `path` is a valid null-terminated UTF-16 path and the output pointer is valid.
        let result = unsafe {
            GetNamedSecurityInfoW(
                path.as_pcwstr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut descriptor as *mut PSECURITY_DESCRIPTOR,
            )
        };
        assert_eq!(result, ERROR_SUCCESS, "GetNamedSecurityInfoW failed");

        let mut sddl = PWSTR::null();

        // SAFETY: `descriptor` is a valid security descriptor returned by `GetNamedSecurityInfoW`
        // and the output pointer is valid.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                None,
            )
        }
        .expect("convert security descriptor to SDDL");

        // SAFETY: `sddl` is a valid null-terminated UTF-16 string allocated by the call above.
        let sddl_string = unsafe { sddl.to_string() }.expect("SDDL is valid UTF-16");

        // SAFETY: `sddl` is a `LocalAlloc` allocation owned by us.
        unsafe { LocalFree(Some(HLOCAL(sddl.0.cast()))) };
        // SAFETY: `descriptor` is a `LocalAlloc` allocation owned by us.
        unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };

        sddl_string
    }

    #[test]
    fn chocolatey_command_uses_chocolateyinstall_path_and_batch_wrapper() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let trusted_program_data = tempfile::tempdir().expect("create fake trusted ProgramData");
        let install_root = trusted_program_data.path().join("chocolatey");
        let choco_bin = install_root.join("bin");
        std::fs::create_dir_all(&choco_bin).expect("create fake Chocolatey bin");
        std::fs::write(choco_bin.join("choco.exe"), "").expect("create fake choco");
        let untrusted_program_data = tempfile::tempdir().expect("create fake untrusted ProgramData");
        let env = HashMap::from([
            ("ChocolateyInstall".to_owned(), install_root.display().to_string()),
            (
                "ProgramData".to_owned(),
                untrusted_program_data.path().display().to_string(),
            ),
        ]);

        let command = vec![
            "choco.exe".to_owned(),
            "install".to_owned(),
            "Vendor.Package&Name".to_owned(),
            "100%".to_owned(),
            "Quoted\"Value".to_owned(),
        ];
        let command = prepare_chocolatey_script_in_with_default_install_root(
            &command,
            Some(temp_dir.path()),
            Some(&env),
            &install_root,
            false,
        )
        .expect("prepare Chocolatey command");

        assert!(command.args()[0].ends_with(r"\System32\cmd.exe"));
        assert_eq!(command.args()[1], "/D");
        assert_eq!(command.args()[2], "/V:OFF");
        assert_eq!(command.args()[3], "/Q");
        assert_eq!(command.args()[4], "/C");

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert!(script.starts_with("@echo off\r\n@chcp 65001 > nul\r\nset \"NO_COLOR=1\""));
        assert!(script.contains(&format!("set \"ChocolateyInstall={}\"", install_root.display())));
        assert!(script.contains(&format!(
            "\"{}\" \"install\" \"Vendor.Package&Name\" \"100%%\" \"Quoted\\\"Value\"",
            choco_bin.join("choco.exe").display()
        )));
        assert!(script.contains("if \"%CHOCO_EXIT_CODE%\"==\"3010\" exit /b 0"));
        assert!(script.contains("exit /b %CHOCO_EXIT_CODE%"));
    }

    #[test]
    fn chocolatey_command_rejects_missing_chocolateyinstall_executable() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let program_data = tempfile::tempdir().expect("create fake ProgramData");
        let install_root = program_data.path().join("chocolatey");
        let env = HashMap::from([
            ("ChocolateyInstall".to_owned(), install_root.display().to_string()),
            ("ProgramData".to_owned(), program_data.path().display().to_string()),
        ]);
        let command = vec!["choco.exe".to_owned(), "install".to_owned(), "git".to_owned()];

        let error = match prepare_chocolatey_script_in_with_default_install_root(
            &command,
            Some(temp_dir.path()),
            Some(&env),
            &install_root,
            false,
        ) {
            Ok(_) => panic!("missing trusted choco should fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("Chocolatey executable was not found"));
    }

    #[test]
    fn chocolatey_command_rejects_non_system_chocolateyinstall_path() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let install_root = tempfile::tempdir().expect("create fake ChocolateyInstall");
        let choco_bin = install_root.path().join("bin");
        std::fs::create_dir_all(&choco_bin).expect("create fake Chocolatey bin");
        std::fs::write(choco_bin.join("choco.exe"), "").expect("create fake choco");
        let trusted_program_data = tempfile::tempdir().expect("create fake trusted ProgramData");
        let trusted_install_root = trusted_program_data.path().join("chocolatey");
        let env = HashMap::from([
            (
                "ChocolateyInstall".to_owned(),
                install_root.path().display().to_string(),
            ),
            ("ProgramData".to_owned(), install_root.path().display().to_string()),
        ]);
        let command = vec!["choco.exe".to_owned(), "install".to_owned(), "git".to_owned()];

        let error = match prepare_chocolatey_script_in_with_default_install_root(
            &command,
            Some(temp_dir.path()),
            Some(&env),
            &trusted_install_root,
            false,
        ) {
            Ok(_) => panic!("non-system ChocolateyInstall should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("trusted system Chocolatey folder"));
    }

    #[test]
    fn chocolatey_elevated_execution_rejects_everyone_writable_executable() {
        let program_data = tempfile::tempdir().expect("create fake ProgramData");
        let install_root = program_data.path().join("chocolatey");
        let choco_bin = install_root.join("bin");
        std::fs::create_dir_all(&choco_bin).expect("create fake Chocolatey bin");
        let choco_path = choco_bin.join("choco.exe");
        std::fs::write(&choco_path, "").expect("create fake choco");
        make_everyone_writable(&choco_path);

        let error = resolve_trusted_chocolatey_executable(None, &install_root, true)
            .expect_err("an everyone-writable choco.exe must be rejected for elevated execution");
        assert!(
            error.to_string().contains("elevated package-manager executable"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn chocolatey_non_elevated_execution_allows_everyone_writable_executable() {
        let program_data = tempfile::tempdir().expect("create fake ProgramData");
        let install_root = program_data.path().join("chocolatey");
        let choco_bin = install_root.join("bin");
        std::fs::create_dir_all(&choco_bin).expect("create fake Chocolatey bin");
        let choco_path = choco_bin.join("choco.exe");
        std::fs::write(&choco_path, "").expect("create fake choco");
        make_everyone_writable(&choco_path);

        let (resolved, resolved_root, guard) = resolve_trusted_chocolatey_executable(None, &install_root, false)
            .expect("non-elevated resolution is not subject to the ACL check");
        assert_eq!(resolved, choco_path);
        assert_eq!(resolved_root, install_root);
        assert!(guard.is_none(), "no guard is produced for non-elevated executions");
    }

    #[test]
    fn cargo_command_uses_batch_wrapper_for_utf8_output() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = vec![
            "cargo.exe".to_owned(),
            "install".to_owned(),
            "ripgrep".to_owned(),
            "--version".to_owned(),
            "15.1.0".to_owned(),
        ];
        let command =
            prepare_main_command_in(&command, Some(temp_dir.path()), None, false).expect("prepare Cargo command");

        assert!(command.args()[0].ends_with(r"\System32\cmd.exe"));
        assert_eq!(command.args()[1], "/D");
        assert_eq!(command.args()[2], "/V:OFF");
        assert_eq!(command.args()[3], "/Q");
        assert_eq!(command.args()[4], "/C");

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert!(script.starts_with("@echo off\r\n@chcp 65001 > nul\r\nset \"NO_COLOR=1\""));
        assert!(script.contains("\"cargo.exe\" \"install\" \"ripgrep\" \"--version\" \"15.1.0\""));
        assert!(script.contains("exit /b %ERRORLEVEL%"));
    }

    #[test]
    fn cargo_command_resolves_executable_from_user_path() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let cargo_home = temp_dir.path().join(".cargo").join("bin");
        std::fs::create_dir_all(&cargo_home).expect("create cargo bin dir");
        std::fs::write(cargo_home.join("cargo.exe"), b"").expect("write cargo executable placeholder");

        let mut env = HashMap::new();
        env.insert("PATH".to_owned(), cargo_home.display().to_string());

        let command = vec!["cargo.exe".to_owned(), "uninstall".to_owned(), "ripgrep".to_owned()];
        let command =
            prepare_main_command_in(&command, Some(temp_dir.path()), Some(&env), false).expect("prepare Cargo command");

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert!(script.contains(&format!(
            "\"{}\" \"uninstall\" \"ripgrep\"",
            cargo_home.join("cargo.exe").display()
        )));
    }

    #[test]
    fn batch_wrapper_rejects_quotes_before_writing_script() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = vec![
            "cargo.exe".to_owned(),
            "install".to_owned(),
            "ripgrep".to_owned(),
            "--root".to_owned(),
            "C:\\Tools\\\"& whoami &\"".to_owned(),
        ];

        let error = match prepare_main_command_in(&command, Some(temp_dir.path()), None, false) {
            Ok(_) => panic!("quote should fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("double quotes"));
    }

    #[test]
    fn vcpkg_command_uses_batch_wrapper_with_user_resolved_executable() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let vcpkg_root = temp_dir.path().join("vcpkg-root");
        std::fs::create_dir(&vcpkg_root).expect("create vcpkg root");
        std::fs::write(vcpkg_root.join("vcpkg.exe"), []).expect("create vcpkg exe");

        let command = vec![
            "vcpkg.exe".to_owned(),
            "install".to_owned(),
            "zlib:x64-windows".to_owned(),
        ];
        let user_env = HashMap::from([("VCPKG_ROOT".to_owned(), vcpkg_root.display().to_string())]);
        let command = prepare_main_command_in(&command, Some(temp_dir.path()), Some(&user_env), false)
            .expect("prepare vcpkg command");

        assert!(command.args()[0].ends_with(r"\System32\cmd.exe"));
        assert_eq!(command.args()[1], "/D");
        assert_eq!(command.args()[2], "/V:OFF");
        assert_eq!(command.args()[3], "/Q");
        assert_eq!(command.args()[4], "/C");

        let script = std::fs::read_to_string(&command.args()[5]).expect("read temp script");
        assert!(script.starts_with("@echo off\r\n@chcp 65001 > nul\r\nset \"NO_COLOR=1\""));
        assert!(script.contains("\"install\" \"zlib:x64-windows\""));
        assert!(script.contains("vcpkg.exe"));
        assert!(script.contains("exit /b %ERRORLEVEL%"));
    }

    #[test]
    fn vcpkg_elevated_execution_is_rejected() {
        let mut ctx = ExecutionContext {
            kill_processes: Vec::new(),
            pre_command: None,
            command: vec![
                "vcpkg.exe".to_owned(),
                "install".to_owned(),
                "zlib:x64-windows".to_owned(),
            ],
            post_command: None,
            effective_user: "DOMAIN\\user".to_owned(),
            user_sid: Sid::from_well_known(WinWorldSid, None).expect("well-known Everyone SID"),
            elevation: Elevation::Elevated,
            scope: Some(Scope::User),
            capture_output: false,
            cancel_token: tokio_util::sync::CancellationToken::new(),
        };

        let error = reject_unsupported_vcpkg_elevation(&ctx).expect_err("elevated vcpkg should fail");
        assert!(error.to_string().contains("elevated"));

        ctx.elevation = Elevation::Standard;
        ctx.scope = Some(Scope::Machine);
        let error = reject_unsupported_vcpkg_elevation(&ctx).expect_err("machine-scope vcpkg should fail");
        assert!(error.to_string().contains("machine-scope"));
    }

    #[tokio::test]
    async fn elevated_pre_post_commands_are_rejected_by_executor() {
        let ctx = ExecutionContext {
            kill_processes: Vec::new(),
            pre_command: Some("echo before".to_owned()),
            command: vec!["winget.exe".to_owned(), "install".to_owned()],
            post_command: None,
            effective_user: "DOMAIN\\user".to_owned(),
            user_sid: Sid::from_well_known(WinWorldSid, None).expect("well-known Everyone SID"),
            elevation: Elevation::Elevated,
            scope: Some(Scope::User),
            capture_output: false,
            cancel_token: tokio_util::sync::CancellationToken::new(),
        };

        let executor = WindowsExecutor { is_system: true };
        let error = executor
            .execute(&ctx, None)
            .await
            .expect_err("elevated pre-command should fail");
        assert!(error.to_string().contains("non-elevated"));
    }

    #[test]
    fn non_system_mode_rejects_client_user_different_from_broker_user() {
        let ctx = ExecutionContext {
            kill_processes: Vec::new(),
            pre_command: None,
            command: vec![
                r"C:\Windows\System32\cmd.exe".to_owned(),
                "/C".to_owned(),
                "exit".to_owned(),
            ],
            post_command: None,
            effective_user: "DOMAIN\\other".to_owned(),
            // The Everyone (World) SID never matches the test process user SID.
            user_sid: Sid::from_well_known(WinWorldSid, None).expect("well-known Everyone SID"),
            elevation: Elevation::Standard,
            scope: Some(Scope::User),
            capture_output: false,
            cancel_token: tokio_util::sync::CancellationToken::new(),
        };

        let error = execute_as_current_user(&ctx, None).expect_err("mismatched client SID should fail");
        assert!(error.to_string().contains("does not match broker process user SID"));
    }

    #[test]
    fn pip_command_resolves_python_without_shell_wrapper() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let python_path = temp_dir.path().join("python.exe");
        std::fs::write(&python_path, b"").expect("write python placeholder");
        let user_env = HashMap::from([("PATH".to_owned(), temp_dir.path().display().to_string())]);
        let command = vec![
            "python.exe".to_owned(),
            "-m".to_owned(),
            "pip".to_owned(),
            "--isolated".to_owned(),
            "install".to_owned(),
            "requests==2.31.0".to_owned(),
            "--no-input".to_owned(),
        ];
        let command = prepare_main_command_in(&command, Some(temp_dir.path()), Some(&user_env), false)
            .expect("prepare Pip command");

        assert_eq!(command.args()[0], python_path.display().to_string());
        assert_eq!(command.args()[1], "-m");
        assert_eq!(command.args()[2], "pip");
        assert_eq!(command.args()[3], "--isolated");
        assert_eq!(command.args()[4], "install");
        assert_eq!(command.args()[5], "requests==2.31.0");
        assert_eq!(command.args()[6], "--no-input");
    }
}
