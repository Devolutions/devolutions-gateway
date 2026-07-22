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
use win_api_wrappers::utils::WideString;
use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_QUERY};

use super::{CommandExecutor, ExecutionContext, ExecutionOutput, ProcessStartedCallback};

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
    async fn execute(
        &self,
        ctx: &ExecutionContext,
        process_started: Option<ProcessStartedCallback>,
    ) -> anyhow::Result<ExecutionOutput> {
        let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine);

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
}

/// Execute a command in the context of the target user's session (SYSTEM mode).
///
/// Steps:
/// 1. Find the user's active session via WTS enumeration.
/// 2. Get the session token.
/// 3. If elevated execution is requested, obtain the linked elevated token.
/// 4. Set the token session ID and create the process.
/// 5. Wait for the process to exit and return the exit code.
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

/// Execute a command as the current user (development mode).
///
/// Opens the current process token and uses the same `create_process_as_user`
/// code path as SYSTEM mode, ensuring consistent behavior (environment, desktop, flags).
fn execute_as_current_user(
    ctx: &ExecutionContext,
    process_started: Option<ProcessStartedCallback>,
) -> anyhow::Result<ExecutionOutput> {
    info!(
        effective_user = %ctx.effective_user,
        "Executing command as current user (dev mode)"
    );

    let token = Process::current_process()
        .token(TOKEN_ALL_ACCESS)
        .context("failed to open current process token")?;

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
    // 1. Kill requested processes (best-effort; a missing process is not an error).
    for process_name in &ctx.kill_processes {
        let kill_cmd = vec![
            trusted_system32_executable("taskkill.exe"),
            "/F".to_owned(),
            "/IM".to_owned(),
            process_name.clone(),
        ];
        match create_process(token, &kill_cmd, session_id, false, None) {
            Ok(out) => info!(%process_name, exit_code = out.exit_code, "Kill-before-operation completed"),
            Err(error) => warn!(%process_name, %error, "Kill-before-operation failed (ignored)"),
        }
    }

    // 2. Pre-operation command — must succeed before the main operation runs.
    if let Some(pre) = &ctx.pre_command {
        info!("Running pre-operation command");
        let command = prepare_shell_command(token, pre)?;
        let out = create_process(token, command.args(), session_id, ctx.capture_output, None)
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
    let output = create_process(token, command.args(), session_id, ctx.capture_output, process_started)?;

    // 4. Post-operation command — runs after the main command; failures are logged only.
    if let Some(post) = &ctx.post_command {
        info!("Running post-operation command");
        let command = prepare_shell_command(token, post)?;
        match create_process(token, command.args(), session_id, false, None) {
            Ok(out) if out.exit_code == 0 => {}
            Ok(out) => warn!(exit_code = out.exit_code, "Post-operation command exited non-zero"),
            Err(error) => warn!(%error, "Post-operation command failed"),
        }
    }

    Ok(output)
}

fn prepare_main_command(token: &Token, command: &[String]) -> anyhow::Result<PreparedCommand> {
    let user_env = win_api_wrappers::utils::environment_block(Some(token), false)
        .context("failed to load user environment block")?;
    prepare_main_command_in(command, None, Some(&user_env))
}

fn prepare_main_command_in(
    command: &[String],
    temp_dir: Option<&Path>,
    user_env: Option<&std::collections::HashMap<String, String>>,
) -> anyhow::Result<PreparedCommand> {
    if let Some(script) = powershell_inline_script(command) {
        return prepare_powershell_script(command, script, temp_dir);
    }

    if executable_is(command, "winget.exe") {
        return prepare_winget_script(command, temp_dir, user_env);
    }

    Ok(PreparedCommand::raw(command))
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
    protect_temp_script(&temp_script)?;

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
    protect_temp_script(&temp_script)?;

    let mut prepared = command[..2].to_vec();
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
    user_env: Option<&std::collections::HashMap<String, String>>,
) -> anyhow::Result<PreparedCommand> {
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str(BATCH_UTF8_PREAMBLE);
    script.push_str("\r\nset \"NO_COLOR=1\"\r\n");

    let (executable, args) = command.split_first().context("empty WinGet command")?;
    let executable = user_env.map_or_else(
        || Ok(executable.clone()),
        |env| resolve_winget_executable(env).map(|path| path.display().to_string()),
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
    protect_temp_script(&temp_script)?;

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

fn protect_temp_script(temp_script: &TmpFileGuard) -> anyhow::Result<()> {
    // Owner keeps full control; interactive users only need read access to execute the script.
    const SCRIPT_DACL: &str = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;BU)";
    set_file_dacl(temp_script.path(), SCRIPT_DACL)
}

fn set_file_dacl(path: &Path, acl: &str) -> anyhow::Result<()> {
    use windows::Win32::Foundation::{ERROR_SUCCESS, FALSE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR};

    struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for OwnedSecurityDescriptor {
        fn drop(&mut self) {
            if self.0.0.is_null() {
                return;
            }
            // SAFETY: The descriptor pointer is returned by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
            unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }

    let acl = WideString::from(acl);
    let mut security_descriptor = OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR::default());

    // SAFETY: `acl` is a valid null-terminated UTF-16 string and the output pointer is valid.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            acl.as_pcwstr(),
            SDDL_REVISION_1,
            &mut security_descriptor.0 as *mut PSECURITY_DESCRIPTOR,
            None,
        )
    }
    .context("failed to convert broker script DACL")?;

    let mut dacl_present = FALSE;
    let mut dacl_defaulted = FALSE;
    let mut dacl: *mut ACL = std::ptr::null_mut();

    // SAFETY: All output pointers are valid and `security_descriptor` owns a valid descriptor.
    unsafe { GetSecurityDescriptorDacl(security_descriptor.0, &mut dacl_present, &mut dacl, &mut dacl_defaulted) }
        .context("failed to read broker script DACL")?;

    if dacl.is_null() {
        bail!("broker script DACL is null");
    }

    let path = WideString::from(path);
    // SAFETY: `path` is a valid null-terminated UTF-16 path and `dacl` remains valid for the call.
    let result = unsafe {
        SetNamedSecurityInfoW(
            path.as_pcwstr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if result != ERROR_SUCCESS {
        bail!("failed to set broker script DACL");
    }

    Ok(())
}

fn executable_is(command: &[String], expected_name: &str) -> bool {
    command.first().is_some_and(|executable| {
        Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
    })
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

fn resolve_winget_executable(env: &std::collections::HashMap<String, String>) -> anyhow::Result<PathBuf> {
    let path_var = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    for dir in path_var.split(';') {
        let candidate = PathBuf::from(dir).join("winget.exe");
        if candidate.exists() && is_trusted_winget_path(&candidate, env) {
            return Ok(candidate);
        }
    }
    bail!("trusted winget.exe not found in target user PATH");
}

fn is_trusted_winget_path(candidate: &Path, env: &std::collections::HashMap<String, String>) -> bool {
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
            prepare_main_command_in(&command, Some(temp_dir.path()), None).expect("prepare PowerShell command");

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
    fn powershell7_command_uses_bomless_utf8_temp_script_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let command = vec![
            "pwsh.exe".to_owned(),
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "Write-Output 'héllo'".to_owned(),
        ];
        let command =
            prepare_main_command_in(&command, Some(temp_dir.path()), None).expect("prepare PowerShell command");

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
            "Quoted\"Value".to_owned(),
        ];
        let command = prepare_main_command_in(&command, Some(temp_dir.path()), None).expect("prepare WinGet command");

        assert!(command.args()[0].ends_with(r"\System32\cmd.exe"));
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
