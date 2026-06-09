//! Command execution module.
//!
//! Handles running commands (primarily WinGet) under the specified user identity.
//!
//! Uses a unified `CreateProcessAsUserW` code path for both SYSTEM (service) and
//! current-user (development) modes. This ensures consistent behavior regarding:
//! - User environment block (`CreateEnvironmentBlock`)
//! - Interactive desktop assignment (`WinSta0\Default`)
//! - Process creation flags (`CREATE_NEW_CONSOLE`, `CREATE_UNICODE_ENVIRONMENT`)
//! - Token session assignment
//!
//! When the broker runs as SYSTEM (production service context), the executor:
//! 1. Enumerates sessions to find the target user's logon session.
//! 2. Obtains and duplicates their token.
//! 3. Optionally retrieves the linked elevated token for `elevated` mode.
//! 4. Loads the user's environment block and creates the process.
//!
//! When running as a normal user (development/debug), the executor:
//! - Opens the current process token and uses it directly.
//! - Rejects `elevated` requests (cannot elevate without SYSTEM).

use async_trait::async_trait;

use crate::model::{Elevation, Scope};

/// Execution context passed from the server to the executor.
///
/// Describes the full ordered plan the broker runs on the user's behalf:
/// process kills, an optional pre-operation shell command, the main
/// package-manager command, and an optional post-operation shell command.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Process image names to terminate before the operation (best-effort).
    pub kill_processes: Vec<String>,
    /// Optional shell command to run before the main command (`cmd.exe /S /C`).
    pub pre_command: Option<String>,
    /// The main package-manager command line as separate arguments (exe + args).
    pub command: Vec<String>,
    /// Optional shell command to run after the main command (`cmd.exe /S /C`).
    pub post_command: Option<String>,
    /// Windows identity of the target user (e.g., `DOMAIN\username`).
    pub effective_user: String,
    /// Requested elevation level.
    pub elevation: Elevation,
    /// Installation scope (machine scope requires elevation).
    pub scope: Option<Scope>,
}

/// Trait for command execution strategies.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Execute a command under the given context.
    ///
    /// Returns the process exit code on success. The method blocks (async) until
    /// the spawned process exits or a fatal error occurs during launch.
    async fn execute(&self, ctx: &ExecutionContext) -> anyhow::Result<i32>;
}

/// Dry-run executor that only logs commands without running them.
pub struct DryRunExecutor;

#[async_trait]
impl CommandExecutor for DryRunExecutor {
    async fn execute(&self, ctx: &ExecutionContext) -> anyhow::Result<i32> {
        tracing::info!(
            effective_user = %ctx.effective_user,
            kill_processes = ?ctx.kill_processes,
            pre_command = ?ctx.pre_command,
            command = %ctx.command.join(" "),
            post_command = ?ctx.post_command,
            elevation = %ctx.elevation,
            "Dry-run: would execute plan"
        );
        Ok(0)
    }
}

/// Create the appropriate command executor for the current platform.
///
/// On Windows, returns a `WindowsExecutor` that uses raw Win32 APIs.
/// On other platforms, returns a `DryRunExecutor` since named pipes
/// and WinGet are not available.
pub fn create_platform_executor() -> Box<dyn CommandExecutor> {
    #[cfg(windows)]
    {
        Box::new(WindowsExecutor::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(DryRunExecutor)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Windows implementation
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(windows)]
mod win {
    use std::path::{Path, PathBuf};

    use anyhow::{Context as _, bail};
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::process::{self, Process, StartupInfo};
    use win_api_wrappers::security::privilege::{self, ScopedPrivileges};
    use win_api_wrappers::token::{Token, TokenElevationType};
    use win_api_wrappers::utils::{self, CommandLine, WideString};
    use win_api_wrappers::wts;
    use windows::Win32::Security::{
        SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_QUERY, TokenPrimary,
    };
    use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, NORMAL_PRIORITY_CLASS};

    use super::*;

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
                tracing::info!("Executor initialized in SYSTEM (service) mode");
            } else {
                tracing::info!("Executor initialized in user (development) mode");
            }
            Self { is_system }
        }
    }

    #[async_trait]
    impl CommandExecutor for WindowsExecutor {
        async fn execute(&self, ctx: &ExecutionContext) -> anyhow::Result<i32> {
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

    /// Detect whether the current process is running under the SYSTEM account.
    ///
    /// Compares the process token SID against S-1-5-18 (LocalSystem).
    fn detect_running_as_system() -> bool {
        let Ok(token) = Process::current_process().token(TOKEN_QUERY) else {
            return false;
        };

        let Ok(sid_and_attrs) = token.sid_and_attributes() else {
            return false;
        };

        let Ok(system_sid) = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None) else {
            return false;
        };

        sid_and_attrs.sid == system_sid
    }

    /// Execute a command in the context of the target user's session (SYSTEM mode).
    ///
    /// Steps:
    /// 1. Find the user's active session via WTS enumeration.
    /// 2. Get the session token.
    /// 3. If elevated execution is requested, obtain the linked elevated token.
    /// 4. Set the token session ID and create the process.
    /// 5. Wait for the process to exit and return the exit code.
    fn execute_as_system(ctx: &ExecutionContext) -> anyhow::Result<i32> {
        let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.scope == Some(Scope::Machine);

        tracing::info!(
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

        tracing::debug!("Enabling SeTcb privilege");
        let mut _priv_tcb =
            ScopedPrivileges::enter(&mut process_token, &[privilege::SE_TCB_NAME]).context("failed to enable SeTcb")?;

        tracing::debug!("Enabling SeAssignPrimaryToken privilege");
        let mut _priv_primary =
            ScopedPrivileges::enter(_priv_tcb.token_mut(), &[privilege::SE_ASSIGNPRIMARYTOKEN_NAME])
                .context("failed to enable SeAssignPrimaryToken")?;

        tracing::debug!("Enabling SeIncreaseQuota privilege");
        let _priv_quota = ScopedPrivileges::enter(_priv_primary.token_mut(), &[privilege::SE_INCREASE_QUOTA_NAME])
            .context("failed to enable SeIncreaseQuota")?;

        tracing::debug!("All privileges enabled, finding user session");

        let session_id = find_user_session(&ctx.effective_user).context("failed to find active session for user")?;

        tracing::info!(
            effective_user = %ctx.effective_user,
            session_id,
            "Found user session"
        );

        tracing::debug!(session_id, "Calling Token::for_session");
        let user_token = Token::for_session(session_id).context("failed to obtain user token for session")?;

        tracing::debug!("Duplicating user token as primary");
        let primary_token = user_token
            .duplicate(TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary)
            .context("failed to duplicate token as primary")?;

        let mut execution_token = if requires_elevation {
            tracing::debug!("Attempting to get elevated token");
            match get_elevated_token(&primary_token) {
                Ok(elevated) => {
                    tracing::info!("Using elevated (linked) token");
                    elevated
                }
                Err(error) => {
                    tracing::warn!(%error, "Could not obtain elevated token, using primary");
                    primary_token
                }
            }
        } else {
            tracing::debug!("Using non-elevated primary token");
            primary_token
        };

        // Assign the target session to the token before process creation.
        tracing::debug!(session_id, "Setting token session ID");
        execution_token
            .set_session_id(session_id)
            .context("failed to set token session ID")?;

        tracing::info!(
            command = %ctx.command.join(" "),
            session_id,
            "Running execution plan"
        );

        let exit_code = run_plan(&execution_token, ctx, session_id)?;

        tracing::info!(
            effective_user = %ctx.effective_user,
            command = %ctx.command.join(" "),
            exit_code,
            "Plan completed under user token"
        );

        Ok(exit_code)
    }

    /// Execute a command as the current user (development mode).
    ///
    /// Opens the current process token and uses the same `create_process_as_user`
    /// code path as SYSTEM mode, ensuring consistent behavior (environment, desktop, flags).
    fn execute_as_current_user(ctx: &ExecutionContext) -> anyhow::Result<i32> {
        tracing::info!(
            effective_user = %ctx.effective_user,
            command = %ctx.command.join(" "),
            "Executing command as current user (dev mode)"
        );

        let token = Process::current_process()
            .token(TOKEN_ALL_ACCESS)
            .context("failed to open current process token")?;

        let session_id = token.session_id().context("failed to query token session ID")?;

        let exit_code = run_plan(&token, ctx, session_id)?;

        tracing::info!(
            command = %ctx.command.join(" "),
            exit_code,
            "Plan completed under current user token"
        );

        Ok(exit_code)
    }

    /// Run the full execution plan under `token`: best-effort process kills, an
    /// optional pre-operation command (must succeed), the main package-manager
    /// command, then an optional post-operation command (failures are logged).
    ///
    /// Returns the exit code of the main command.
    fn run_plan(token: &Token, ctx: &ExecutionContext, session_id: u32) -> anyhow::Result<i32> {
        // 1. Kill requested processes (best-effort; a missing process is not an error).
        for process_name in &ctx.kill_processes {
            let kill_cmd = vec![
                "taskkill.exe".to_owned(),
                "/F".to_owned(),
                "/IM".to_owned(),
                process_name.clone(),
            ];
            match create_process_and_wait(token, &kill_cmd, session_id) {
                Ok(code) => tracing::info!(%process_name, exit_code = code, "Kill-before-operation completed"),
                Err(error) => tracing::warn!(%process_name, %error, "Kill-before-operation failed (ignored)"),
            }
        }

        // 2. Pre-operation command — must succeed before the main operation runs.
        if let Some(pre) = &ctx.pre_command {
            tracing::info!(command = %pre, "Running pre-operation command");
            let code = create_process_and_wait(token, &shell_command(pre), session_id)
                .context("failed to run pre-operation command")?;
            if code != 0 {
                bail!("pre-operation command exited with code {code}");
            }
        }

        // 3. Main package-manager command.
        let exit_code = create_process_and_wait(token, &ctx.command, session_id)?;

        // 4. Post-operation command — runs after the main command; failures are logged only.
        if let Some(post) = &ctx.post_command {
            tracing::info!(command = %post, "Running post-operation command");
            match create_process_and_wait(token, &shell_command(post), session_id) {
                Ok(0) => {}
                Ok(code) => tracing::warn!(exit_code = code, "Post-operation command exited non-zero"),
                Err(error) => tracing::warn!(%error, "Post-operation command failed"),
            }
        }

        Ok(exit_code)
    }

    /// Build a `cmd.exe` invocation for a client-supplied shell payload.
    ///
    /// Mirrors UniGetUI's pre/post command semantics: newlines are collapsed into
    /// `&` separators, and `/S /C` makes `cmd.exe` strip the outermost quotes and
    /// run the remainder verbatim, so the quoting added by `CommandLine` round-trips.
    fn shell_command(payload: &str) -> Vec<String> {
        let normalized = payload.replace('\r', "\n").replace("\n\n", "\n").replace('\n', "&");
        vec!["cmd.exe".to_owned(), "/S".to_owned(), "/C".to_owned(), normalized]
    }

    /// Enumerate WTS sessions to find one belonging to `effective_user`.
    ///
    /// `effective_user` can be `DOMAIN\user` or just `user`.
    fn find_user_session(effective_user: &str) -> anyhow::Result<u32> {
        let target_username = effective_user
            .rsplit('\\')
            .next()
            .unwrap_or(effective_user)
            .to_lowercase();

        let sessions = wts::get_sessions().context("failed to enumerate WTS sessions")?;

        for session in &sessions {
            if session.session_id == 0 {
                continue;
            }

            if let Ok(session_user) = wts::get_session_user_name(session.session_id)
                && session_user.to_lowercase() == target_username
            {
                return Ok(session.session_id);
            }
        }

        anyhow::bail!("no active session found for user '{effective_user}'")
    }

    /// Attempt to obtain an elevated (linked) token from a filtered/limited token.
    ///
    /// On UAC-enabled systems with split tokens, the standard user token has a linked
    /// elevated token. This function retrieves it when elevation is requested.
    fn get_elevated_token(token: &Token) -> anyhow::Result<Token> {
        let elevation_type = token.elevation_type().context("failed to query elevation type")?;

        match elevation_type {
            TokenElevationType::Full => {
                // Already elevated — duplicate as primary.
                token
                    .duplicate(TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary)
                    .context("failed to duplicate full token")
            }
            TokenElevationType::Limited => {
                // Obtain the linked (elevated) token and duplicate as primary.
                let linked = token.linked_token().context("failed to get linked token")?;
                linked
                    .duplicate(TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary)
                    .context("failed to duplicate linked token")
            }
            TokenElevationType::Default => {
                bail!("token elevation type is Default; cannot elevate (UAC may be disabled)");
            }
        }
    }

    /// Create a process under the given token and wait for it to exit.
    ///
    /// This is the unified process-creation path used by both SYSTEM and current-user modes.
    /// It:
    /// - Sets `lpDesktop` to `WinSta0\Default` so the process can interact with the user desktop.
    /// - Passes `None` for environment so `create_process_as_user` loads the user's environment
    ///   block via `CreateEnvironmentBlock` automatically.
    /// - Uses `CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS` (plus `CREATE_UNICODE_ENVIRONMENT`
    ///   which is always added by the wrapper).
    ///
    /// Returns the process exit code.
    #[allow(clippy::cast_possible_wrap)]
    fn create_process_and_wait(token: &Token, command: &[String], session_id: u32) -> anyhow::Result<i32> {
        let cmd_line = CommandLine::new(command.to_vec());

        tracing::debug!(
            command_line = %command.join(" "),
            session_id,
            "Building process creation parameters"
        );

        // Resolve the executable using the user's environment PATH.
        // CreateProcessAsUserW searches the CALLING process's PATH (SYSTEM) to find the
        // executable, not the child's environment block. Since tools like winget.exe live
        // in per-user directories (e.g. %LOCALAPPDATA%\Microsoft\WindowsApps), we must
        // resolve the full path ourselves using the user's environment.
        let user_env = utils::environment_block(Some(token), false).context("failed to load user environment block")?;

        let exe_name = command.first().context("empty command")?;
        let resolved_exe = resolve_executable(exe_name, &user_env).with_context(|| {
            format!(
                "could not find '{}' in user's PATH: {:?}",
                exe_name,
                user_env.get("Path").or_else(|| user_env.get("PATH"))
            )
        })?;

        tracing::info!(
            exe = %resolved_exe.display(),
            "Resolved executable path from user environment"
        );

        // Desktop string: enables the process to interact with the interactive desktop.
        // Required for GUI installers and many silent installers that create windows.
        let mut startup_info = StartupInfo {
            desktop: WideString::from("WinSta0\\Default"),
            ..Default::default()
        };

        let creation_flags = CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS;

        tracing::debug!("Calling process::create_process_as_user");

        let process_info = match process::create_process_as_user(
            Some(token),
            Some(&resolved_exe),
            Some(&cmd_line),
            None,
            None,
            false,
            creation_flags,
            Some(&user_env),
            None,
            &mut startup_info,
        ) {
            Ok(info) => info,
            Err(error) => {
                tracing::error!(
                    error = format!("{error:#}"),
                    command_line = %command.join(" "),
                    exe = %resolved_exe.display(),
                    session_id,
                    "create_process_as_user failed"
                );
                return Err(error).with_context(|| {
                    format!(
                        "CreateProcessAsUserW failed for '{}' (session {})",
                        resolved_exe.display(),
                        session_id
                    )
                });
            }
        };

        tracing::info!(
            session_id,
            pid = process_info.process_id,
            "Process spawned, waiting for exit"
        );

        // Wait for the process to exit (no timeout).
        process_info.process.wait(None).context("failed to wait for process")?;

        let exit_code = process_info
            .process
            .exit_code()
            .context("failed to get process exit code")?;

        Ok(exit_code as i32)
    }

    /// Resolve an executable name to its full path using the given environment's PATH.
    ///
    /// Handles both absolute paths and bare names (e.g., `winget.exe`).
    /// Appends `.exe` if no extension is present and the file is not found as-is.
    fn resolve_executable(exe_name: &str, env: &std::collections::HashMap<String, String>) -> anyhow::Result<PathBuf> {
        let exe_path = Path::new(exe_name);

        // If already an absolute path, just verify it exists.
        if exe_path.is_absolute() {
            if exe_path.exists() {
                return Ok(exe_path.to_owned());
            }
            bail!("executable not found at absolute path: {}", exe_path.display());
        }

        // Get PATH from environment (case-insensitive key lookup).
        let path_var = env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
            .map(|(_, v)| v.as_str())
            .unwrap_or_default();

        let extensions: &[&str] = if exe_path.extension().is_some() {
            &[""]
        } else {
            &["", ".exe", ".cmd", ".bat", ".com"]
        };

        for dir in path_var.split(';') {
            let dir = dir.trim();
            if dir.is_empty() {
                continue;
            }
            for ext in extensions {
                let mut candidate = PathBuf::from(dir);
                let file_name = format!("{}{}", exe_name, ext);
                candidate.push(&file_name);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }

        bail!("executable '{}' not found in PATH", exe_name);
    }
}

#[cfg(windows)]
pub use win::WindowsExecutor;
