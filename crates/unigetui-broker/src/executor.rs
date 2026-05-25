//! Command execution module.
//!
//! Handles running WinGet commands under the specified user identity.
//!
//! When the broker runs as SYSTEM (production service context), the executor:
//! 1. Enumerates sessions to find the target user's logon session.
//! 2. Obtains and duplicates their token.
//! 3. Optionally creates an elevated token (linked token) for `elevated` mode.
//! 4. Creates a process with `CreateProcessAsUserW` under that token.
//!
//! When running as a normal user (development/debug), the executor:
//! - Runs commands directly under the current process identity.
//! - Rejects `elevated` / `runAsAdministrator` requests (cannot elevate without SYSTEM).

use async_trait::async_trait;

use crate::models::Elevation;

/// Execution context passed from the server to the executor.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// The command line as separate arguments (exe + args).
    pub command: Vec<String>,
    /// Windows identity of the target user (e.g., `DOMAIN\username`).
    pub effective_user: String,
    /// Requested elevation level.
    pub elevation: Elevation,
    /// Whether the client requested `runAsAdministrator` in options.
    pub run_as_administrator: bool,
}

/// Trait for command execution strategies.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Execute a command under the given context.
    async fn execute(&self, ctx: &ExecutionContext) -> anyhow::Result<()>;
}

/// Dry-run executor that only logs commands without running them.
pub struct DryRunExecutor;

#[async_trait]
impl CommandExecutor for DryRunExecutor {
    async fn execute(&self, ctx: &ExecutionContext) -> anyhow::Result<()> {
        tracing::info!(
            effective_user = %ctx.effective_user,
            command = %ctx.command.join(" "),
            elevation = %ctx.elevation,
            run_as_administrator = ctx.run_as_administrator,
            "Dry-run: would execute command"
        );
        Ok(())
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
// SAFETY: This module implements Win32 security token manipulation for process creation.
// All unsafe blocks call documented Win32 APIs with validated parameters.
// Handle lifetime is managed by SafeHandle (RAII). Memory is freed via WTSFreeMemory/LocalFree.
#[allow(clippy::multiple_unsafe_ops_per_block)]
mod win {
    use std::ptr;

    use anyhow::{Context as _, bail};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{
        DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_ELEVATION_TYPE,
        TOKEN_LINKED_TOKEN, TOKEN_QUERY, TOKEN_USER, TokenElevationType, TokenElevationTypeFull,
        TokenElevationTypeLimited, TokenLinkedToken, TokenSessionId, TokenUser,
    };
    use windows::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory,
        WTSQuerySessionInformationW, WTSUserName,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
        STARTUPINFOW,
    };
    use windows::core::{PWSTR, w};

    use super::*;

    /// RAII wrapper for Win32 handles.
    struct SafeHandle(HANDLE);

    impl SafeHandle {
        fn new(h: HANDLE) -> Self {
            Self(h)
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for SafeHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: Handle is valid and owned by this wrapper.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    /// Windows command executor using raw Win32 APIs.
    ///
    /// Detects whether it runs as SYSTEM (service mode) or as a normal user (dev mode).
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
        async fn execute(&self, ctx: &ExecutionContext) -> anyhow::Result<()> {
            let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.run_as_administrator;

            if !self.is_system && requires_elevation {
                bail!(
                    "elevated execution requested but broker is not running as SYSTEM; \
                     elevation is only supported in service mode"
                );
            }

            if self.is_system {
                execute_as_system(ctx).await
            } else {
                execute_as_current_user(ctx).await
            }
        }
    }

    /// Detect whether the current process is running under the SYSTEM account.
    ///
    /// Compares the process token SID against S-1-5-18 (LocalSystem).
    #[allow(clippy::cast_possible_truncation)]
    fn detect_running_as_system() -> bool {
        // SAFETY: All Win32 calls use valid handles and buffers allocated with sufficient size.
        // SafeHandle ensures token is closed on all paths. LocalFree releases the SID memory.
        unsafe {
            let process = GetCurrentProcess();
            let mut token = HANDLE::default();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let token = SafeHandle::new(token);

            let mut buf = vec![0u8; 256];
            let mut returned = 0u32;
            if GetTokenInformation(
                token.raw(),
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                buf.len() as u32,
                &mut returned,
            )
            .is_err()
            {
                return false;
            }

            let token_user: &TOKEN_USER = &*(buf.as_ptr().cast());
            let user_sid = token_user.User.Sid;

            // Compare against the well-known SYSTEM SID (S-1-5-18).
            let mut system_sid = windows::Win32::Security::PSID::default();
            if ConvertStringSidToSidW(w!("S-1-5-18"), &mut system_sid).is_err() {
                return false;
            }

            let equal = windows::Win32::Security::EqualSid(user_sid, system_sid).is_ok();
            let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(system_sid.0)));
            equal
        }
    }

    /// Execute a command in the context of the target user's session (SYSTEM mode).
    ///
    /// Steps:
    /// 1. Find the user's active session via WTS enumeration.
    /// 2. Get the session token.
    /// 3. If elevated execution is requested, obtain the linked elevated token.
    /// 4. Create a process under that token using `CreateProcessAsUserW`.
    async fn execute_as_system(ctx: &ExecutionContext) -> anyhow::Result<()> {
        let effective_user = ctx.effective_user.clone();
        let command = ctx.command.clone();
        let requires_elevation = ctx.elevation == Elevation::Elevated || ctx.run_as_administrator;

        // Blocking Win32 calls — run in a blocking thread.
        tokio::task::spawn_blocking(move || {
            let session_id = find_user_session(&effective_user).context("failed to find active session for user")?;

            tracing::debug!(
                %effective_user,
                session_id,
                "Found user session"
            );

            let user_token = query_user_token(session_id).context("failed to obtain user token for session")?;

            let primary_token = duplicate_token_primary(&user_token).context("failed to duplicate token as primary")?;

            let execution_token = if requires_elevation {
                match get_elevated_token(&primary_token) {
                    Ok(elevated) => {
                        tracing::debug!("Using elevated (linked) token");
                        elevated
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Could not obtain elevated token, using primary");
                        primary_token
                    }
                }
            } else {
                primary_token
            };

            create_process_as_user(&execution_token, &command, session_id).context("CreateProcessAsUserW failed")?;

            tracing::info!(
                %effective_user,
                command = %command.join(" "),
                "Process created successfully under user token"
            );

            Ok(())
        })
        .await
        .context("blocking task panicked")?
    }

    /// Execute a command directly as the current user (development mode).
    ///
    /// Does not impersonate or elevate. Useful for quick testing without a service.
    async fn execute_as_current_user(ctx: &ExecutionContext) -> anyhow::Result<()> {
        use std::process::Stdio;

        use tokio::process::Command;

        tracing::info!(
            effective_user = %ctx.effective_user,
            command = %ctx.command.join(" "),
            "Executing command as current user (dev mode)"
        );

        let exe = &ctx.command[0];
        let args = &ctx.command[1..];

        let output = Command::new(exe)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to spawn process")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            tracing::info!(stdout = %stdout, "Command completed successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let code = output.status.code().unwrap_or(-1);
            tracing::error!(%stderr, exit_code = code, "Command failed");
            bail!("command exited with code {code}: {stderr}")
        }
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

        // SAFETY: WTS functions are called with valid server handle (current server).
        // session_info pointer is freed via WTSFreeMemory. PWSTR lifetime is valid
        // for the duration of string extraction.
        unsafe {
            let mut session_info: *mut WTS_SESSION_INFOW = ptr::null_mut();
            let mut count = 0u32;

            WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut session_info, &mut count)
                .context("WTSEnumerateSessionsW failed")?;

            let sessions = std::slice::from_raw_parts(session_info, count as usize);

            let mut found_session = None;

            for session in sessions {
                if session.SessionId == 0 {
                    continue;
                }

                let mut buf: PWSTR = PWSTR::null();
                let mut bytes_returned = 0u32;

                if WTSQuerySessionInformationW(
                    Some(WTS_CURRENT_SERVER_HANDLE),
                    session.SessionId,
                    WTSUserName,
                    &mut buf,
                    &mut bytes_returned,
                )
                .is_ok()
                    && !buf.is_null()
                {
                    let session_user = buf.to_string().unwrap_or_default().to_lowercase();
                    WTSFreeMemory(buf.as_ptr().cast());

                    if session_user == target_username {
                        found_session = Some(session.SessionId);
                        break;
                    }
                }
            }

            WTSFreeMemory(session_info.cast());

            found_session.ok_or_else(|| anyhow::anyhow!("no active session found for user '{effective_user}'"))
        }
    }

    /// Get the user token for a given session using `WTSQueryUserToken`.
    fn query_user_token(session_id: u32) -> anyhow::Result<SafeHandle> {
        // SAFETY: WTSQueryUserToken writes to a valid HANDLE pointer.
        // Requires SeTcbPrivilege (available to SYSTEM).
        unsafe {
            let mut token = HANDLE::default();
            windows::Win32::System::RemoteDesktop::WTSQueryUserToken(session_id, &mut token)
                .context("WTSQueryUserToken failed (requires SYSTEM privilege)")?;
            Ok(SafeHandle::new(token))
        }
    }

    /// Duplicate a token as a primary token suitable for `CreateProcessAsUserW`.
    fn duplicate_token_primary(source: &SafeHandle) -> anyhow::Result<SafeHandle> {
        // SAFETY: source handle is valid (from SafeHandle). Output handle is wrapped in SafeHandle.
        unsafe {
            let mut dup = HANDLE::default();
            DuplicateTokenEx(
                source.raw(),
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                windows::Win32::Security::TokenPrimary,
                &mut dup,
            )
            .context("DuplicateTokenEx failed")?;
            Ok(SafeHandle::new(dup))
        }
    }

    /// Attempt to obtain an elevated (linked) token from a filtered/limited token.
    ///
    /// On UAC-enabled systems with split tokens, the standard user token has a linked
    /// elevated token. This function retrieves it when elevation is requested.
    #[allow(clippy::cast_possible_truncation)]
    fn get_elevated_token(token: &SafeHandle) -> anyhow::Result<SafeHandle> {
        // SAFETY: GetTokenInformation is called with correctly-sized output buffers.
        // The linked token handle is wrapped in SafeHandle for cleanup.
        unsafe {
            let mut elevation_type: TOKEN_ELEVATION_TYPE = TOKEN_ELEVATION_TYPE(0);
            let mut returned = 0u32;
            GetTokenInformation(
                token.raw(),
                TokenElevationType,
                Some(ptr::addr_of_mut!(elevation_type).cast()),
                size_of::<TOKEN_ELEVATION_TYPE>() as u32,
                &mut returned,
            )
            .context("GetTokenInformation(TokenElevationType) failed")?;

            if elevation_type == TokenElevationTypeFull {
                duplicate_token_primary(token)
            } else if elevation_type == TokenElevationTypeLimited {
                let mut linked = TOKEN_LINKED_TOKEN::default();
                let mut returned = 0u32;
                GetTokenInformation(
                    token.raw(),
                    TokenLinkedToken,
                    Some(ptr::addr_of_mut!(linked).cast()),
                    size_of::<TOKEN_LINKED_TOKEN>() as u32,
                    &mut returned,
                )
                .context("GetTokenInformation(TokenLinkedToken) failed")?;

                let linked_handle = SafeHandle::new(linked.LinkedToken);
                duplicate_token_primary(&linked_handle)
            } else {
                bail!("token elevation type is neither full nor limited; cannot elevate");
            }
        }
    }

    /// Create a process under the given token using `CreateProcessAsUserW`.
    #[allow(clippy::cast_possible_truncation)]
    fn create_process_as_user(token: &SafeHandle, command: &[String], session_id: u32) -> anyhow::Result<()> {
        // SAFETY: Token handle is valid. Command line is null-terminated UTF-16.
        // STARTUPINFOW is initialized with correct cb size. Process/thread handles are closed.
        unsafe {
            let cmd_line = build_command_line(command);
            let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

            let mut desktop: Vec<u16> = "WinSta0\\Default\0".encode_utf16().collect();
            let si = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop.as_mut_ptr()),
                ..Default::default()
            };

            let mut pi = PROCESS_INFORMATION::default();

            // Assign the target session to the token.
            let mut sid = session_id;
            windows::Win32::Security::SetTokenInformation(
                token.raw(),
                TokenSessionId,
                ptr::addr_of_mut!(sid).cast(),
                size_of::<u32>() as u32,
            )
            .context("SetTokenInformation(TokenSessionId) failed")?;

            CreateProcessAsUserW(
                Some(token.raw()),
                None,
                Some(PWSTR(cmd_wide.as_mut_ptr())),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(0),
                None,
                None,
                &si,
                &mut pi,
            )
            .context("CreateProcessAsUserW failed")?;

            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);

            Ok(())
        }
    }

    /// Build a Windows command line string from arguments.
    ///
    /// Follows Windows quoting rules: arguments containing spaces are wrapped in double quotes.
    fn build_command_line(command: &[String]) -> String {
        command
            .iter()
            .map(|arg| {
                if arg.contains(' ') || arg.contains('"') {
                    format!("\"{}\"", arg.replace('"', "\\\""))
                } else {
                    arg.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(windows)]
pub use win::WindowsExecutor;
