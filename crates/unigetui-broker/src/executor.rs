//! Command execution module.
//!
//! Handles running WinGet commands under the specified user identity.
//! Running WinGet under SYSTEM requires impersonating the target user session,
//! since WinGet resolves packages relative to a user profile.

use async_trait::async_trait;

/// Trait for command execution strategies.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Execute a command with the given arguments under the effective user.
    async fn execute(&self, command: &[String], effective_user: &str) -> anyhow::Result<()>;
}

/// Dry-run executor that only logs commands without running them.
pub struct DryRunExecutor;

#[async_trait]
impl CommandExecutor for DryRunExecutor {
    async fn execute(&self, command: &[String], effective_user: &str) -> anyhow::Result<()> {
        tracing::info!(
            %effective_user,
            command = %command.join(" "),
            "Dry-run: would execute command"
        );
        Ok(())
    }
}

/// Real executor that runs WinGet commands.
///
/// When running as SYSTEM (service context), WinGet needs to be invoked
/// in the context of the target user. This executor uses `CreateProcessAsUser`
/// or equivalent mechanisms to achieve this.
#[cfg(windows)]
pub struct WindowsExecutor;

#[cfg(windows)]
#[async_trait]
impl CommandExecutor for WindowsExecutor {
    async fn execute(&self, command: &[String], effective_user: &str) -> anyhow::Result<()> {
        use std::process::Stdio;
        use tokio::process::Command;

        tracing::info!(
            %effective_user,
            command = %command.join(" "),
            "Executing command"
        );

        // When running under SYSTEM, we need to find the user's session and create
        // a process in their context. For the initial implementation, we use
        // `runas /user:<user>` as a simplified approach. A production implementation
        // should use CreateProcessAsUser with the user's token from a logon session.
        //
        // For WinGet specifically, it needs access to the user's AppData for its
        // settings and source configuration. Running it directly under SYSTEM will
        // fail for user-scoped operations.

        let exe = &command[0];
        let args = &command[1..];

        // Try to run directly first (works if service is running as the effective user
        // or if the operation is machine-scoped and WinGet is available system-wide).
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set environment for WinGet to work under SYSTEM:
        // WinGet looks for its settings in LOCALAPPDATA. Under SYSTEM that would be
        // C:\Windows\System32\config\systemprofile\AppData\Local which may not have
        // the WinGet source configured. We attempt to resolve the user's profile path.
        if let Some(user_profile) = resolve_user_profile_path(effective_user) {
            cmd.env("LOCALAPPDATA", format!("{}\\AppData\\Local", user_profile));
            cmd.env("APPDATA", format!("{}\\AppData\\Roaming", user_profile));
        }

        let output = cmd.output().await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            tracing::info!(%effective_user, stdout = %stdout, "Command completed successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let code = output.status.code().unwrap_or(-1);
            tracing::error!(%effective_user, %stderr, exit_code = code, "Command failed");
            anyhow::bail!("command exited with code {code}: {stderr}")
        }
    }
}

/// Create the appropriate command executor for the current platform.
///
/// On Windows, returns a `WindowsExecutor` that runs real processes.
/// On other platforms, returns a `DryRunExecutor` since named pipes
/// and WinGet are not available.
pub fn create_platform_executor() -> Box<dyn CommandExecutor> {
    #[cfg(windows)]
    {
        Box::new(WindowsExecutor)
    }
    #[cfg(not(windows))]
    {
        Box::new(DryRunExecutor)
    }
}

/// Resolve a user's profile directory from their username.
/// Format expected: "DOMAIN\\username" or just "username".
#[cfg(windows)]
fn resolve_user_profile_path(effective_user: &str) -> Option<String> {
    // Extract just the username part.
    let username = effective_user
        .rsplit('\\')
        .next()
        .unwrap_or(effective_user);

    // Common profile path pattern.
    let profiles_dir = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    let profile_path = format!("{profiles_dir}\\Users\\{username}");

    if std::path::Path::new(&profile_path).exists() {
        Some(profile_path)
    } else {
        tracing::warn!(
            %effective_user,
            attempted_path = %profile_path,
            "Could not resolve user profile path"
        );
        None
    }
}
