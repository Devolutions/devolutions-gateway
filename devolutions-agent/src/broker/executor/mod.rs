//! Command execution module.
//!
//! Handles running commands under the specified user identity.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use now_policy_api::{Elevation, Scope};
use tracing::info;

mod output;

#[cfg(windows)]
mod windows;

pub use output::{ExecutionOutput, MAX_CAPTURED_OUTPUT_BYTES, describe_exit_code, tail_utf8};
#[cfg(windows)]
pub use windows::WindowsExecutor;

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
    /// When true, capture the main command's combined stdout+stderr.
    pub capture_output: bool,
}

pub type ProcessStartedCallback = std::sync::Arc<dyn Fn(DateTime<Utc>) + Send + Sync>;

/// Trait for command execution strategies.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Execute a command under the given context.
    ///
    /// Returns the main command's exit code and captured output on success.
    /// The method blocks (async) until the spawned process exits or a fatal error occurs during launch.
    async fn execute(
        &self,
        ctx: &ExecutionContext,
        process_started: Option<ProcessStartedCallback>,
    ) -> anyhow::Result<ExecutionOutput>;
}

/// Dry-run executor that only logs commands without running them.
pub struct DryRunExecutor;

#[async_trait]
impl CommandExecutor for DryRunExecutor {
    async fn execute(
        &self,
        ctx: &ExecutionContext,
        _process_started: Option<ProcessStartedCallback>,
    ) -> anyhow::Result<ExecutionOutput> {
        info!(
            effective_user = %ctx.effective_user,
            kill_processes = ?ctx.kill_processes,
            has_pre_command = ctx.pre_command.is_some(),
            command_len = ctx.command.len(),
            has_post_command = ctx.post_command.is_some(),
            elevation = %ctx.elevation,
            "Dry-run: would execute plan"
        );
        Ok(ExecutionOutput::default())
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
