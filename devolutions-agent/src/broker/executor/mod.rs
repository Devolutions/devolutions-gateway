//! Command execution module.
//!
//! Handles running commands under the specified user identity.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use now_policy_api::{Elevation, ManagerName, Scope};
use tokio_util::sync::CancellationToken;
use tracing::info;
use win_api_wrappers::identity::sid::Sid;

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
    ///
    /// SECURITY: this is a raw command string whose content is not governed by the
    /// policy yet, so it is only accepted for non-elevated execution. The broker
    /// server rejects requests carrying pre/post operation commands when the
    /// execution token would be elevated (see `BrokerState::evaluate_request`),
    /// and the executor refuses such plans as defense in depth.
    pub pre_command: Option<String>,
    /// The main package-manager command line as separate arguments (exe + args).
    pub command: Vec<String>,
    /// Optional shell command to run after the main command (`cmd.exe /S /C`).
    ///
    /// SECURITY: same restrictions as `pre_command`.
    pub post_command: Option<String>,
    /// Windows identity of the target user (e.g., `DOMAIN\username`), used for display and logging.
    pub effective_user: String,
    /// Security identifier of the target user, captured from the authenticated pipe client.
    ///
    /// Session selection uses this SID so distinct accounts sharing the same name
    /// (e.g. `MACHINE\alice` vs `DOMAIN\alice`) cannot be confused with one another.
    pub user_sid: Sid,
    /// Requested elevation level.
    pub elevation: Elevation,
    /// Installation scope (machine scope requires elevation).
    pub scope: Option<Scope>,
    /// When true, capture the main command's combined stdout+stderr.
    ///
    /// Since API v0.3 this only controls whether output frames are pushed on the
    /// per-operation event channel; output is no longer returned in status responses.
    pub capture_output: bool,
    /// Fired when the client requests cancellation of the operation.
    ///
    /// The executor terminates the in-flight process (gracefully first, forcefully
    /// after a grace period) and reports the cancellation through an error chain
    /// containing [`OperationCanceled`].
    pub cancel_token: CancellationToken,
}

/// Marker error reported by executors when an operation was terminated because its
/// cancellation was requested through [`ExecutionContext::cancel_token`].
#[derive(Debug)]
pub struct OperationCanceled;

impl core::fmt::Display for OperationCanceled {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "operation was canceled at the client's request")
    }
}

impl core::error::Error for OperationCanceled {}

/// Whether an executor error chain denotes a client-requested cancellation.
pub fn is_canceled_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<OperationCanceled>())
}

pub type ProcessStartedCallback = std::sync::Arc<dyn Fn(DateTime<Utc>) + Send + Sync>;

/// All package managers the broker knows how to drive.
pub const BROKER_SUPPORTED_MANAGERS: [ManagerName; 11] = [
    ManagerName::Winget,
    ManagerName::Chocolatey,
    ManagerName::Bun,
    ManagerName::Cargo,
    ManagerName::Dotnet,
    ManagerName::Pip,
    ManagerName::Npm,
    ManagerName::PowerShell,
    ManagerName::PowerShell7,
    ManagerName::Scoop,
    ManagerName::Vcpkg,
];

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

    /// Probe which package managers are actually available for the target user.
    ///
    /// The default implementation reports no managers at all: availability must be
    /// positively established by a platform executor, which overrides this to resolve
    /// each manager executable using the same logic the execution path uses.
    async fn probe_managers(&self, user_sid: &Sid) -> Vec<ManagerName> {
        let _ = user_sid;
        Vec::new()
    }
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
            user_sid = %ctx.user_sid,
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
