//! Devolutions Agent Windows Event Log event definitions.
//!
//! The Agent message catalog holds exactly the codes declared here, so the Agent never ships a
//! message it cannot emit.

use std::path::Path;

use sysevent::{Entry, Severity};

// 1000-1099 **Service/Lifecycle**

/// Fired after the Agent service started.
pub const SERVICE_STARTED: u32 = 1000;
/// Graceful stop received.
pub const SERVICE_STOPPING: u32 = 1001;
/// Failed to init config.
pub const CONFIG_INVALID: u32 = 1010;
/// Top-level start failure (often transient).
pub const START_FAILED: u32 = 1020;
/// A boot crash trace was persisted.
pub const BOOT_STACKTRACE_WRITTEN: u32 = 1030;

pub fn service_started(version: impl ToString) -> Entry {
    Entry::new("Service started")
        .event_code(SERVICE_STARTED)
        .severity(Severity::Info)
        .field("version", version)
}

pub fn service_stopping(reason: impl ToString) -> Entry {
    Entry::new("Service stopping")
        .event_code(SERVICE_STOPPING)
        .severity(Severity::Info)
        .field("reason", reason)
}

pub fn config_invalid(error: impl std::fmt::Display, path: impl AsRef<Path>) -> Entry {
    Entry::new("Configuration invalid")
        .event_code(CONFIG_INVALID)
        .severity(Severity::Critical)
        .field("path", path.as_ref().display())
        .field("error_chain", format!("{error:#}"))
        .field("reason_code", "invalid_config")
}

pub fn start_failed(error: impl std::fmt::Display, cause: impl ToString) -> Entry {
    Entry::new("Start failed")
        .event_code(START_FAILED)
        .severity(Severity::Error)
        .field("cause", cause) // e.g. "bind", "dependency", "tls", "io"
        .field("error_chain", format!("{error:#}"))
}

pub fn boot_stacktrace_written(path: &Path) -> Entry {
    Entry::new("Boot stacktrace written")
        .event_code(BOOT_STACKTRACE_WRITTEN)
        .severity(Severity::Warning)
        .field("path", path.display())
}

// 6000-6009 **User Sessions**

/// `DevolutionsSession.exe` started in session; include session id & kind (console/remote).
pub const USER_SESSION_PROCESS_STARTED: u32 = 6000;
/// Exit code; who triggered.
pub const USER_SESSION_PROCESS_TERMINATED: u32 = 6001;

pub fn user_session_process_started(session_id: u32, kind: impl ToString, exe: impl ToString) -> Entry {
    Entry::new("User session process started")
        .event_code(USER_SESSION_PROCESS_STARTED)
        .severity(Severity::Info)
        .field("session_id", session_id)
        .field("kind", kind) // "console","remote"
        .field("exe", exe)
}

pub fn user_session_process_terminated(session_id: u32, exit_code: i32, by: impl ToString) -> Entry {
    Entry::new("User session process terminated")
        .event_code(USER_SESSION_PROCESS_TERMINATED)
        .severity(Severity::Info)
        .field("session_id", session_id)
        .field("exit_code", exit_code)
        .field("by", by) // "user","service","timeout"
}

// 6100-6199 **Updater**

pub const UPDATER_TASK_ENABLED: u32 = 6100;
pub const UPDATER_ERROR: u32 = 6101;

pub fn updater_task_enabled() -> Entry {
    Entry::new("Updater task enabled")
        .event_code(UPDATER_TASK_ENABLED)
        .severity(Severity::Info)
}

pub fn updater_error(step: impl ToString, error: impl std::fmt::Display) -> Entry {
    Entry::new("Updater error")
        .event_code(UPDATER_ERROR)
        .severity(Severity::Error)
        .field("step", step) // "download","verify","apply","rollback"
        .field("error_chain", format!("{error:#}"))
}

// 6200-6299 **PEDM**

pub const PEDM_ENABLED: u32 = 6200;

pub fn pedm_enabled() -> Entry {
    Entry::new("PEDM enabled")
        .event_code(PEDM_ENABLED)
        .severity(Severity::Info)
}

// 8000-8099 **Package Broker / Policy Management**

pub const POLICY_WRITE_ATTEMPTED: u32 = 8000;
pub const POLICY_WRITE_DENIED: u32 = 8001;
pub const POLICY_CREATE_FAILED: u32 = 8002;
pub const POLICY_CREATE_SUCCEEDED: u32 = 8003;
pub const POLICY_CHANGE_FAILED: u32 = 8004;
pub const POLICY_CHANGE_SUCCEEDED: u32 = 8005;
pub const POLICY_EXTERNAL_CHANGE_APPLIED: u32 = 8010;
pub const POLICY_EXTERNAL_CHANGE_REJECTED: u32 = 8011;

pub fn policy_write_attempted(
    actor_sid: impl ToString,
    actor_exe: impl ToString,
    intent: impl ToString,
    path: &Path,
) -> Entry {
    Entry::new("Policy management write attempted")
        .event_code(POLICY_WRITE_ATTEMPTED)
        .severity(Severity::Info)
        .field("actor_sid", actor_sid)
        .field("actor_exe", actor_exe)
        .field("intent", intent)
        .field("path", path.display())
}

pub fn policy_write_denied(
    actor_sid: impl ToString,
    actor_exe: impl ToString,
    intent: impl ToString,
    path: &Path,
    reason: impl ToString,
) -> Entry {
    Entry::new("Policy management write denied")
        .event_code(POLICY_WRITE_DENIED)
        .severity(Severity::Warning)
        .field("actor_sid", actor_sid)
        .field("actor_exe", actor_exe)
        .field("intent", intent)
        .field("path", path.display())
        .field("reason", reason)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the shared builder keeps the Create and change failure events field-compatible"
)]
pub fn policy_write_failed(
    event_code: u32,
    message: &'static str,
    actor_sid: impl ToString,
    actor_exe: impl ToString,
    intent: impl ToString,
    path: impl AsRef<Path>,
    operation: impl ToString,
    outcome: impl ToString,
    reason: impl ToString,
) -> Entry {
    Entry::new(message)
        .event_code(event_code)
        .severity(Severity::Error)
        .field("actor_sid", actor_sid)
        .field("actor_exe", actor_exe)
        .field("intent", intent)
        .field("path", path.as_ref().display())
        .field("operation", operation)
        .field("outcome", outcome)
        .field("reason", reason)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the audit event records both policy identities and the operation outcome"
)]
pub fn policy_write_succeeded(
    event_code: u32,
    message: &'static str,
    actor_sid: impl ToString,
    actor_exe: impl ToString,
    path: impl AsRef<Path>,
    old_id: impl ToString,
    old_revision: impl ToString,
    new_id: impl ToString,
    new_revision: u32,
    intent: impl ToString,
    operation: impl ToString,
    outcome: impl ToString,
) -> Entry {
    Entry::new(message)
        .event_code(event_code)
        .severity(Severity::Info)
        .field("actor_sid", actor_sid)
        .field("actor_exe", actor_exe)
        .field("path", path.as_ref().display())
        .field("old_id", old_id)
        .field("old_revision", old_revision)
        .field("new_id", new_id)
        .field("new_revision", new_revision)
        .field("intent", intent)
        .field("operation", operation)
        .field("outcome", outcome)
}

pub fn policy_external_change_applied(path: impl AsRef<Path>, new_id: impl ToString, new_revision: u32) -> Entry {
    Entry::new("External policy change applied")
        .event_code(POLICY_EXTERNAL_CHANGE_APPLIED)
        .severity(Severity::Notice)
        .field("path", path.as_ref().display())
        .field("new_id", new_id)
        .field("new_revision", new_revision)
}

pub fn policy_external_change_rejected(path: impl AsRef<Path>, reason: impl ToString) -> Entry {
    Entry::new("External policy change rejected")
        .event_code(POLICY_EXTERNAL_CHANGE_REJECTED)
        .severity(Severity::Warning)
        .field("path", path.as_ref().display())
        .field("reason", reason)
}

/// Every declared Agent event code, paired with its symbolic name.
///
/// `devolutions-agent.mc` is checked against this inventory, and the check is an exact match in
/// both directions, so adding a code here means adding its messages to the catalog, and a code
/// this crate does not declare must never appear there.
pub static DECLARED_CODES: &[(&str, u32)] = &[
    ("SERVICE_STARTED", SERVICE_STARTED),
    ("SERVICE_STOPPING", SERVICE_STOPPING),
    ("CONFIG_INVALID", CONFIG_INVALID),
    ("START_FAILED", START_FAILED),
    ("BOOT_STACKTRACE_WRITTEN", BOOT_STACKTRACE_WRITTEN),
    ("USER_SESSION_PROCESS_STARTED", USER_SESSION_PROCESS_STARTED),
    ("USER_SESSION_PROCESS_TERMINATED", USER_SESSION_PROCESS_TERMINATED),
    ("UPDATER_TASK_ENABLED", UPDATER_TASK_ENABLED),
    ("UPDATER_ERROR", UPDATER_ERROR),
    ("PEDM_ENABLED", PEDM_ENABLED),
    ("POLICY_WRITE_ATTEMPTED", POLICY_WRITE_ATTEMPTED),
    ("POLICY_WRITE_DENIED", POLICY_WRITE_DENIED),
    ("POLICY_CREATE_FAILED", POLICY_CREATE_FAILED),
    ("POLICY_CREATE_SUCCEEDED", POLICY_CREATE_SUCCEEDED),
    ("POLICY_CHANGE_FAILED", POLICY_CHANGE_FAILED),
    ("POLICY_CHANGE_SUCCEEDED", POLICY_CHANGE_SUCCEEDED),
    ("POLICY_EXTERNAL_CHANGE_APPLIED", POLICY_EXTERNAL_CHANGE_APPLIED),
    ("POLICY_EXTERNAL_CHANGE_REJECTED", POLICY_EXTERNAL_CHANGE_REJECTED),
];
