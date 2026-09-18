//! Devolutions Agent-specific Windows Event Log event definitions.

use std::path::Path;

use sysevent::{Entry, Severity};

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
