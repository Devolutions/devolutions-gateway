//! Structured audit logging for policy management writes.
//!
//! Every attempt, denial, conflict, confirmed overwrite, failure, and success is recorded
//! twice: once as a structured `tracing` event (for local diagnostics and log
//! aggregation) and once to the platform system event log via [`sysevent`] (a
//! tamper-evident, centrally collectible security audit trail). Entries carry actor
//! SID/executable, intent, path, and old/new policy id/revision, but never full policy
//! content.

use std::path::Path;
use std::sync::Arc;

use sysevent::SystemEventSink;
use win_api_wrappers::identity::sid::Sid;

/// Lazily-initialized Windows Event Log sink for policy management audit events.
///
/// Mirrors `devolutions_gateway::SYSTEM_LOGGER`, which the Agent does not otherwise have
/// an equivalent of; the package broker owns this one since it is the only Agent
/// subsystem that currently needs security-audit event log entries.
static SYSTEM_LOGGER: std::sync::LazyLock<Arc<dyn SystemEventSink>> = std::sync::LazyLock::new(init_system_logger);

fn init_system_logger() -> Arc<dyn SystemEventSink> {
    match sysevent_winevent::WinEvent::new("Devolutions Agent") {
        Ok(winevent) => Arc::new(winevent),
        Err(error) => {
            // Explicitly traced before falling back: an operator relying on the Windows
            // Event Log audit trail needs to know it is not being written to. The Noop
            // fallback exists precisely so this initialization failure never blocks
            // policy writes themselves.
            tracing::error!(
                %error,
                "Failed to initialize the Windows Event Log sink for policy management audit events; \
                 falling back to a no-op sink (policy writes are not blocked)"
            );
            Arc::new(sysevent::NoopSink)
        }
    }
}

fn emit(entry: sysevent::Entry) {
    if let Err(error) = SYSTEM_LOGGER.emit(entry) {
        tracing::warn!(%error, "Failed to emit policy management audit event to the system event log");
    }
}

pub(crate) fn write_attempted(actor_sid: &Sid, actor_exe: &Path, intent: &str, path: &Path) {
    tracing::info!(
        actor_sid = %actor_sid,
        actor_exe = %actor_exe.display(),
        intent,
        path = %path.display(),
        "Policy management write attempted"
    );
    emit(sysevent_codes::policy_write_attempted(
        actor_sid.to_string(),
        actor_exe.display().to_string(),
        intent,
        path,
    ));
}

pub(crate) fn write_denied(actor_sid: &Sid, actor_exe: &Path, intent: &str, path: &Path, reason: &str) {
    tracing::warn!(
        actor_sid = %actor_sid,
        actor_exe = %actor_exe.display(),
        intent,
        path = %path.display(),
        reason,
        "Policy management write denied"
    );
    emit(sysevent_codes::policy_write_denied(
        actor_sid.to_string(),
        actor_exe.display().to_string(),
        intent,
        path,
        reason,
    ));
}

pub(crate) fn write_conflict(actor_sid: &Sid, actor_exe: &Path, intent: &str, path: &Path) {
    tracing::info!(
        actor_sid = %actor_sid,
        actor_exe = %actor_exe.display(),
        intent,
        path = %path.display(),
        "Policy management write conflict: expected store token no longer matches"
    );
    emit(sysevent_codes::policy_write_conflict(
        actor_sid.to_string(),
        actor_exe.display().to_string(),
        intent,
        path,
    ));
}

pub(crate) fn write_failed(actor_sid: &Sid, actor_exe: &Path, intent: &str, path: &Path, reason: &str) {
    tracing::error!(
        actor_sid = %actor_sid,
        actor_exe = %actor_exe.display(),
        intent,
        path = %path.display(),
        reason,
        "Policy management write failed"
    );
    emit(sysevent_codes::policy_write_failed(
        actor_sid.to_string(),
        actor_exe.display().to_string(),
        intent,
        path,
        reason,
    ));
}

#[expect(
    clippy::too_many_arguments,
    reason = "audit event needs the full old/new identity for a security trail"
)]
pub(crate) fn write_succeeded(
    actor_sid: &Sid,
    actor_exe: &Path,
    intent: &str,
    path: &Path,
    old_id: &str,
    old_revision: Option<u32>,
    new_id: &str,
    new_revision: u32,
) {
    let old_revision_display = old_revision.map_or_else(|| "none".to_owned(), |revision| revision.to_string());
    tracing::info!(
        actor_sid = %actor_sid,
        actor_exe = %actor_exe.display(),
        intent,
        path = %path.display(),
        old_id,
        old_revision = old_revision_display,
        new_id,
        new_revision,
        "Policy management write succeeded"
    );
    emit(sysevent_codes::policy_write_succeeded(
        actor_sid.to_string(),
        actor_exe.display().to_string(),
        path,
        old_id,
        old_revision_display,
        new_id,
        new_revision,
        intent,
    ));
}

#[expect(
    clippy::too_many_arguments,
    reason = "audit event needs the full old/new identity for a security trail"
)]
pub(crate) fn write_confirmed_overwrite(
    actor_sid: &Sid,
    actor_exe: &Path,
    intent: &str,
    path: &Path,
    old_id: &str,
    old_revision: Option<u32>,
    new_id: &str,
    new_revision: u32,
) {
    let old_revision_display = old_revision.map_or_else(|| "none".to_owned(), |revision| revision.to_string());
    tracing::warn!(
        actor_sid = %actor_sid,
        actor_exe = %actor_exe.display(),
        intent,
        path = %path.display(),
        old_id,
        old_revision = old_revision_display,
        new_id,
        new_revision,
        "Policy management confirmed overwrite"
    );
    emit(sysevent_codes::policy_write_confirmed_overwrite(
        actor_sid.to_string(),
        actor_exe.display().to_string(),
        path,
        old_id,
        old_revision_display,
        new_id,
        new_revision,
        intent,
    ));
}

pub(crate) fn external_change_applied(path: &Path, new_id: &str, new_revision: u32) {
    tracing::info!(path = %path.display(), new_id, new_revision, "External policy change applied");
    emit(sysevent_codes::policy_external_change_applied(
        path,
        new_id,
        new_revision,
    ));
}

pub(crate) fn external_change_rejected(path: &Path, reason: &str) {
    tracing::warn!(path = %path.display(), reason, "External policy change rejected");
    emit(sysevent_codes::policy_external_change_rejected(path, reason));
}
