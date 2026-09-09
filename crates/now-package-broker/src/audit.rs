//! Structured audit events for policy management writes and external policy changes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(all(not(test), not(debug_assertions)))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};

use now_policy_api::{PolicyManagementState, PolicyReplacementOperation};
#[cfg(not(test))]
use sysevent::Severity;
#[cfg(all(not(test), not(debug_assertions)))]
use sysevent::SystemEventSink;
use win_api_wrappers::identity::sid::Sid;

const INTENT: &str = "PUT /v1/policy";
const MAX_SID_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 1024;
const MAX_POLICY_ID_BYTES: usize = 256;
#[cfg(all(not(test), not(debug_assertions)))]
const EVENT_LOG_QUEUE_CAPACITY: usize = 256;

static RECORDER: std::sync::LazyLock<Arc<dyn AuditRecorder>> = std::sync::LazyLock::new(default_recorder);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DenialReason {
    AuthenticationFailed,
    AdministratorRequired,
    RequestRejected,
}

impl DenialReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "authentication_failed",
            Self::AdministratorRequired => "administrator_required",
            Self::RequestRejected => "request_rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureReason {
    MonitoringUnavailable,
    StaleStoreToken,
    PathNotWritable,
    InvalidPolicy,
    InvalidReceipt,
    WarningsNotAcknowledged,
    RevisionConflict,
    DraftCommitFailed,
    SerializationFailed,
    PersistenceFailed,
    ConditionalPublicationFailed,
    ActivationFailed,
}

impl FailureReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MonitoringUnavailable => "monitoring_unavailable",
            Self::StaleStoreToken => "stale_store_token",
            Self::PathNotWritable => "path_not_writable",
            Self::InvalidPolicy => "invalid_policy",
            Self::InvalidReceipt => "invalid_receipt",
            Self::WarningsNotAcknowledged => "warnings_not_acknowledged",
            Self::RevisionConflict => "revision_conflict",
            Self::DraftCommitFailed => "draft_commit_failed",
            Self::SerializationFailed => "serialization_failed",
            Self::PersistenceFailed => "persistence_failed",
            Self::ConditionalPublicationFailed => "conditional_publication_failed",
            Self::ActivationFailed => "activation_failed",
        }
    }
}

trait AuditRecorder: Send + Sync {
    fn record(&self, entry: sysevent::Entry);
}

fn default_recorder() -> Arc<dyn AuditRecorder> {
    #[cfg(test)]
    {
        Arc::new(TestRecorder)
    }
    #[cfg(all(not(test), debug_assertions))]
    {
        Arc::new(TracingRecorder)
    }
    #[cfg(all(not(test), not(debug_assertions)))]
    {
        match SystemRecorder::new() {
            Ok(recorder) => Arc::new(recorder),
            Err(error) => {
                tracing::error!(%error, "Failed to start the Windows Event Log policy audit worker");
                Arc::new(TracingRecorder)
            }
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static TEST_EVENTS: std::cell::RefCell<Vec<sysevent::Entry>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
struct TestRecorder;

#[cfg(test)]
impl AuditRecorder for TestRecorder {
    fn record(&self, entry: sysevent::Entry) {
        TEST_EVENTS.with(|events| events.borrow_mut().push(entry));
    }
}

#[cfg(test)]
pub(crate) fn take_test_events() -> Vec<sysevent::Entry> {
    TEST_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

#[cfg(not(test))]
struct TracingRecorder;

#[cfg(not(test))]
impl AuditRecorder for TracingRecorder {
    fn record(&self, entry: sysevent::Entry) {
        trace_entry(&entry);
    }
}

#[cfg(all(not(test), not(debug_assertions)))]
struct SystemRecorder {
    sender: std::sync::mpsc::SyncSender<sysevent::Entry>,
    dropped: AtomicU64,
}

#[cfg(all(not(test), not(debug_assertions)))]
impl SystemRecorder {
    fn new() -> std::io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(EVENT_LOG_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("policy-audit-event-log".to_owned())
            .spawn(move || event_log_worker(&receiver))
            .map(|_| Self {
                sender,
                dropped: AtomicU64::new(0),
            })
    }
}

#[cfg(all(not(test), not(debug_assertions)))]
impl AuditRecorder for SystemRecorder {
    fn record(&self, entry: sysevent::Entry) {
        trace_entry(&entry);
        if let Err(error) = self.sender.try_send(entry) {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                tracing::warn!(
                    dropped,
                    error = %match error {
                        std::sync::mpsc::TrySendError::Full(_) => "queue_full",
                        std::sync::mpsc::TrySendError::Disconnected(_) => "worker_disconnected",
                    },
                    "Dropped policy audit Windows Event Log entries"
                );
            }
        }
    }
}

#[cfg(not(test))]
fn trace_entry(entry: &sysevent::Entry) {
    let code = entry.event_code;
    let message = &entry.message;
    let fields = &entry.fields;
    match entry.severity {
        Severity::Critical | Severity::Error => tracing::error!(?code, %message, ?fields, "Policy audit event"),
        Severity::Warning => tracing::warn!(?code, %message, ?fields, "Policy audit event"),
        Severity::Notice | Severity::Info | Severity::Debug => {
            tracing::info!(?code, %message, ?fields, "Policy audit event");
        }
    }
}

#[cfg(all(not(test), not(debug_assertions)))]
fn event_log_worker(receiver: &std::sync::mpsc::Receiver<sysevent::Entry>) {
    let sink: Arc<dyn SystemEventSink> = match sysevent_winevent::WinEvent::new("Devolutions Agent") {
        Ok(event_log) => Arc::new(event_log),
        Err(error) => {
            tracing::error!(%error, "Failed to initialize the Windows Event Log policy audit sink");
            Arc::new(sysevent::NoopSink)
        }
    };
    for entry in receiver {
        if let Err(error) = sink.emit(entry) {
            tracing::warn!(%error, "Failed to emit policy audit event to the Windows Event Log");
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RecordingAudit(parking_lot::Mutex<Vec<sysevent::Entry>>);

#[cfg(test)]
impl RecordingAudit {
    pub(crate) fn events(&self) -> Vec<sysevent::Entry> {
        self.0.lock().clone()
    }
}

#[cfg(test)]
impl AuditRecorder for RecordingAudit {
    fn record(&self, entry: sysevent::Entry) {
        self.0.lock().push(entry);
    }
}

struct WriteAuditState {
    actor_sid: String,
    actor_exe: String,
    path: PathBuf,
    terminal_recorded: AtomicBool,
    recorder: Arc<dyn AuditRecorder>,
}

impl Drop for WriteAuditState {
    fn drop(&mut self) {
        if !self.terminal_recorded.swap(true, Ordering::AcqRel) {
            self.record(sysevent_codes::policy_write_denied(
                &self.actor_sid,
                &self.actor_exe,
                INTENT,
                &self.path,
                DenialReason::RequestRejected.as_str(),
            ));
        }
    }
}

#[derive(Clone)]
pub(crate) struct WriteAudit(Arc<WriteAuditState>);

impl WriteAudit {
    pub(crate) fn begin(actor_sid: &Sid, actor_exe: &Path, path: &Path) -> Self {
        Self::begin_with_recorder(actor_sid, actor_exe, path, Arc::clone(&RECORDER))
    }

    fn begin_with_recorder(actor_sid: &Sid, actor_exe: &Path, path: &Path, recorder: Arc<dyn AuditRecorder>) -> Self {
        let state = Arc::new(WriteAuditState {
            actor_sid: bounded(actor_sid.to_string(), MAX_SID_BYTES),
            actor_exe: bounded(actor_exe.display().to_string(), MAX_PATH_BYTES),
            path: bounded_path(path),
            terminal_recorded: AtomicBool::new(false),
            recorder,
        });
        state.record(sysevent_codes::policy_write_attempted(
            &state.actor_sid,
            &state.actor_exe,
            INTENT,
            &state.path,
        ));
        Self(state)
    }

    #[cfg(test)]
    pub(crate) fn begin_recording(actor_sid: &Sid, actor_exe: &Path, path: &Path) -> (Self, Arc<RecordingAudit>) {
        let recorder = Arc::new(RecordingAudit::default());
        let recorder_sink = Arc::<RecordingAudit>::clone(&recorder);
        let audit = Self::begin_with_recorder(actor_sid, actor_exe, path, recorder_sink);
        (audit, recorder)
    }

    pub(crate) fn denied(&self, reason: DenialReason) {
        self.finish(|state| {
            sysevent_codes::policy_write_denied(
                &state.actor_sid,
                &state.actor_exe,
                INTENT,
                &state.path,
                reason.as_str(),
            )
        });
    }

    pub(crate) fn failed(&self, operation: PolicyReplacementOperation, reason: FailureReason) {
        self.failed_at(operation, &self.0.path, reason);
    }

    pub(crate) fn failed_at(&self, operation: PolicyReplacementOperation, path: &Path, reason: FailureReason) {
        let path = bounded_path(path);
        let operation_name = operation_name(operation);
        let outcome = if reason == FailureReason::StaleStoreToken {
            "stale_conflict"
        } else {
            "failed"
        };
        self.finish(|state| {
            if operation == PolicyReplacementOperation::Create {
                sysevent_codes::policy_create_failed(
                    &state.actor_sid,
                    &state.actor_exe,
                    INTENT,
                    path,
                    operation_name,
                    outcome,
                    reason.as_str(),
                )
            } else {
                sysevent_codes::policy_change_failed(
                    &state.actor_sid,
                    &state.actor_exe,
                    INTENT,
                    path,
                    operation_name,
                    outcome,
                    reason.as_str(),
                )
            }
        });
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the terminal event records operation and both policy identities"
    )]
    pub(crate) fn succeeded_at(
        &self,
        path: &Path,
        old_id: Option<&str>,
        old_revision: Option<u32>,
        new_id: &str,
        new_revision: u32,
        operation: PolicyReplacementOperation,
        confirmed_overwrite: bool,
    ) {
        let path = bounded_path(path);
        let old_id = bounded(old_id.unwrap_or("<none>").to_owned(), MAX_POLICY_ID_BYTES);
        let old_revision = old_revision.map_or_else(|| "none".to_owned(), |revision| revision.to_string());
        let new_id = bounded(new_id.to_owned(), MAX_POLICY_ID_BYTES);
        let operation_name = operation_name(operation);
        let outcome = if confirmed_overwrite {
            "confirmed_overwrite"
        } else {
            "applied"
        };
        self.finish(|state| {
            if operation == PolicyReplacementOperation::Create {
                sysevent_codes::policy_create_succeeded(
                    &state.actor_sid,
                    &state.actor_exe,
                    path,
                    old_id,
                    old_revision,
                    new_id,
                    new_revision,
                    INTENT,
                    operation_name,
                    outcome,
                )
            } else {
                sysevent_codes::policy_change_succeeded(
                    &state.actor_sid,
                    &state.actor_exe,
                    path,
                    old_id,
                    old_revision,
                    new_id,
                    new_revision,
                    INTENT,
                    operation_name,
                    outcome,
                )
            }
        });
    }

    fn finish(&self, entry: impl FnOnce(&WriteAuditState) -> sysevent::Entry) {
        if self
            .0
            .terminal_recorded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.0.record(entry(&self.0));
        }
    }
}

impl WriteAuditState {
    fn record(&self, entry: sysevent::Entry) {
        self.recorder.record(entry);
    }
}

pub(crate) fn external_change_applied(path: &Path, new_id: &str, new_revision: u32) {
    RECORDER.record(sysevent_codes::policy_external_change_applied(
        bounded_path(path),
        bounded(new_id.to_owned(), MAX_POLICY_ID_BYTES),
        new_revision,
    ));
}

pub(crate) fn external_change_rejected(path: &Path, state: PolicyManagementState) {
    let reason = match state {
        PolicyManagementState::Active => "active",
        PolicyManagementState::Missing => "missing",
        PolicyManagementState::Invalid => "invalid",
    };
    RECORDER.record(sysevent_codes::policy_external_change_rejected(
        bounded_path(path),
        reason,
    ));
}

fn bounded(mut value: String, max_bytes: usize) -> String {
    value = value
        .chars()
        .map(|character| if character.is_control() { ' ' } else { character })
        .collect();
    if value.len() <= max_bytes {
        return value;
    }
    const SUFFIX: &str = "...";
    let mut end = max_bytes - SUFFIX.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str(SUFFIX);
    value
}

fn bounded_path(path: &Path) -> PathBuf {
    PathBuf::from(bounded(path.display().to_string(), MAX_PATH_BYTES))
}

const fn operation_name(operation: PolicyReplacementOperation) -> &'static str {
    match operation {
        PolicyReplacementOperation::Create => "create",
        PolicyReplacementOperation::Update => "update",
        PolicyReplacementOperation::Repair => "repair",
        PolicyReplacementOperation::ReplaceIdentity => "replace_identity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_audit() -> (WriteAudit, Arc<RecordingAudit>) {
        let sid = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None).expect("SYSTEM SID");
        WriteAudit::begin_recording(&sid, Path::new(r"C:\client.exe"), Path::new(r"C:\policy.json"))
    }

    #[test]
    fn attempt_precedes_denial_and_only_one_terminal_event_is_recorded() {
        let (audit, recorder) = test_audit();
        audit.denied(DenialReason::AuthenticationFailed);
        audit.failed(PolicyReplacementOperation::Update, FailureReason::InvalidPolicy);
        assert_eq!(
            recorder
                .events()
                .iter()
                .map(|entry| entry.event_code)
                .collect::<Vec<_>>(),
            [
                Some(sysevent_codes::POLICY_WRITE_ATTEMPTED),
                Some(sysevent_codes::POLICY_WRITE_DENIED)
            ]
        );
    }

    #[test]
    fn audit_values_are_bounded_and_fields_are_allowlisted() {
        let sid = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None).expect("SYSTEM SID");
        let long = "é".repeat(MAX_PATH_BYTES);
        let (audit, recorder) = WriteAudit::begin_recording(&sid, Path::new(&long), Path::new(&long));
        audit.succeeded_at(
            Path::new(&long),
            Some(&long),
            Some(1),
            &long,
            2,
            PolicyReplacementOperation::Update,
            false,
        );

        let events = recorder.events();
        let entry = &events[1];
        assert!(entry.fields.iter().all(|(name, value)| {
            matches!(
                name.as_str(),
                "actor_sid"
                    | "actor_exe"
                    | "intent"
                    | "path"
                    | "old_id"
                    | "old_revision"
                    | "new_id"
                    | "new_revision"
                    | "operation"
                    | "outcome"
            ) && value.len() <= MAX_PATH_BYTES
        }));
        for forbidden in ["body", "draft", "policy", "receipt", "store_token"] {
            assert!(!entry.fields.iter().any(|(name, _)| name == forbidden));
        }
    }

    #[test]
    fn terminal_event_codes_follow_the_replacement_operation() {
        for (operation, failure_code, success_code) in [
            (
                PolicyReplacementOperation::Create,
                sysevent_codes::POLICY_CREATE_FAILED,
                sysevent_codes::POLICY_CREATE_SUCCEEDED,
            ),
            (
                PolicyReplacementOperation::Update,
                sysevent_codes::POLICY_CHANGE_FAILED,
                sysevent_codes::POLICY_CHANGE_SUCCEEDED,
            ),
            (
                PolicyReplacementOperation::Repair,
                sysevent_codes::POLICY_CHANGE_FAILED,
                sysevent_codes::POLICY_CHANGE_SUCCEEDED,
            ),
            (
                PolicyReplacementOperation::ReplaceIdentity,
                sysevent_codes::POLICY_CHANGE_FAILED,
                sysevent_codes::POLICY_CHANGE_SUCCEEDED,
            ),
        ] {
            let (failed, failed_recorder) = test_audit();
            failed.failed(operation, FailureReason::StaleStoreToken);
            assert_eq!(failed_recorder.events()[1].event_code, Some(failure_code));

            let (succeeded, succeeded_recorder) = test_audit();
            succeeded.succeeded_at(Path::new(r"C:\policy.json"), None, None, "new", 1, operation, true);
            assert_eq!(succeeded_recorder.events()[1].event_code, Some(success_code));
        }
    }
}
