//! Structured audit events for policy management writes and external policy changes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(all(not(test), not(debug_assertions)))]
use std::sync::atomic::AtomicU64;
#[cfg(any(test, not(debug_assertions)))]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};

use agent_sysevent_codes as policy_events;
use now_policy_api::{PolicyManagementState, PolicyReplacementOperation};
use sysevent::Entry;
#[cfg(not(test))]
use sysevent::Severity;
#[cfg(all(not(test), not(debug_assertions)))]
use sysevent::SystemEventSink;
use win_api_wrappers::identity::sid::Sid;

const INTENT: &str = "PUT /v1/policy";
const MAX_SID_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 1024;
const MAX_POLICY_ID_BYTES: usize = 256;
/// Slots of the Event Log queue kept for terminal outcomes and external changes.
///
/// Only the outcome of an authenticated policy write, which the policy store serializes, and the
/// policy store's own observation of an external change take these slots. Attempts and denials,
/// which an unauthenticated client can produce at will, are refused before reaching them.
#[cfg(any(test, not(debug_assertions)))]
const EVENT_LOG_OUTCOME_RESERVE: usize = 64;

/// Slots of the Event Log queue that write attempts and denials may occupy.
///
/// The write attempt is recorded before the pipe client is authenticated, so a client that never
/// authenticates can produce this class at will. It is the class that yields when the sink
/// saturates.
#[cfg(any(test, not(debug_assertions)))]
const EVENT_LOG_ADMISSION_BUDGET: usize = 256;

/// Capacity of the queue holding every policy audit entry waiting for the Event Log worker.
#[cfg(any(test, not(debug_assertions)))]
const EVENT_LOG_QUEUE_CAPACITY: usize = EVENT_LOG_ADMISSION_BUDGET + EVENT_LOG_OUTCOME_RESERVE;

static RECORDER: std::sync::OnceLock<Arc<dyn AuditRecorder>> = std::sync::OnceLock::new();

/// The process-wide recorder, started on the first policy audit event.
fn recorder() -> &'static Arc<dyn AuditRecorder> {
    RECORDER.get_or_init(default_recorder)
}

/// Stops accepting policy audit events and waits for the ones already accepted to reach the sink.
///
/// The recorder lives in a process-lifetime static, so its worker is otherwise killed with whatever
/// it is still holding when the process exits.
pub(crate) fn drain() {
    if let Some(recorder) = RECORDER.get() {
        recorder.drain();
    }
}

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
            Self::RevisionConflict => "revision_conflict",
            Self::DraftCommitFailed => "draft_commit_failed",
            Self::SerializationFailed => "serialization_failed",
            Self::PersistenceFailed => "persistence_failed",
            Self::ConditionalPublicationFailed => "conditional_publication_failed",
            Self::ActivationFailed => "activation_failed",
        }
    }
}

/// Which class an audit entry belongs to.
///
/// Both classes share one queue, so entries reach the sink in the order they were recorded. The
/// class only decides whether an entry may be refused to keep capacity for the other class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryClass {
    /// A write attempt or a denial. Recorded from unauthenticated requests, so it may be dropped
    /// when the sink saturates.
    Admission,
    /// The terminal outcome of a policy write, or the observation of an external change. It does
    /// not consume the admission budget, so only a full queue or a gone worker can refuse it.
    Outcome,
}

impl EntryClass {
    #[cfg(all(not(test), not(debug_assertions)))]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Outcome => "outcome",
        }
    }
}

/// Why the Event Log queue refused an entry.
#[cfg(any(test, not(debug_assertions)))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueRefusal {
    /// The queue, or the slots this class may occupy, is full.
    Full,
    /// The worker is gone, so nothing can reach the sink anymore.
    Disconnected,
}

#[cfg(all(not(test), not(debug_assertions)))]
impl QueueRefusal {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "queue_full",
            Self::Disconnected => "worker_disconnected",
        }
    }
}

trait AuditRecorder: Send + Sync {
    /// Records one entry of `class`. Admission is best-effort for both classes: an
    /// [`EntryClass::Admission`] entry is refused once admissions fill their budget, and either
    /// class is refused while the shared queue is full or its worker is gone.
    fn record(&self, entry: Entry, class: EntryClass);

    /// Stops accepting entries and waits for the accepted ones to be emitted.
    fn drain(&self) {}
}

fn default_recorder() -> Arc<dyn AuditRecorder> {
    #[cfg(test)]
    {
        Arc::new(tests::TestRecorder)
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

#[cfg(not(test))]
struct TracingRecorder;

#[cfg(not(test))]
impl AuditRecorder for TracingRecorder {
    fn record(&self, entry: Entry, _: EntryClass) {
        trace_entry(&entry);
    }
}

#[cfg(all(not(test), not(debug_assertions)))]
struct SystemRecorder {
    queue: parking_lot::Mutex<EventLogQueue>,
    dropped: AtomicU64,
}

/// The queue and the worker thread that move accepted entries to the Windows Event Log.
///
/// Every entry shares one bounded queue, so entries reach the sink in the order they were recorded
/// and an accepted write's attempt precedes its terminal outcome. Write attempts and denials are
/// refused once they occupy [`EVENT_LOG_ADMISSION_BUDGET`] slots, so a flood of unauthenticated
/// attempts cannot fill the queue and starve outcomes and external changes.
#[cfg(any(test, not(debug_assertions)))]
struct EventLogQueue {
    /// `None` once [`Self::drain`] closed the queue, so no later entry can be accepted.
    sender: Option<std::sync::mpsc::SyncSender<(Entry, EntryClass)>>,
    /// Write attempts and denials still queued, shared with the worker that dequeues them.
    admission_pending: Arc<AtomicUsize>,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[cfg(any(test, not(debug_assertions)))]
impl EventLogQueue {
    fn start(emit: impl FnMut(Entry) + Send + 'static) -> std::io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(EVENT_LOG_QUEUE_CAPACITY);
        let admission_pending = Arc::new(AtomicUsize::new(0));
        let queued = Arc::clone(&admission_pending);
        let worker = std::thread::Builder::new()
            .name("policy-audit-event-log".to_owned())
            .spawn(move || event_log_worker(&receiver, &queued, emit))?;

        Ok(Self {
            sender: Some(sender),
            admission_pending,
            worker: Some(worker),
        })
    }

    /// Queues one entry, unless its class is over budget or the queue is full or closed.
    fn record(&mut self, entry: Entry, class: EntryClass) -> Result<(), QueueRefusal> {
        // The queue is closed after the broker drained it, so nothing can be emitted anymore.
        let Some(sender) = self.sender.as_ref() else {
            return Err(QueueRefusal::Disconnected);
        };
        if class == EntryClass::Admission {
            // Claim the slot before sending, so concurrent attempts cannot overdraw the budget.
            if self.admission_pending.fetch_add(1, Ordering::Relaxed) >= EVENT_LOG_ADMISSION_BUDGET {
                self.admission_pending.fetch_sub(1, Ordering::Relaxed);
                return Err(QueueRefusal::Full);
            }
        }
        match sender.try_send((entry, class)) {
            Ok(()) => Ok(()),
            Err(error) => {
                if class == EntryClass::Admission {
                    // The entry never entered the queue, so its claimed slot is free again.
                    self.admission_pending.fetch_sub(1, Ordering::Relaxed);
                }
                Err(match error {
                    std::sync::mpsc::TrySendError::Full(_) => QueueRefusal::Full,
                    std::sync::mpsc::TrySendError::Disconnected(_) => QueueRefusal::Disconnected,
                })
            }
        }
    }

    fn drain(&mut self) {
        // Dropping the sender ends the worker's iteration as soon as the queue is empty.
        self.sender = None;
        let Some(worker) = self.worker.take() else {
            return;
        };
        if worker.join().is_err() {
            tracing::warn!("The Windows Event Log policy audit worker panicked");
        }
    }
}

#[cfg(all(not(test), not(debug_assertions)))]
impl SystemRecorder {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            queue: parking_lot::Mutex::new(EventLogQueue::start(event_log_emitter())?),
            dropped: AtomicU64::new(0),
        })
    }
}

#[cfg(all(not(test), not(debug_assertions)))]
impl AuditRecorder for SystemRecorder {
    fn record(&self, entry: Entry, class: EntryClass) {
        trace_entry(&entry);
        if let Some(refusal) = self.queue.lock().record(entry, class).err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                tracing::warn!(
                    dropped,
                    class = class.as_str(),
                    error = refusal.as_str(),
                    "Dropped policy audit Windows Event Log entries"
                );
            }
        }
    }

    fn drain(&self) {
        // The lock keeps a concurrent `record` from queueing an entry the closed queue would drop.
        self.queue.lock().drain();
    }
}

#[cfg(not(test))]
fn trace_entry(entry: &Entry) {
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

/// The Windows Event Log sink, wrapped in the closure the worker thread owns.
#[cfg(all(not(test), not(debug_assertions)))]
fn event_log_emitter() -> impl FnMut(Entry) + Send + 'static {
    let sink: Arc<dyn SystemEventSink> = match sysevent_winevent::WinEvent::new("Devolutions Agent") {
        Ok(event_log) => Arc::new(event_log),
        Err(error) => {
            tracing::error!(%error, "Failed to initialize the Windows Event Log policy audit sink");
            Arc::new(sysevent::NoopSink)
        }
    };
    move |entry| {
        if let Err(error) = sink.emit(entry) {
            tracing::warn!(%error, "Failed to emit policy audit event to the Windows Event Log");
        }
    }
}

/// Emits entries in the order they were recorded, until the queue is closed.
#[cfg(any(test, not(debug_assertions)))]
fn event_log_worker(
    receiver: &std::sync::mpsc::Receiver<(Entry, EntryClass)>,
    admission_pending: &AtomicUsize,
    mut emit: impl FnMut(Entry),
) {
    while let Ok((entry, class)) = receiver.recv() {
        if class == EntryClass::Admission {
            // The entry left the queue, so its slot in the admission budget is free again.
            admission_pending.fetch_sub(1, Ordering::Relaxed);
        }
        emit(entry);
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
            self.record(
                policy_events::policy_write_denied(
                    &self.actor_sid,
                    &self.actor_exe,
                    INTENT,
                    &self.path,
                    DenialReason::RequestRejected.as_str(),
                ),
                EntryClass::Admission,
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct WriteAudit(Arc<WriteAuditState>);

impl WriteAudit {
    pub(crate) fn begin(actor_sid: &Sid, actor_exe: &Path, path: &Path) -> Self {
        Self::begin_with_recorder(actor_sid, actor_exe, path, Arc::clone(recorder()))
    }

    fn begin_with_recorder(actor_sid: &Sid, actor_exe: &Path, path: &Path, recorder: Arc<dyn AuditRecorder>) -> Self {
        let state = Arc::new(WriteAuditState {
            actor_sid: bounded(actor_sid.to_string(), MAX_SID_BYTES),
            actor_exe: bounded(actor_exe.display().to_string(), MAX_PATH_BYTES),
            path: bounded_path(path),
            terminal_recorded: AtomicBool::new(false),
            recorder,
        });
        state.record(
            policy_events::policy_write_attempted(&state.actor_sid, &state.actor_exe, INTENT, &state.path),
            EntryClass::Admission,
        );
        Self(state)
    }

    pub(crate) fn denied(&self, reason: DenialReason) {
        // A denial is recorded before the pipe client authenticates, so an unauthenticated flood can
        // produce it at will: it yields rather than consuming the capacity reserved for outcomes.
        self.finish(EntryClass::Admission, |state| {
            policy_events::policy_write_denied(&state.actor_sid, &state.actor_exe, INTENT, &state.path, reason.as_str())
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
        self.finish(EntryClass::Outcome, |state| {
            if operation == PolicyReplacementOperation::Create {
                policy_events::policy_write_failed(
                    policy_events::POLICY_CREATE_FAILED,
                    "Policy creation failed",
                    &state.actor_sid,
                    &state.actor_exe,
                    INTENT,
                    path,
                    operation_name,
                    outcome,
                    reason.as_str(),
                )
            } else {
                policy_events::policy_write_failed(
                    policy_events::POLICY_CHANGE_FAILED,
                    "Policy change failed",
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
        self.finish(EntryClass::Outcome, |state| {
            if operation == PolicyReplacementOperation::Create {
                policy_events::policy_write_succeeded(
                    policy_events::POLICY_CREATE_SUCCEEDED,
                    "Policy creation succeeded",
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
                policy_events::policy_write_succeeded(
                    policy_events::POLICY_CHANGE_SUCCEEDED,
                    "Policy change succeeded",
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

    /// Records the terminal event of `class`, which decides whether a request flood may drop it.
    ///
    /// A denial never reaches the policy store, so it yields like an attempt; the reserved capacity
    /// is kept for the outcome of an authenticated write.
    fn finish(&self, class: EntryClass, entry: impl FnOnce(&WriteAuditState) -> Entry) {
        if self
            .0
            .terminal_recorded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.0.record(entry(&self.0), class);
        }
    }
}

impl WriteAuditState {
    fn record(&self, entry: Entry, class: EntryClass) {
        self.recorder.record(entry, class);
    }
}

pub(crate) fn external_change_applied(path: &Path, new_id: &str, new_revision: u32) {
    recorder().record(
        policy_events::policy_external_change_applied(
            bounded_path(path),
            bounded(new_id.to_owned(), MAX_POLICY_ID_BYTES),
            new_revision,
        ),
        EntryClass::Outcome,
    );
}

pub(crate) fn external_change_rejected(path: &Path, state: PolicyManagementState) {
    let reason = match state {
        PolicyManagementState::Active => "active",
        PolicyManagementState::Missing => "missing",
        PolicyManagementState::Invalid => "invalid",
    };
    recorder().record(
        policy_events::policy_external_change_rejected(bounded_path(path), reason),
        EntryClass::Outcome,
    );
}

fn bounded(mut value: String, max_bytes: usize) -> String {
    value = value
        .chars()
        .map(|character| if is_audit_control(character) { ' ' } else { character })
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

fn is_audit_control(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
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
pub(crate) mod tests {
    use super::*;

    std::thread_local! {
        static EVENTS: std::cell::RefCell<Vec<Entry>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    pub(crate) struct TestRecorder;

    impl AuditRecorder for TestRecorder {
        fn record(&self, entry: Entry, _: EntryClass) {
            EVENTS.with(|events| events.borrow_mut().push(entry));
        }
    }

    pub(crate) fn take_events() -> Vec<Entry> {
        EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
    }

    #[derive(Default)]
    pub(crate) struct Recorder(parking_lot::Mutex<Vec<(Entry, EntryClass)>>);

    impl Recorder {
        pub(crate) fn events(&self) -> Vec<Entry> {
            self.0.lock().iter().map(|(entry, _)| entry.clone()).collect()
        }

        fn classes(&self) -> Vec<EntryClass> {
            self.0.lock().iter().map(|(_, class)| *class).collect()
        }
    }

    impl AuditRecorder for Recorder {
        fn record(&self, entry: Entry, class: EntryClass) {
            self.0.lock().push((entry, class));
        }
    }

    pub(crate) fn begin(actor_sid: &Sid, actor_exe: &Path, path: &Path) -> (WriteAudit, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        let audit = WriteAudit::begin_with_recorder(
            actor_sid,
            actor_exe,
            path,
            Arc::clone(&recorder) as Arc<dyn AuditRecorder>,
        );
        (audit, recorder)
    }

    pub(crate) fn noop() -> WriteAudit {
        let sid = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None).expect("SYSTEM SID");
        WriteAudit::begin_with_recorder(
            &sid,
            Path::new(r"C:\test-client.exe"),
            Path::new(r"C:\policy.json"),
            Arc::new(NoopRecorder),
        )
    }

    struct NoopRecorder;

    impl AuditRecorder for NoopRecorder {
        fn record(&self, _: Entry, _: EntryClass) {}
    }

    fn test_audit() -> (WriteAudit, Arc<Recorder>) {
        let sid = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None).expect("SYSTEM SID");
        begin(&sid, Path::new(r"C:\client.exe"), Path::new(r"C:\policy.json"))
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
                Some(policy_events::POLICY_WRITE_ATTEMPTED),
                Some(policy_events::POLICY_WRITE_DENIED)
            ]
        );
    }

    #[test]
    fn a_denial_yields_like_an_attempt_while_an_outcome_keeps_the_reserve() {
        // A denial is reachable before the pipe client authenticates, so an unauthenticated flood
        // must be unable to spend the capacity reserved for the outcome of an accepted write.
        let (denied, recorder) = test_audit();
        denied.denied(DenialReason::AuthenticationFailed);
        assert_eq!(recorder.classes(), [EntryClass::Admission, EntryClass::Admission]);

        let (abandoned, recorder) = test_audit();
        drop(abandoned);
        assert_eq!(recorder.classes(), [EntryClass::Admission, EntryClass::Admission]);

        let (failed, recorder) = test_audit();
        failed.failed(PolicyReplacementOperation::Update, FailureReason::InvalidPolicy);
        assert_eq!(recorder.classes(), [EntryClass::Admission, EntryClass::Outcome]);
    }

    #[test]
    fn abandoned_clones_record_one_terminal_denial() {
        let (audit, recorder) = test_audit();
        let retained = audit.clone();
        drop(audit);
        assert_eq!(recorder.events().len(), 1);
        drop(retained);
        let events = recorder.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_code, Some(policy_events::POLICY_WRITE_DENIED));
        assert!(
            events[1]
                .fields
                .iter()
                .any(|(name, value)| name == "reason" && value == "request_rejected")
        );
    }

    #[test]
    fn terminal_outcomes_are_reserved_against_an_admission_flood() {
        // A worker that cannot make progress leaves the queue in its saturated state.
        let open = Arc::new(AtomicBool::new(false));
        let release = Arc::clone(&open);
        let (emitted, received) = std::sync::mpsc::channel();
        let mut queue = EventLogQueue::start(move |entry| {
            while !release.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = emitted.send(entry);
        })
        .expect("the audit worker starts");

        let admission =
            || Entry::new("Policy management write attempted").event_code(policy_events::POLICY_WRITE_ATTEMPTED);
        let outcome =
            Entry::new("Policy management change succeeded").event_code(policy_events::POLICY_CHANGE_SUCCEEDED);

        let mut admitted = 0;
        let mut refused = 0;
        for _ in 0..EVENT_LOG_ADMISSION_BUDGET + 8 {
            if queue.record(admission(), EntryClass::Admission).is_ok() {
                admitted += 1;
            } else {
                refused += 1;
            }
        }
        assert!(admitted >= EVENT_LOG_ADMISSION_BUDGET);
        assert!(refused > 0, "the flood must saturate the admission budget");

        // The outcome is still accepted, because the outcome reserve is out of reach of the flood.
        queue
            .record(outcome, EntryClass::Outcome)
            .expect("a terminal outcome is accepted while admission entries are refused");

        open.store(true, Ordering::Release);
        queue.drain();
        assert_eq!(
            queue.admission_pending.load(Ordering::Relaxed),
            0,
            "every admitted entry released its slot in the admission budget"
        );

        // Every admitted entry reached the sink, plus the outcome that the flood could not displace.
        let codes = received.iter().map(|entry| entry.event_code).collect::<Vec<_>>();
        assert_eq!(codes.len(), admitted + 1);
        assert_eq!(
            codes
                .iter()
                .filter(|code| **code == Some(policy_events::POLICY_CHANGE_SUCCEEDED))
                .count(),
            1
        );
    }

    #[test]
    fn an_accepted_attempt_precedes_its_terminal_outcome() {
        // The worker blocks on the first entry it takes, so the attempt and its outcome are both
        // queued while it cannot make progress, and the emitted order is the recorded order.
        let busy = Arc::new(AtomicBool::new(false));
        let open = Arc::new(AtomicBool::new(false));
        let started = Arc::clone(&busy);
        let release = Arc::clone(&open);
        let (emitted, received) = std::sync::mpsc::channel();
        let mut queue = EventLogQueue::start(move |entry| {
            started.store(true, Ordering::Release);
            while !release.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = emitted.send(entry);
        })
        .expect("the audit worker starts");

        queue
            .record(
                // The terminal outcome of a previous write, which the worker takes and emits first.
                Entry::new("Policy management change failed").event_code(policy_events::POLICY_CHANGE_FAILED),
                EntryClass::Outcome,
            )
            .expect("the blocking outcome is accepted");
        while !busy.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        queue
            .record(
                Entry::new("Policy management write attempted").event_code(policy_events::POLICY_WRITE_ATTEMPTED),
                EntryClass::Admission,
            )
            .expect("the attempt is accepted");
        queue
            .record(
                Entry::new("Policy management change succeeded").event_code(policy_events::POLICY_CHANGE_SUCCEEDED),
                EntryClass::Outcome,
            )
            .expect("the terminal outcome is accepted");

        open.store(true, Ordering::Release);
        queue.drain();

        let codes = received.iter().map(|entry| entry.event_code).collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                Some(policy_events::POLICY_CHANGE_FAILED),
                Some(policy_events::POLICY_WRITE_ATTEMPTED),
                Some(policy_events::POLICY_CHANGE_SUCCEEDED)
            ]
        );
    }

    #[test]
    fn audit_text_removes_control_characters_before_truncation() {
        let value = format!(
            "injected\r\n\t\0\u{061c}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}{}",
            "é".repeat(MAX_POLICY_ID_BYTES)
        );
        let bounded = bounded(value, MAX_POLICY_ID_BYTES);
        assert!(bounded.len() <= MAX_POLICY_ID_BYTES);
        assert!(bounded.ends_with("..."));
        assert!(!bounded.chars().any(is_audit_control));
    }

    #[test]
    fn audit_values_are_bounded_and_fields_are_allowlisted() {
        let sid = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None).expect("SYSTEM SID");
        let long = "é".repeat(MAX_PATH_BYTES);
        let (audit, recorder) = begin(&sid, Path::new(&long), Path::new(&long));
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
                policy_events::POLICY_CREATE_FAILED,
                policy_events::POLICY_CREATE_SUCCEEDED,
            ),
            (
                PolicyReplacementOperation::Update,
                policy_events::POLICY_CHANGE_FAILED,
                policy_events::POLICY_CHANGE_SUCCEEDED,
            ),
            (
                PolicyReplacementOperation::Repair,
                policy_events::POLICY_CHANGE_FAILED,
                policy_events::POLICY_CHANGE_SUCCEEDED,
            ),
            (
                PolicyReplacementOperation::ReplaceIdentity,
                policy_events::POLICY_CHANGE_FAILED,
                policy_events::POLICY_CHANGE_SUCCEEDED,
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
