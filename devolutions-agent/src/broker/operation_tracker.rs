//! Operation tracker — tracks in-flight and recently completed operations.
//!
//! Each tracked operation holds the current status and is updated by a background
//! task that waits for the process to exit. Completed operations are retained for
//! a configurable retention period before being evicted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use now_policy_api::{OperationStatus, ResourceId};
use tokio::sync::Notify;

/// How long completed/failed operation results are retained for status queries.
const RESULT_RETENTION: Duration = Duration::from_secs(5 * 60); // 5 minutes.

/// Maximum operation runtime before declaring timeout.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour.

/// Internal state of a tracked operation.
#[derive(Debug, Clone)]
pub struct TrackedOperation {
    /// Original request identifier.
    pub request_id: ResourceId,
    /// Current status.
    pub status: OperationStatus,
    /// When the process was launched (Some after CreateProcess succeeds).
    pub started_at: Option<DateTime<Utc>>,
    /// When the operation completed/failed.
    pub completed_at: Option<DateTime<Utc>>,
    /// Process exit code (when available).
    pub exit_code: Option<i32>,
    /// Human-readable note.
    pub note: Option<String>,
    /// Captured combined stdout+stderr (tail-truncated), when the request opted in.
    pub stdout: Option<String>,
    /// When this entry should be evicted (set upon completion/failure).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Thread-safe operation tracker.
#[derive(Clone)]
pub struct OperationTracker {
    state: Arc<Mutex<TrackerState>>,
}

struct TrackerState {
    operations: HashMap<String, TrackedOperation>,
    request_index: HashMap<String, String>,
}

impl Default for OperationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationTracker {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(TrackerState {
                operations: HashMap::new(),
                request_index: HashMap::new(),
            })),
        }
    }

    /// Register a new operation as Starting.
    ///
    /// Returns the operation ID and whether this call created a new operation.
    pub fn register(&self, request_id: &ResourceId, operation_id: ResourceId) -> (ResourceId, bool) {
        let mut state = self.state.lock().expect("tracker lock poisoned");
        let request_key = request_id.to_string();
        if let Some(existing_operation_id) = state.request_index.get(&request_key) {
            return (ResourceId::from(existing_operation_id.as_str()), false);
        }

        let operation_key = operation_id.to_string();
        state.request_index.insert(request_key, operation_key.clone());
        state.operations.insert(
            operation_key,
            TrackedOperation {
                request_id: request_id.clone(),
                status: OperationStatus::Starting,
                started_at: None,
                completed_at: None,
                exit_code: None,
                note: None,
                stdout: None,
                expires_at: None,
            },
        );
        (operation_id, true)
    }

    /// Mark an operation as Running (process launched).
    pub fn mark_running(&self, request_id: &str) {
        let mut state = self.state.lock().expect("tracker lock poisoned");
        if let Some(op) = state.operations.get_mut(request_id) {
            op.status = OperationStatus::Running;
            op.started_at = Some(Utc::now());
        }
    }

    /// Mark an operation as finished with an exit code, a status note (success message or
    /// short error summary), and optionally captured output.
    pub fn mark_completed(&self, request_id: &str, exit_code: i32, note: String, stdout: Option<String>) {
        let mut state = self.state.lock().expect("tracker lock poisoned");
        if let Some(op) = state.operations.get_mut(request_id) {
            let now = Utc::now();
            op.status = if exit_code == 0 {
                OperationStatus::Completed
            } else {
                OperationStatus::Failed
            };
            op.exit_code = Some(exit_code);
            op.note = Some(note);
            op.stdout = stdout;
            op.completed_at = Some(now);
            op.expires_at = Some(now + chrono::Duration::from_std(RESULT_RETENTION).expect("valid duration"));
        }
    }

    /// Mark an operation as Failed without a process exit code (launch failure or timeout).
    pub fn mark_failed(&self, request_id: &str, note: String, stdout: Option<String>) {
        let mut state = self.state.lock().expect("tracker lock poisoned");
        if let Some(op) = state.operations.get_mut(request_id) {
            let now = Utc::now();
            op.status = OperationStatus::Failed;
            op.note = Some(note);
            op.stdout = stdout;
            op.completed_at = Some(now);
            op.expires_at = Some(now + chrono::Duration::from_std(RESULT_RETENTION).expect("valid duration"));
        }
    }

    /// Query the current state of an operation.
    pub fn get(&self, request_id: &str) -> Option<TrackedOperation> {
        let state = self.state.lock().expect("tracker lock poisoned");
        state.operations.get(request_id).cloned()
    }

    /// Remove expired entries. Called periodically.
    pub fn evict_expired(&self) {
        let now = Utc::now();
        let mut state = self.state.lock().expect("tracker lock poisoned");
        state.operations.retain(|_, op| match op.expires_at {
            Some(expiry) => now < expiry,
            None => true, // Still running, keep it.
        });
        let retained_operation_ids: std::collections::HashSet<_> = state.operations.keys().cloned().collect();
        state
            .request_index
            .retain(|_, operation_id| retained_operation_ids.contains(operation_id));
    }

    /// Returns the operation timeout duration.
    pub fn operation_timeout() -> Duration {
        OPERATION_TIMEOUT
    }

    /// Spawn a background task that periodically evicts expired operations.
    pub fn spawn_eviction_task(self, shutdown: Arc<Notify>) {
        tokio::spawn(async move {
            let interval = Duration::from_secs(30);
            loop {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    _ = tokio::time::sleep(interval) => {
                        self.evict_expired();
                    }
                }
            }
        });
    }
}
