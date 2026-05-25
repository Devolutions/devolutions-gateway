//! Operation tracker — tracks in-flight and recently completed operations.
//!
//! Each tracked operation holds the current status and is updated by a background
//! task that waits for the process to exit. Completed operations are retained for
//! a configurable retention period before being evicted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::Notify;

use crate::model::{OperationStatus, ResourceId};

/// How long completed/failed operation results are retained for status queries.
const RESULT_RETENTION: Duration = Duration::from_secs(5 * 60); // 5 minutes.

/// Maximum operation runtime before declaring timeout.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour.

/// Internal state of a tracked operation.
#[derive(Debug, Clone)]
pub struct TrackedOperation {
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
    /// When this entry should be evicted (set upon completion/failure).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Thread-safe operation tracker.
#[derive(Clone)]
pub struct OperationTracker {
    operations: Arc<Mutex<HashMap<String, TrackedOperation>>>,
}

impl Default for OperationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationTracker {
    pub fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new operation as Starting.
    pub fn register(&self, request_id: &ResourceId) {
        let mut ops = self.operations.lock().expect("tracker lock poisoned");
        ops.insert(
            request_id.to_string(),
            TrackedOperation {
                status: OperationStatus::Starting,
                started_at: None,
                completed_at: None,
                exit_code: None,
                note: None,
                expires_at: None,
            },
        );
    }

    /// Mark an operation as Running (process launched).
    pub fn mark_running(&self, request_id: &str) {
        let mut ops = self.operations.lock().expect("tracker lock poisoned");
        if let Some(op) = ops.get_mut(request_id) {
            op.status = OperationStatus::Running;
            op.started_at = Some(Utc::now());
        }
    }

    /// Mark an operation as Completed with an exit code.
    pub fn mark_completed(&self, request_id: &str, exit_code: i32) {
        let mut ops = self.operations.lock().expect("tracker lock poisoned");
        if let Some(op) = ops.get_mut(request_id) {
            let now = Utc::now();
            if exit_code == 0 {
                op.status = OperationStatus::Completed;
                op.note = Some("Process exited successfully.".to_owned());
            } else {
                op.status = OperationStatus::Failed;
                op.note = Some(format!("Process exited with code {exit_code}."));
            }
            op.exit_code = Some(exit_code);
            op.completed_at = Some(now);
            op.expires_at = Some(now + chrono::Duration::from_std(RESULT_RETENTION).expect("valid duration"));
        }
    }

    /// Mark an operation as Failed with a reason.
    pub fn mark_failed(&self, request_id: &str, reason: String) {
        let mut ops = self.operations.lock().expect("tracker lock poisoned");
        if let Some(op) = ops.get_mut(request_id) {
            let now = Utc::now();
            op.status = OperationStatus::Failed;
            op.note = Some(reason);
            op.completed_at = Some(now);
            op.expires_at = Some(now + chrono::Duration::from_std(RESULT_RETENTION).expect("valid duration"));
        }
    }

    /// Query the current state of an operation.
    pub fn get(&self, request_id: &str) -> Option<TrackedOperation> {
        let ops = self.operations.lock().expect("tracker lock poisoned");
        ops.get(request_id).cloned()
    }

    /// Remove expired entries. Called periodically.
    pub fn evict_expired(&self) {
        let now = Utc::now();
        let mut ops = self.operations.lock().expect("tracker lock poisoned");
        ops.retain(|_, op| match op.expires_at {
            Some(expiry) => now < expiry,
            None => true, // Still running, keep it.
        });
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
