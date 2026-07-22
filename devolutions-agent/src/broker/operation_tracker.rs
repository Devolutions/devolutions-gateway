//! Operation tracker — tracks in-flight and recently completed operations.
//!
//! Each tracked operation holds the current status and is updated by a background
//! task that waits for the process to exit. Completed operations are retained for
//! a configurable retention period before being evicted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, bail};
use chrono::{DateTime, Utc};
use now_policy_api::{OperationStatus, PackageRequest, ResourceId};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

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
    /// Authenticated operation owner.
    pub owner_key: String,
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
    request_index: HashMap<RequestIndexKey, IndexedRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestIndexKey {
    owner_key: String,
    request_id: String,
}

struct IndexedRequest {
    operation_id: String,
    fingerprint: String,
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
    pub fn register(
        &self,
        owner_key: &str,
        request: &PackageRequest,
        operation_id: ResourceId,
    ) -> anyhow::Result<(ResourceId, bool)> {
        let mut state = self.state.lock().expect("tracker lock poisoned");
        let request_key = RequestIndexKey {
            owner_key: owner_key.to_owned(),
            request_id: request.request_id.to_string(),
        };
        let fingerprint = request_fingerprint(request)?;
        if let Some(existing) = state.request_index.get(&request_key) {
            if existing.fingerprint != fingerprint {
                bail!("request id was already used by this client with a different request body");
            }
            return Ok((ResourceId::from(existing.operation_id.as_str()), false));
        }

        let operation_key = operation_id.to_string();
        state.request_index.insert(
            request_key,
            IndexedRequest {
                operation_id: operation_key.clone(),
                fingerprint,
            },
        );
        state.operations.insert(
            operation_key,
            TrackedOperation {
                request_id: request.request_id.clone(),
                status: OperationStatus::Starting,
                started_at: None,
                completed_at: None,
                exit_code: None,
                note: None,
                stdout: None,
                owner_key: owner_key.to_owned(),
                expires_at: None,
            },
        );
        Ok((operation_id, true))
    }

    /// Mark an operation as Running (process launched).
    pub fn mark_running(&self, request_id: &str, started_at: DateTime<Utc>) {
        let mut state = self.state.lock().expect("tracker lock poisoned");
        if let Some(op) = state.operations.get_mut(request_id) {
            op.status = OperationStatus::Running;
            op.started_at = Some(started_at);
        }
    }

    /// Mark an operation as finished with an exit code, a status note (success message or
    /// short error summary), and optionally captured output.
    pub fn mark_completed(
        &self,
        request_id: &str,
        exit_code: i32,
        note: String,
        stdout: Option<String>,
        started_at: Option<DateTime<Utc>>,
    ) {
        let mut state = self.state.lock().expect("tracker lock poisoned");
        if let Some(op) = state.operations.get_mut(request_id) {
            let now = Utc::now();
            if op.started_at.is_none()
                && let Some(started_at) = started_at
            {
                op.status = OperationStatus::Running;
                op.started_at = Some(started_at);
            }
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

    /// Query the current state of an operation if owned by the authenticated client.
    pub fn get_for_owner(&self, request_id: &str, owner_key: &str) -> Option<TrackedOperation> {
        let state = self.state.lock().expect("tracker lock poisoned");
        state
            .operations
            .get(request_id)
            .filter(|operation| operation.owner_key == owner_key)
            .cloned()
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
            .retain(|_, request| retained_operation_ids.contains(&request.operation_id));
    }

    /// Returns the operation timeout duration.
    pub fn operation_timeout() -> Duration {
        OPERATION_TIMEOUT
    }

    /// Spawn a background task that periodically evicts expired operations.
    pub fn spawn_eviction_task(self, shutdown: CancellationToken) {
        tokio::spawn(async move {
            let interval = Duration::from_secs(30);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        self.evict_expired();
                    }
                }
            }
        });
    }
}

fn request_fingerprint(request: &PackageRequest) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(request).context("failed to serialize package request for idempotency")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
