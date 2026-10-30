use std::sync::Arc;

use parking_lot::Mutex;
use provisioner_task::DynProvisionerTaskStore;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::deadline;

/// One attempt of a record, as its task sees it.
pub struct Attempt {
    pub task_id: Uuid,
    pub target: String,
    /// Attempts started so far, this one included.
    pub attempts: u32,
    /// Payload of the record as this attempt started, from [`ProvisionerTask::starting_payload`].
    pub payload: serde_json::Value,
    /// Cancelled once the record is past its deadline or no longer running.
    pub cancel: CancellationToken,
    pub(super) progress_timeout: time::Duration,
    pub(super) store: DynProvisionerTaskStore,
    /// The deadline the record has, shared with the job so it cancels the attempt once the deadline passes.
    pub(super) deadline_at: Arc<Mutex<OffsetDateTime>>,
}

impl Attempt {
    /// Deadline of the record, after which the attempt is cancelled.
    pub fn deadline(&self) -> OffsetDateTime {
        *self.deadline_at.lock()
    }

    /// Replaces the payload of the running record and moves its deadline ahead, so whoever asks about it sees how the
    /// attempt goes.
    ///
    /// A record that is no longer running, such as one past its deadline, cancels the attempt.
    pub async fn report_progress(&self, payload: serde_json::Value) {
        let now = OffsetDateTime::now_utc();
        let deadline_at = deadline(now, self.progress_timeout);

        match self.store.update_running(self.task_id, payload, deadline_at, now).await {
            Ok(true) => *self.deadline_at.lock() = deadline_at,
            Ok(false) => {
                debug!(task.id = %self.task_id, "Task is no longer running, so its attempt stops");
                self.cancel.cancel();
            }
            Err(error) => {
                warn!(task.id = %self.task_id, error = format!("{error:#}"), "Failed to record the Task progress");
            }
        }
    }
}
