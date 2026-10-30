//! Work the provisioner asks Gateway to do: each request is a Task recorded in `gateway.db`, run on the job queue as a
//! [`TaskJob`]. This module is the one place that keeps a task's record and the job running it in step.
//!
//! Each kind of work is a [`ProvisionerTask`]: what one attempt does, what its payloads hold, and what to do once it has
//! ended.
//! Its job is a [`TaskJob`], a job like any other on the job queue, which wraps each attempt in a prelude and a
//! completion: the prelude records the start of the attempt, and the completion publishes and records how it ended,
//! then ends the record.
//! After a recoverable failure, the job waits [`ProvisionerTask::retry_delay`] and runs the next attempt itself, up to
//! [`MAX_ATTEMPTS`].
//! [`ProvisionerTaskService`] stores the job while it records the Task, so a record never exists without its job.
//!
//! The record is the source of truth and the job only wakes it up.
//! The job queue delivers the job at least once, so after a restart the job picks the record up where it left off.
//! A job whose record is not there yet returns an error, so the job queue delivers it again later; the record of a job
//! whose creation was cut short never comes, and the job queue drops the job once its retries are spent.

pub mod ai;
pub mod recording_ai_analysis;

mod attempt;
mod job;
mod service;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use provisioner_task::ProvisionerTaskRecord;
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;

pub use self::attempt::Attempt;
pub use self::job::TaskJob;
pub use self::service::{
    ProvisionerTaskHandle, ProvisionerTaskReceiver, ProvisionerTaskService, provisioner_task_channel,
};

/// Attempts a record gets: a recoverable failure of the last one fails the record.
pub const MAX_ATTEMPTS: u32 = 5;

/// A provisioner task: the work Gateway does for one kind of request, such as `recording-ai-analysis`.
///
/// One value serves every record of its kind, so it keeps only what they share; what belongs to one record comes in
/// through [`Attempt`] and the parameters.
#[async_trait]
pub trait ProvisionerTask: Send + Sync + 'static {
    /// The kind written in the records of this task, and the name of its jobs.
    const KIND: &'static str;

    /// Time from the creation of a record until its first attempt must start.
    const START_WINDOW: time::Duration;

    /// What the record keeps as asked; never secrets, since records are kept and returned to callers.
    type Params: Serialize + DeserializeOwned + Send + 'static;

    /// The payload of a `succeeded` record.
    type Output: Serialize + Send + Sync + 'static;

    /// Why an attempt of this task fails for good, next to the failures any task may have.
    type Failure: Serialize + Send + Sync + 'static;

    /// Why an attempt of this task fails for now, so a later attempt may succeed.
    type Recoverable: Serialize + Send + Sync + 'static;

    /// Time a running record may go without progress: each attempt start and each progress report moves its deadline
    /// this far ahead.
    fn progress_timeout(&self) -> time::Duration;

    /// Time to wait after attempt `attempts` failed with a recoverable failure, before the next attempt starts.
    fn retry_delay(&self, attempts: u32) -> time::Duration;

    /// The payload of the running record as an attempt starts, from `last`, its payload until then: `null` before its
    /// first attempt.
    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value;

    /// The payload of a record that failed with `error`, from `last`, its payload until then: `null` if it never ran.
    fn failed_payload(
        &self,
        error: &Permanent<Self::Failure, Self::Recoverable>,
        last: &serde_json::Value,
    ) -> serde_json::Value;

    /// Runs one attempt.
    ///
    /// The attempt should stop soon after [`Attempt::cancel`] is cancelled, which happens once the record is past its
    /// deadline.
    async fn run(
        &self,
        attempt: &Attempt,
        params: Self::Params,
    ) -> Result<Self::Output, AttemptError<Self::Failure, Self::Recoverable>>;

    /// Publishes what a successful attempt produced, such as listing its file where callers find it.
    ///
    /// It runs in the step that records the success, before the success is written, so a `succeeded` record always
    /// has its output published; an error leaves the record running, and the job queue runs the job again.
    async fn publish(&self, record: &ProvisionerTaskRecord, output: &Self::Output) -> anyhow::Result<()>;

    /// Finishes what the record leaves to do once it has ended, however it ended, such as dropping what was kept only
    /// while it ran.
    ///
    /// It may be called again for a record that already ended, so it must be idempotent; an error returns from the job,
    /// and the job queue runs the job again, which calls it again.
    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()>;
}

/// The deadline `timeout` after `now`, in whole seconds as the store keeps it, so Gateway and the store agree on when
/// it passes.
fn deadline(now: OffsetDateTime, timeout: time::Duration) -> OffsetDateTime {
    (now + timeout).truncate_to_second()
}

/// Why one attempt of a Task failed, with `F` and `R` the failures of its own kind of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError<F, R> {
    /// Worth another attempt later, such as a rate limit or a network error.
    Recoverable(R),
    /// Another attempt would fail the same way, so the Task fails at once.
    Permanent(Permanent<F, R>),
}

impl<F, R> AttemptError<F, R> {
    /// A permanent failure of the Task's own kind of work.
    pub fn of_kind(failure: F) -> Self {
        Self::Permanent(Permanent::Kind(failure))
    }
}

/// Why a Task failed, as the `error` of its payload: a closed set of kinds without text for people, since the caller
/// words them.
///
/// The kinds below can happen to any Task, while [`Permanent::Kind`] holds those of its own kind of work, so a new kind
/// of Task brings its failures without adding to these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Permanent<F, R> {
    /// The Task itself is not valid, such as with parameters this Gateway cannot read.
    InvalidTask,
    /// The attempt panicked.
    Panicked,
    /// Something went wrong inside Gateway, such as a file it could not write, or a restart that cut the last attempt
    /// short.
    Internal,
    /// Every attempt failed with a recoverable failure, the last one being `last`.
    AttemptsExhausted { last: R },
    /// The Task did not start in time, or went too long without progress.
    DeadlinePassed,
    /// A failure of the Task's own kind of work, which names its own `kind`.
    #[serde(untagged)]
    Kind(F),
}
