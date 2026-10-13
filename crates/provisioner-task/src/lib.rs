//! Tasks: the permanent record of work the provisioner (DVLS, Hub) asked Gateway to do.
//!
//! A Task remembers what was asked, how it is going and how it ended, and it stays around for auditing. The work
//! itself runs as a job on the job queue; that job is gone once it finishes, but its Task is not.

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

pub type DynProvisionerTaskStore = Arc<dyn ProvisionerTaskStore>;

/// Where a Task is in its life.
///
/// Running, succeeded and failed Tasks carry a payload whose shape belongs to the Task kind; a queued Task has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionerTaskState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl ProvisionerTaskState {
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// What is kept of a Task: what was asked, how it goes and how it ended.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionerTaskRecord {
    /// Chosen by the provisioner, so it can ask again without knowing whether the first request went through.
    pub id: Uuid,
    /// What kind of work this is, e.g. `recording-ai-analysis`.
    pub kind: String,
    /// What the work is about, e.g. a session ID. At most one unfinished Task per kind and target.
    pub target: String,
    /// What was asked, without secrets.
    pub params: serde_json::Value,
    pub state: ProvisionerTaskState,
    pub payload: serde_json::Value,
    pub attempts: u32,
    pub created_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    /// After this, an unfinished Task is failed, so a lost job can't block its target forever.
    pub deadline_at: OffsetDateTime,
    /// The job that may run this Task: a job with another token is stale or a duplicate, and must not run it.
    pub job_token: Uuid,
}

/// The record of a Task about to be created.
#[derive(Debug, Clone, PartialEq)]
pub struct NewProvisionerTaskRecord {
    pub id: Uuid,
    pub kind: String,
    pub target: String,
    pub params: serde_json::Value,
    pub deadline_at: OffsetDateTime,
    /// Token of the job that will run the new Task.
    pub job_token: Uuid,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    Created(ProvisionerTaskRecord),
    /// The same request came in again; nothing new was created.
    Existing(ProvisionerTaskRecord),
    /// The ID is already used by a Task with another kind, target or parameters.
    IdConflict(ProvisionerTaskRecord),
    /// Another unfinished Task of the same kind already works on this target.
    TargetBusy(ProvisionerTaskRecord),
}

/// What a job finds when it comes to run an attempt of its Task.
#[derive(Debug, Clone, PartialEq)]
pub enum AttemptStart {
    /// The attempt is recorded: the Task is `running` with one more attempt counted.
    Started(ProvisionerTaskRecord),
    /// The Task is finished, possibly just now because it is past its deadline.
    Finished(ProvisionerTaskRecord),
    /// Another job now runs the Task, so this one is stale or a duplicate.
    Superseded,
    /// No Task has this ID.
    Unknown,
}

#[async_trait]
pub trait ProvisionerTaskStore: Send + Sync {
    /// Records a new `queued` Task, unless the ID is known or its target is busy.
    ///
    /// Like every method that takes `now`, it first fails the Tasks it looks at that are past their deadline.
    async fn create(&self, task: NewProvisionerTaskRecord, now: OffsetDateTime) -> anyhow::Result<CreateOutcome>;

    /// Reads a Task, after failing it if it is past its deadline.
    async fn get(&self, id: Uuid, now: OffsetDateTime) -> anyhow::Result<Option<ProvisionerTaskRecord>>;

    /// Marks the start of one more attempt by the job holding `job_token`: `running`, with one more attempt counted.
    ///
    /// Only [`AttemptStart::Started`] lets the attempt run. A job that no longer holds the token gets
    /// [`AttemptStart::Superseded`], and nothing changes.
    async fn start_attempt(
        &self,
        id: Uuid,
        job_token: Uuid,
        payload: serde_json::Value,
        now: OffsetDateTime,
    ) -> anyhow::Result<AttemptStart>;

    /// Hands an unfinished Task to a new job, so the job that had it stops at its next attempt.
    ///
    /// Only the start of an attempt checks the token, so call it only while the old job runs no attempt, such as at
    /// startup before any job runs. Returns `false` if the Task is unknown or finished.
    async fn replace_job_token(&self, id: Uuid, job_token: Uuid, now: OffsetDateTime) -> anyhow::Result<bool>;

    /// Every unfinished Task, after failing those past their deadline.
    async fn list_unfinished(&self, now: OffsetDateTime) -> anyhow::Result<Vec<ProvisionerTaskRecord>>;

    /// Replaces the payload of a `running` Task, e.g. to report progress. Returns `false` if it is not running, such
    /// as when it was just failed for being past its deadline.
    async fn update_running(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool>;

    /// Ends a `running` Task as `succeeded`. Returns `false` if it is not running, such as when it was just failed for
    /// being past its deadline.
    async fn succeed(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool>;

    /// Ends a `queued` or `running` Task as `failed`. Returns `false` if it was already finished, such as when it was
    /// just failed for being past its deadline.
    async fn fail(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool>;
}
