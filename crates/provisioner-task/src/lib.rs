//! Tasks: the permanent record of work the provisioner (DVLS, Hub) asked Gateway to do.
//!
//! A Task remembers what was asked, how it is going and how it ended, and it stays around for auditing. The work
//! itself runs as a job on the job queue; that job is gone once it finishes, but its Task is not.

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

pub type DynProvisionerTaskStore = Arc<dyn ProvisionerTaskStore>;

/// Where a Task is in its life. Every state carries a payload whose shape belongs to the Task kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionerTaskState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl ProvisionerTaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub fn is_finished(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

impl std::str::FromStr for ProvisionerTaskState {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => anyhow::bail!("unknown task state {value:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionerTask {
    /// Chosen by the provisioner, so it can ask again without knowing whether the first request went through.
    pub id: Uuid,
    /// What kind of work this is, e.g. `recording.ai-analysis`.
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewProvisionerTask {
    pub id: Uuid,
    pub kind: String,
    pub target: String,
    pub params: serde_json::Value,
    pub deadline_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateOutcome {
    Created(ProvisionerTask),
    /// The same request came in again; nothing new was created.
    Existing(ProvisionerTask),
    /// The ID is already used by a Task with another kind, target or parameters.
    IdConflict(ProvisionerTask),
    /// Another unfinished Task of the same kind already works on this target.
    TargetBusy(ProvisionerTask),
}

#[async_trait]
pub trait ProvisionerTaskStore: Send + Sync {
    /// Records a new `queued` Task, unless the ID is known or its target is busy.
    ///
    /// Like every method that takes `now`, it first fails the Tasks it looks at that are past their deadline.
    async fn create(&self, task: NewProvisionerTask, now: OffsetDateTime) -> anyhow::Result<CreateOutcome>;

    async fn get(&self, id: Uuid, now: OffsetDateTime) -> anyhow::Result<Option<ProvisionerTask>>;

    /// Marks the start of one more attempt: `running`, with one more attempt counted.
    ///
    /// Returns `false` if the Task is unknown, finished or past its deadline; the attempt must not run then.
    async fn start_attempt(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool>;

    /// Replaces the payload of a `running` Task, e.g. to report progress. Returns `false` if it is not running.
    async fn update_running(&self, id: Uuid, payload: serde_json::Value) -> anyhow::Result<bool>;

    /// Ends a `running` Task as `succeeded`. Returns `false` if it is not running, and changes nothing.
    async fn succeed(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool>;

    /// Ends a `queued` or `running` Task as `failed`. Returns `false` if it was already finished, and changes nothing.
    async fn fail(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool>;
}
