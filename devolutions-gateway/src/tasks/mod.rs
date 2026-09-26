//! Background tasks started by the provisioner through `POST /jet/tasks` and polled through `GET /jet/tasks/{id}`.
//!
//! Every task has a record in the provisioner task database, kept forever so it can be audited.
//! Each task runs as a job of the job queue. The job definition holds only the persisted, non-secret parameters,
//! so a [`DurableTask`] resumes after a restart. The secrets of an [`EphemeralTask`] stay in memory only:
//! when Gateway restarts, the task fails instead.

pub mod ai_log;

use core::marker::PhantomData;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use parking_lot::Mutex;
use provisioner_task_store_libsql::{LibSqlProvisionerTaskStore, NewTask, TaskRecord, TaskState};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{OnceCell, Semaphore};
use uuid::Uuid;

use crate::DgwState;
use crate::job_queue::{JOB_MAX_ATTEMPTS, JobQueueCtx};

/// Number of tasks running at the same time; other tasks wait in the `NotStarted` state.
pub const MAX_CONCURRENT_TASKS: usize = 2;

/// Longest time one attempt of a task may run, not counting the time it waits for a free slot.
pub const TASK_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub const SECRETS_LOST_ERROR: &str = "gateway restarted, API key no longer available";

pub const JOB_LOST_ERROR: &str = "gateway restarted, task job no longer exists";

/// Why a run of a task failed; the message is stored in the task record and returned by the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskError {
    /// Worth another attempt later, such as a rate limit or a network error.
    Transient(String),
    /// Another attempt would fail the same way.
    Permanent(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts in total, capped by the job queue.
    pub max_attempts: u32,
}

impl RetryPolicy {
    pub const NO_RETRY: Self = Self { max_attempts: 1 };

    pub const JOB_QUEUE: Self = Self {
        max_attempts: JOB_MAX_ATTEMPTS,
    };
}

/// A kind of one-shot background task.
pub trait TaskKind: Sized + Send + Sync + 'static {
    /// Value of the TASK token `jet_tk` claim.
    const KIND: &'static str;

    /// How many times a run ending with [`TaskError::Transient`] is attempted.
    const RETRY: RetryPolicy;

    /// What the task works on, taken from the TASK token.
    type Target: Serialize + DeserializeOwned + Send + Sync + 'static;

    /// Persisted parameters; they must never hold a secret.
    type Params: Serialize + DeserializeOwned + Send + Sync + 'static;

    /// Progress reported while the task is running.
    type Substate: Serialize + Default + Send + Sync + 'static;

    type Output: Serialize + Send + 'static;

    fn run(ctx: TaskCtx<Self>) -> impl Future<Output = Result<Self::Output, TaskError>> + Send;
}

/// A task whose inputs are all persisted, so it resumes after a restart.
pub trait DurableTask: TaskKind {
    /// Checks the request before the task is recorded.
    fn prepare(target: &Self::Target, params: &Self::Params, state: &DgwState) -> Result<(), StartError>;
}

/// A task that needs secrets, kept in memory only until the task finishes.
pub trait EphemeralTask: TaskKind {
    type Secrets: Send + Sync + 'static;

    /// Body of `POST /jet/tasks`, holding both the parameters and the secrets.
    type Request: DeserializeOwned;

    /// Checks the request and splits it into the persisted parameters and the secrets.
    fn prepare(
        target: &Self::Target,
        request: Self::Request,
        state: &DgwState,
    ) -> Result<(Self::Params, Self::Secrets), StartError>;
}

/// Reason why a task was not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// The request parameters are invalid; the code is stable and safe to show.
    InvalidParams(&'static str),
    /// The target cannot be worked on right now; the code is stable and safe to show.
    TargetBusy(&'static str),
    Internal,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    NotStarted,
    Running { substate: serde_json::Value },
    Success { result: serde_json::Value },
    Failed { error: String },
}

#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    pub id: Uuid,
    pub kind: String,
    pub status: TaskStatus,
}

impl From<TaskRecord> for TaskSnapshot {
    fn from(record: TaskRecord) -> Self {
        let status = match record.state {
            TaskState::NotStarted => TaskStatus::NotStarted,
            TaskState::Running => TaskStatus::Running {
                substate: parse_json(record.substate.as_deref()),
            },
            TaskState::Success => TaskStatus::Success {
                result: parse_json(record.result.as_deref()),
            },
            TaskState::Failed => TaskStatus::Failed {
                error: record.error.unwrap_or_default(),
            },
        };

        Self {
            id: record.id,
            kind: record.kind,
            status,
        }
    }
}

/// What a run of a task gets.
pub struct TaskCtx<K: TaskKind> {
    pub id: Uuid,
    /// Starts at 1.
    pub attempt: u32,
    pub target: K::Target,
    pub params: K::Params,
    pub state: DgwState,
    pub progress: Progress<K::Substate>,
    secrets: Option<Arc<dyn Any + Send + Sync>>,
}

impl<K: EphemeralTask> TaskCtx<K> {
    pub fn secrets(&self) -> Option<&K::Secrets> {
        self.secrets.as_deref().and_then(|secrets| secrets.downcast_ref())
    }
}

/// Lets a running task update its substate.
pub struct Progress<S> {
    id: Uuid,
    tasks: TaskService,
    _substate: PhantomData<fn(S)>,
}

impl<S: Serialize> Progress<S> {
    pub async fn set(&self, substate: &S) {
        let stored = match self.tasks.store().await {
            Ok(store) => store.set_substate(self.id, &to_json(substate)).await,
            Err(error) => Err(error),
        };

        if let Err(error) = stored {
            warn!(task.id = %self.id, error = format!("{error:#}"), "Failed to store the task substate");
        }
    }
}

type SecretsMap = HashMap<Uuid, Arc<dyn Any + Send + Sync>>;

struct TaskServiceInner {
    store: OnceCell<LibSqlProvisionerTaskStore>,
    /// Where the store is opened on first use, when it was not opened up front.
    lazy_path: &'static str,
    secrets: Mutex<SecretsMap>,
    slots: Semaphore,
    timeout: Duration,
}

/// Starts background tasks, runs them as jobs and reads their records.
#[derive(Clone)]
pub struct TaskService {
    inner: Arc<TaskServiceInner>,
}

impl TaskService {
    /// Opens the task database at `path`.
    pub async fn open(path: &str) -> anyhow::Result<Self> {
        let store = LibSqlProvisionerTaskStore::open(path)
            .await
            .context("failed to open the provisioner task database")?;

        Ok(Self::with_limits(
            OnceCell::new_with(Some(store)),
            MAX_CONCURRENT_TASKS,
            TASK_TIMEOUT,
        ))
    }

    /// Opens an in-memory database on first use, so tests that never start a task never create one.
    #[doc(hidden)]
    pub fn mock() -> Self {
        Self::with_limits(OnceCell::new(), MAX_CONCURRENT_TASKS, TASK_TIMEOUT)
    }

    fn with_limits(store: OnceCell<LibSqlProvisionerTaskStore>, max_concurrent: usize, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(TaskServiceInner {
                store,
                lazy_path: ":memory:",
                secrets: Mutex::new(HashMap::new()),
                slots: Semaphore::new(max_concurrent),
                timeout,
            }),
        }
    }

    async fn store(&self) -> anyhow::Result<&LibSqlProvisionerTaskStore> {
        self.inner
            .store
            .get_or_try_init(|| LibSqlProvisionerTaskStore::open(self.inner.lazy_path))
            .await
    }

    pub async fn get(&self, id: Uuid) -> anyhow::Result<Option<TaskSnapshot>> {
        Ok(self.store().await?.get(id).await?.map(TaskSnapshot::from))
    }

    /// Fails every unfinished task that has no job left in the queue; call it at startup, before the job runner.
    pub async fn reconcile(&self, job_queue: &JobQueueCtx) -> anyhow::Result<()> {
        let defs = job_queue
            .job_defs(TaskJob::NAME)
            .await
            .context("failed to list the task jobs")?;

        self.reconcile_with_job_defs(&defs).await
    }

    async fn reconcile_with_job_defs(&self, defs: &[String]) -> anyhow::Result<()> {
        let queued = defs
            .iter()
            .filter_map(|def| serde_json::from_str::<TaskJobDef>(def).ok())
            .map(|def| def.task_id)
            .collect::<HashSet<_>>();

        let store = self.store().await?;

        for id in store.unfinished().await? {
            if !queued.contains(&id) && store.fail(id, JOB_LOST_ERROR).await? {
                warn!(task.id = %id, "Background task has no job left; marked as failed");
            }
        }

        Ok(())
    }

    /// Parses the request of an ephemeral task, records the task and queues its job.
    pub async fn start_ephemeral<K: EphemeralTask>(
        &self,
        target: K::Target,
        body: &[u8],
        token_jti: Uuid,
        state: &DgwState,
    ) -> Result<TaskSnapshot, StartError> {
        let request = parse_body::<K, K::Request>(body)?;
        let (params, secrets) = K::prepare(&target, request, state)?;
        self.create::<K>(&target, &params, token_jti, Some(Arc::new(secrets)), state)
            .await
    }

    /// Parses the parameters of a durable task, records the task and queues its job.
    pub async fn start_durable<K: DurableTask>(
        &self,
        target: K::Target,
        body: &[u8],
        token_jti: Uuid,
        state: &DgwState,
    ) -> Result<TaskSnapshot, StartError> {
        let params = parse_body::<K, K::Params>(body)?;
        K::prepare(&target, &params, state)?;
        self.create::<K>(&target, &params, token_jti, None, state).await
    }

    async fn create<K: TaskKind>(
        &self,
        target: &K::Target,
        params: &K::Params,
        token_jti: Uuid,
        secrets: Option<Arc<dyn Any + Send + Sync>>,
        state: &DgwState,
    ) -> Result<TaskSnapshot, StartError> {
        let id = Uuid::new_v4();

        let (target, params) = match (serde_json::to_value(target), serde_json::to_value(params)) {
            (Ok(target), Ok(params)) => (target, params),
            (Err(error), _) | (_, Err(error)) => {
                error!(%error, task.kind = K::KIND, "Failed to serialize the task definition");
                return Err(StartError::Internal);
            }
        };

        let def = TaskJobDef {
            task_id: id,
            kind: K::KIND.to_owned(),
            target,
            params,
        };

        // The job may run as soon as it is queued, so the secrets must be in place first.
        if let Some(secrets) = secrets {
            self.inner.secrets.lock().insert(id, secrets);
        }

        let inserted = match self.store().await {
            Ok(store) => {
                store
                    .insert(NewTask {
                        id,
                        kind: K::KIND,
                        target: &def.target.to_string(),
                        params: &def.params.to_string(),
                        token_jti,
                    })
                    .await
            }
            Err(error) => Err(error),
        };

        if let Err(error) = inserted {
            error!(task.id = %id, task.kind = K::KIND, error = format!("{error:#}"), "Failed to record the task");
            self.forget_secrets(id);
            return Err(StartError::Internal);
        }

        let job = TaskJob {
            def,
            state: state.clone(),
        };

        if let Err(error) = state.job_queue_handle.enqueue(job).await {
            error!(task.id = %id, task.kind = K::KIND, error = format!("{error:#}"), "Failed to queue the task");
            self.fail(id, "failed to queue the task").await;
            return Err(StartError::Internal);
        }

        info!(task.id = %id, task.kind = K::KIND, %token_jti, "Background task created");

        Ok(TaskSnapshot {
            id,
            kind: K::KIND.to_owned(),
            status: TaskStatus::NotStarted,
        })
    }

    async fn execute_ephemeral<K: EphemeralTask>(&self, def: TaskJobDef, state: &DgwState) -> anyhow::Result<()> {
        let secrets = self.inner.secrets.lock().get(&def.task_id).cloned();

        match secrets {
            Some(secrets) => self.execute::<K>(def, state, Some(secrets)).await,
            None => {
                warn!(task.id = %def.task_id, task.kind = K::KIND, "Background task secrets are gone");
                self.fail(def.task_id, SECRETS_LOST_ERROR).await;
                Ok(())
            }
        }
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "no durable task kind exists yet"))]
    async fn execute_durable<K: DurableTask>(&self, def: TaskJobDef, state: &DgwState) -> anyhow::Result<()> {
        self.execute::<K>(def, state, None).await
    }

    /// Runs one attempt; an error asks the job queue to try again later.
    async fn execute<K: TaskKind>(
        &self,
        def: TaskJobDef,
        state: &DgwState,
        secrets: Option<Arc<dyn Any + Send + Sync>>,
    ) -> anyhow::Result<()> {
        let id = def.task_id;

        let (target, params) = match (
            serde_json::from_value::<K::Target>(def.target),
            serde_json::from_value::<K::Params>(def.params),
        ) {
            (Ok(target), Ok(params)) => (target, params),
            (Err(error), _) | (_, Err(error)) => {
                error!(task.id = %id, task.kind = K::KIND, %error, "Invalid task definition");
                self.fail(id, "invalid task definition").await;
                return Ok(());
            }
        };

        let _permit = self.inner.slots.acquire().await.context("task slots are closed")?;

        let substate = to_json(&K::Substate::default());

        let store = self.store().await?;

        let Some(attempt) = store.start_attempt(id, &substate).await? else {
            debug!(task.id = %id, task.kind = K::KIND, "Background task is already finished");
            self.forget_secrets(id);
            return Ok(());
        };

        info!(task.id = %id, task.kind = K::KIND, attempt, "Background task running");

        let ctx = TaskCtx {
            id,
            attempt,
            target,
            params,
            state: state.clone(),
            progress: Progress {
                id,
                tasks: self.clone(),
                _substate: PhantomData,
            },
            secrets,
        };

        let max_attempts = K::RETRY.max_attempts.min(JOB_MAX_ATTEMPTS);

        match run_attempt::<K>(ctx, self.inner.timeout).await {
            Ok(output) => {
                store.succeed(id, &to_json(&output)).await?;
                info!(task.id = %id, task.kind = K::KIND, attempt, "Background task succeeded");
            }
            Err(TaskError::Transient(error)) if attempt < max_attempts => {
                warn!(task.id = %id, task.kind = K::KIND, attempt, max_attempts, %error, "Background task attempt failed");
                store.retry_later(id, &error).await?;
                anyhow::bail!("background task attempt failed: {error}");
            }
            Err(TaskError::Transient(error) | TaskError::Permanent(error)) => {
                warn!(task.id = %id, task.kind = K::KIND, attempt, %error, "Background task failed");
                store.fail(id, &error).await?;
            }
        }

        self.forget_secrets(id);

        Ok(())
    }

    async fn fail(&self, id: Uuid, error: &str) {
        self.forget_secrets(id);

        let stored = match self.store().await {
            Ok(store) => store.fail(id, error).await.map(|_| ()),
            Err(store_error) => Err(store_error),
        };

        if let Err(store_error) = stored {
            error!(task.id = %id, error = format!("{store_error:#}"), "Failed to record the task failure");
        }
    }

    fn forget_secrets(&self, id: Uuid) {
        self.inner.secrets.lock().remove(&id);
    }
}

async fn run_attempt<K: TaskKind>(ctx: TaskCtx<K>, timeout: Duration) -> Result<K::Output, TaskError> {
    // The run has its own Tokio task so a panic ends as a failure instead of a task stuck in `Running`.
    let mut handle = tokio::spawn(K::run(ctx));

    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => Err(TaskError::Permanent("task panicked".to_owned())),
        Err(_) => {
            handle.abort();
            Err(TaskError::Permanent("task timed out".to_owned()))
        }
    }
}

fn parse_body<K: TaskKind, T: DeserializeOwned>(body: &[u8]) -> Result<T, StartError> {
    // The serde error is not logged because it may quote the rejected value, which could be a secret.
    serde_json::from_slice::<T>(body).map_err(|error| {
        warn!(
            task.kind = K::KIND,
            category = ?error.classify(),
            line = error.line(),
            column = error.column(),
            "Invalid task parameters"
        );
        StartError::InvalidParams("invalid_params")
    })
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|error| {
        error!(%error, "Failed to serialize a task value");
        "null".to_owned()
    })
}

fn parse_json(json: Option<&str>) -> serde_json::Value {
    json.and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or(serde_json::Value::Null)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskJobDef {
    task_id: Uuid,
    kind: String,
    target: serde_json::Value,
    params: serde_json::Value,
}

/// Job running one attempt of a background task.
pub(crate) struct TaskJob {
    def: TaskJobDef,
    state: DgwState,
}

impl TaskJob {
    pub(crate) const NAME: &'static str = "provisioner-task";

    pub(crate) fn read_json(json: &str, state: DgwState) -> anyhow::Result<Self> {
        let def = serde_json::from_str(json).context("failed to deserialize the task job")?;
        Ok(Self { def, state })
    }
}

#[async_trait]
impl job_queue::Job for TaskJob {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(&self.def).context("failed to serialize the task job")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let tasks = self.state.tasks.clone();
        let def = self.def.clone();

        match def.kind.as_str() {
            ai_log::AiLogTask::KIND => tasks.execute_ephemeral::<ai_log::AiLogTask>(def, &self.state).await,
            kind => {
                error!(task.id = %def.task_id, task.kind = kind, "Unknown task kind");
                tasks.fail(def.task_id, "unknown task kind").await;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests;
