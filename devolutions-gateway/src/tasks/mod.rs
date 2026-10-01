//! Background tasks started by the provisioner through `POST /jet/tasks` and polled through `GET /jet/tasks/{id}`.
//!
//! Every task has a record in the provisioner task database, kept forever so it can be audited.
//! Each task runs as a job of a job queue stored in that same database, with its own runner:
//! tasks never take a slot from the other Gateway jobs, and other jobs never delay a task.
//! The job definition holds only the persisted, non-secret parameters, so a [`DurableTask`] resumes after a restart.
//! The secrets of an [`EphemeralTask`] stay in memory only: when Gateway restarts, the task fails instead.
//! A task may keep intermediate files in its workspace, under the recording folder so it gets the same access rules;
//! the workspace is kept across attempts and deleted when the task finishes.
//!
//! The task system is unstable: it starts only when `__debug__.enable_unstable` is set.

pub mod ai;
pub mod ai_log;

use core::marker::PhantomData;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use camino::Utf8PathBuf;
use devolutions_gateway_task::{ShutdownSignal, Task};
use job_queue::{DynJob, DynJobQueue, JobQueue as _, JobReader, RunnerWaker};
use job_queue_libsql::{LibSqlJobQueue, libsql};
use parking_lot::Mutex;
use provisioner_task_store_libsql::{LibSqlProvisionerTaskStore, NewTask, TaskRecord, TaskState};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::DgwState;
use crate::config::Conf;

/// Number of tasks running at the same time; other tasks wait in the `NotStarted` state.
pub const MAX_CONCURRENT_TASKS: usize = 2;

/// Longest time one attempt of a task may run.
pub const TASK_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Attempts of a task job before the task job queue gives up on it.
pub const TASK_MAX_ATTEMPTS: u32 = 5;

pub const SECRETS_LOST_ERROR: &str = "gateway restarted, API key no longer available";

pub const JOB_LOST_ERROR: &str = "gateway restarted, task job no longer exists";

/// Folder of the task workspaces, in the recording folder.
pub const WORKSPACES_DIR: &str = ".provisioner-tasks";

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
    /// Attempts in total, capped by the task job queue.
    pub max_attempts: u32,
}

impl RetryPolicy {
    pub const JOB_QUEUE: Self = Self {
        max_attempts: TASK_MAX_ATTEMPTS,
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
    fn prepare(state: &DgwState, target: &Self::Target, params: &Self::Params) -> Result<(), TaskErrorCode>;
}

/// A task that needs secrets, kept in memory only until the task finishes.
pub trait EphemeralTask: TaskKind {
    type Secrets: Send + Sync + 'static;

    /// Body of `POST /jet/tasks`, holding both the parameters and the secrets.
    type Request: DeserializeOwned;

    /// Checks the request and splits it into the persisted parameters and the secrets.
    fn prepare(
        state: &DgwState,
        target: &Self::Target,
        request: Self::Request,
    ) -> Result<(Self::Params, Self::Secrets), TaskErrorCode>;
}

/// Stable code telling a client why a task request failed; safe to show.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskErrorCode {
    /// The body is not valid JSON or does not match the parameters of the task kind.
    InvalidParams,
    /// The AI model is empty.
    MissingModel,
    /// The AI API key is empty.
    MissingApiKey,
    /// The AI provider has no default base URL, so the request must give one.
    MissingBaseUrl,
    /// The AI settings are invalid for another reason.
    InvalidAiSettings,
    /// `ai-log`: the session is still recording.
    RecordingActive,
    /// No task has this ID.
    TaskNotFound,
    /// Unexpected server error.
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
    /// Folder of files kept across attempts; not created until the task needs it.
    pub workspace: Utf8PathBuf,
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
        if let Err(error) = self.tasks.store().set_substate(self.id, &to_json(substate)).await {
            warn!(task.id = %self.id, error = format!("{error:#}"), "Failed to store the task substate");
        }
    }
}

type SecretsMap = HashMap<Uuid, Arc<dyn Any + Send + Sync>>;

struct TaskServiceInner {
    store: LibSqlProvisionerTaskStore,
    /// Stored in the same database as the task records.
    queue: DynJobQueue,
    notify_runner: Arc<Notify>,
    runner_waker: RunnerWaker,
    secrets: Mutex<SecretsMap>,
    workspaces: Utf8PathBuf,
    timeout: Duration,
}

/// Starts background tasks, queues their jobs and reads their records.
#[derive(Clone)]
pub struct TaskService {
    inner: Arc<TaskServiceInner>,
}

impl TaskService {
    /// Opens the provisioner task database when `enable_unstable` is set; otherwise, never touches it.
    ///
    /// Call it at startup, before the task runner starts.
    pub async fn open_if_enabled(conf: &Conf) -> anyhow::Result<Option<Self>> {
        if !conf.debug.enable_unstable {
            return Ok(None);
        }

        Self::open(
            conf.provisioner_tasks_database.as_str(),
            conf.recording_path.join(WORKSPACES_DIR),
            TASK_TIMEOUT,
        )
        .await
        .map(Some)
    }

    /// Opens the database at `path`, fails every unfinished task whose job is gone, then deletes stale workspaces.
    async fn open(path: &str, workspaces: Utf8PathBuf, timeout: Duration) -> anyhow::Result<Self> {
        let conn = libsql::Builder::new_local(path)
            .build()
            .await
            .context("failed to open the provisioner task database")?
            .connect()
            .context("failed to connect to the provisioner task database")?;

        let notify_runner = Arc::new(Notify::new());

        let runner_waker = RunnerWaker::new({
            let notify_runner = Arc::clone(&notify_runner);
            move || notify_runner.notify_one()
        });

        let queue = LibSqlJobQueue::builder()
            .runner_waker(runner_waker.clone())
            .conn(conn.clone())
            .max_attempts(TASK_MAX_ATTEMPTS)
            .build();

        queue.setup().await.context("failed to set up the task job queue")?;

        queue
            .reset_claimed_jobs()
            .await
            .context("failed to reset the claimed task jobs")?;

        queue
            .clear_failed()
            .await
            .context("failed to clear the failed task jobs")?;

        let store = LibSqlProvisionerTaskStore::init(conn)
            .await
            .context("failed to set up the provisioner task records")?;

        let service = Self {
            inner: Arc::new(TaskServiceInner {
                store,
                queue: Arc::new(queue),
                notify_runner,
                runner_waker,
                secrets: Mutex::new(HashMap::new()),
                workspaces,
                timeout,
            }),
        };

        service
            .reconcile()
            .await
            .context("failed to reconcile the provisioner tasks")?;

        service
            .remove_stale_workspaces()
            .await
            .context("failed to remove the stale task workspaces")?;

        Ok(service)
    }

    fn workspace(&self, id: Uuid) -> Utf8PathBuf {
        self.inner.workspaces.join(id.to_string())
    }

    /// Deletes every workspace that no unfinished task owns.
    async fn remove_stale_workspaces(&self) -> anyhow::Result<()> {
        let mut entries = match tokio::fs::read_dir(&self.inner.workspaces).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        let unfinished = self.store().unfinished().await?.into_iter().collect::<HashSet<_>>();

        while let Some(entry) = entries.next_entry().await? {
            let owned = entry
                .file_name()
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok())
                .is_some_and(|id| unfinished.contains(&id));

            if !owned {
                let path = entry.path();
                info!(path = %path.display(), "Removing a stale task workspace");
                remove_all(&path).await;
            }
        }

        Ok(())
    }

    fn store(&self) -> &LibSqlProvisionerTaskStore {
        &self.inner.store
    }

    pub async fn get(&self, id: Uuid) -> anyhow::Result<Option<TaskSnapshot>> {
        Ok(self.store().get(id).await?.map(TaskSnapshot::from))
    }

    /// Fails every unfinished task that has no job left in the queue.
    async fn reconcile(&self) -> anyhow::Result<()> {
        let defs = self
            .inner
            .queue
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

        let store = self.store();

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
        state: &DgwState,
        target: K::Target,
        body: &[u8],
        token_jti: Uuid,
    ) -> Result<TaskSnapshot, TaskErrorCode> {
        let request = parse_body::<K, K::Request>(body)?;
        let (params, secrets) = K::prepare(state, &target, request)?;
        self.create::<K>(state, &target, &params, token_jti, Some(Arc::new(secrets)))
            .await
    }

    /// Parses the parameters of a durable task, records the task and queues its job.
    pub async fn start_durable<K: DurableTask>(
        &self,
        state: &DgwState,
        target: K::Target,
        body: &[u8],
        token_jti: Uuid,
    ) -> Result<TaskSnapshot, TaskErrorCode> {
        let params = parse_body::<K, K::Params>(body)?;
        K::prepare(state, &target, &params)?;
        self.create::<K>(state, &target, &params, token_jti, None).await
    }

    async fn create<K: TaskKind>(
        &self,
        state: &DgwState,
        target: &K::Target,
        params: &K::Params,
        token_jti: Uuid,
        secrets: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Result<TaskSnapshot, TaskErrorCode> {
        let id = Uuid::new_v4();

        let (target, params) = match (serde_json::to_value(target), serde_json::to_value(params)) {
            (Ok(target), Ok(params)) => (target, params),
            (Err(error), _) | (_, Err(error)) => {
                error!(%error, task.kind = K::KIND, "Failed to serialize the task definition");
                return Err(TaskErrorCode::Internal);
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

        let inserted = self
            .store()
            .insert(NewTask {
                id,
                kind: K::KIND,
                target: &def.target.to_string(),
                params: &def.params.to_string(),
                token_jti,
            })
            .await;

        if let Err(error) = inserted {
            error!(task.id = %id, task.kind = K::KIND, error = format!("{error:#}"), "Failed to record the task");
            self.forget_secrets(id);
            return Err(TaskErrorCode::Internal);
        }

        let job: DynJob = Box::new(TaskJob {
            def,
            tasks: self.clone(),
            state: state.clone(),
        });

        if let Err(error) = self.inner.queue.push_job(&job, None).await {
            error!(task.id = %id, task.kind = K::KIND, error = format!("{error:#}"), "Failed to queue the task");
            self.fail(id, "failed to queue the task").await;
            return Err(TaskErrorCode::Internal);
        }

        info!(task.id = %id, task.kind = K::KIND, %token_jti, "Background task created");

        Ok(TaskSnapshot {
            id,
            kind: K::KIND.to_owned(),
            status: TaskStatus::NotStarted,
        })
    }

    async fn execute_ephemeral<K: EphemeralTask>(&self, state: &DgwState, def: TaskJobDef) -> anyhow::Result<()> {
        let secrets = self.inner.secrets.lock().get(&def.task_id).cloned();

        match secrets {
            Some(secrets) => self.execute::<K>(state, def, Some(secrets)).await,
            None => {
                warn!(task.id = %def.task_id, task.kind = K::KIND, "Background task secrets are gone");
                self.fail(def.task_id, SECRETS_LOST_ERROR).await;
                Ok(())
            }
        }
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "no durable task kind exists yet"))]
    async fn execute_durable<K: DurableTask>(&self, state: &DgwState, def: TaskJobDef) -> anyhow::Result<()> {
        self.execute::<K>(state, def, None).await
    }

    /// Runs one attempt; an error asks the job queue to try again later.
    async fn execute<K: TaskKind>(
        &self,
        state: &DgwState,
        def: TaskJobDef,
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

        let substate = to_json(&K::Substate::default());

        let store = self.store();

        let Some(attempt) = store.start_attempt(id, &substate).await? else {
            debug!(task.id = %id, task.kind = K::KIND, "Background task is already finished");
            self.finish(id).await;
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
            workspace: self.workspace(id),
            secrets,
        };

        let max_attempts = K::RETRY.max_attempts.min(TASK_MAX_ATTEMPTS);

        match run_attempt::<K>(ctx, self.inner.timeout).await {
            // An error returned to the job queue would run the task again, so a failure to store is only logged.
            Ok(output) => match store.succeed(id, &to_json(&output)).await {
                Ok(_) => info!(task.id = %id, task.kind = K::KIND, attempt, "Background task succeeded"),
                Err(error) => error!(
                    task.id = %id,
                    task.kind = K::KIND,
                    attempt,
                    error = format!("{error:#}"),
                    "Background task succeeded but its result was not stored"
                ),
            },
            Err(TaskError::Transient(error)) if attempt < max_attempts => {
                warn!(task.id = %id, task.kind = K::KIND, attempt, max_attempts, %error, "Background task attempt failed");
                store.retry_later(id, &error).await?;
                anyhow::bail!("background task attempt failed: {error}");
            }
            Err(TaskError::Transient(error) | TaskError::Permanent(error)) => {
                warn!(task.id = %id, task.kind = K::KIND, attempt, %error, "Background task failed");
                self.fail(id, &error).await;
            }
        }

        self.finish(id).await;

        Ok(())
    }

    async fn fail(&self, id: Uuid, error: &str) {
        self.finish(id).await;

        if let Err(store_error) = self.store().fail(id, error).await {
            error!(task.id = %id, error = format!("{store_error:#}"), "Failed to record the task failure");
        }
    }

    /// Drops what a task keeps only until it finishes: its secrets and its workspace.
    async fn finish(&self, id: Uuid) {
        self.forget_secrets(id);
        remove_all(self.workspace(id).as_std_path()).await;
    }

    fn forget_secrets(&self, id: Uuid) {
        self.inner.secrets.lock().remove(&id);
    }
}

async fn remove_all(path: &std::path::Path) {
    let removed = if path.is_dir() {
        tokio::fs::remove_dir_all(path).await
    } else {
        tokio::fs::remove_file(path).await
    };

    match removed {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => warn!(path = %path.display(), %error, "Failed to remove a task workspace"),
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

fn parse_body<K: TaskKind, T: DeserializeOwned>(body: &[u8]) -> Result<T, TaskErrorCode> {
    // The serde error is not logged because it may quote the rejected value, which could be a secret.
    serde_json::from_slice::<T>(body).map_err(|error| {
        debug!(
            task.kind = K::KIND,
            category = ?error.classify(),
            line = error.line(),
            column = error.column(),
            "Invalid task parameters"
        );
        TaskErrorCode::InvalidParams
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
struct TaskJob {
    def: TaskJobDef,
    tasks: TaskService,
    state: DgwState,
}

impl TaskJob {
    const NAME: &'static str = "provisioner-task";

    fn read_json(json: &str, tasks: TaskService, state: DgwState) -> anyhow::Result<Self> {
        let def = serde_json::from_str(json).context("failed to deserialize the task job")?;
        Ok(Self { def, tasks, state })
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
        let def = self.def.clone();

        match def.kind.as_str() {
            ai_log::AiLogTask::KIND => {
                self.tasks
                    .execute_ephemeral::<ai_log::AiLogTask>(&self.state, def)
                    .await
            }
            kind => {
                error!(task.id = %def.task_id, task.kind = kind, "Unknown task kind");
                self.tasks.fail(def.task_id, "unknown task kind").await;
                Ok(())
            }
        }
    }
}

struct TaskJobReader {
    tasks: TaskService,
    state: DgwState,
}

impl JobReader for TaskJobReader {
    fn read_json(&self, name: &str, json: &str) -> anyhow::Result<DynJob> {
        match name {
            TaskJob::NAME => {
                let job = TaskJob::read_json(json, self.tasks.clone(), self.state.clone())?;
                Ok(Box::new(job))
            }
            _ => anyhow::bail!("unknown job name: {name}"),
        }
    }
}

/// Runs the jobs of the provisioner tasks.
pub struct TaskRunnerTask {
    tasks: TaskService,
    state: DgwState,
}

impl TaskRunnerTask {
    pub fn new(tasks: TaskService, state: DgwState) -> Self {
        Self { tasks, state }
    }
}

#[async_trait]
impl Task for TaskRunnerTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "provisioner task runner";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        let inner = Arc::clone(&self.tasks.inner);

        let reader = TaskJobReader {
            tasks: self.tasks,
            state: self.state,
        };

        // The runner claims no more jobs than may run at once, so a claimed job never waits for a slot.
        crate::job_queue::run_jobs(
            Arc::clone(&inner.queue),
            &reader,
            Arc::clone(&inner.notify_runner),
            inner.runner_waker.clone(),
            MAX_CONCURRENT_TASKS,
            shutdown_signal,
        )
        .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
