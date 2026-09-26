//! One-shot background tasks, started through `POST /jet/tasks` and polled through `GET /jet/tasks/{id}`.
//!
//! Tasks are kept in memory only, so they are lost when Gateway restarts.

pub mod ai_log;

use core::marker::PhantomData;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::DgwState;

/// Number of tasks running at the same time; other tasks wait in the `NotStarted` state.
pub const MAX_CONCURRENT_TASKS: usize = 2;

/// Longest time a task may run, not counting the time it waits for a free slot.
pub const TASK_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How long the status of a finished task can still be read.
pub const FINISHED_TASK_RETENTION: Duration = Duration::from_secs(60 * 60);

/// Where the tasks of one kind are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persistence {
    /// Tasks are dropped when Gateway restarts.
    InMemory,
}

/// A kind of one-shot background task.
pub trait BackgroundTask: Sized + Send + 'static {
    /// Value of the TASK token `jet_tk` claim.
    const KIND: &'static str;

    const PERSISTENCE: Persistence;

    /// Kind-specific request body of `POST /jet/tasks`.
    type Params: DeserializeOwned;

    /// What the task works on, taken from the TASK token.
    type Target;

    /// Progress reported while the task is running.
    type Substate: Serialize + Default + Send;

    type Output: Serialize + Send;

    /// Checks the request and builds the task, before it is registered.
    fn prepare(target: Self::Target, params: Self::Params, state: &DgwState) -> Result<Self, StartError>;

    fn run(self, progress: Progress<Self::Substate>) -> impl Future<Output = anyhow::Result<Self::Output>> + Send;
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
    pub kind: &'static str,
    pub status: TaskStatus,
}

struct TaskEntry {
    kind: &'static str,
    status: TaskStatus,
}

type TaskMap = Arc<Mutex<HashMap<Uuid, TaskEntry>>>;

/// Lets a running task update its substate.
pub struct Progress<S> {
    id: Uuid,
    tasks: TaskMap,
    _substate: PhantomData<fn(S)>,
}

impl<S: Serialize> Progress<S> {
    pub fn set(&self, substate: &S) {
        let substate = to_json_value(substate);

        if let Some(entry) = self.tasks.lock().get_mut(&self.id) {
            entry.status = TaskStatus::Running { substate };
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    max_concurrent: usize,
    timeout: Duration,
    retention: Duration,
}

/// In-memory registry of the background tasks, keyed by task ID.
#[derive(Clone)]
pub struct TaskRegistry {
    tasks: TaskMap,
    slots: Arc<Semaphore>,
    limits: Limits,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self::with_limits(Limits {
            max_concurrent: MAX_CONCURRENT_TASKS,
            timeout: TASK_TIMEOUT,
            retention: FINISHED_TASK_RETENTION,
        })
    }

    fn with_limits(limits: Limits) -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            slots: Arc::new(Semaphore::new(limits.max_concurrent)),
            limits,
        }
    }

    pub fn get(&self, id: Uuid) -> Option<TaskSnapshot> {
        self.tasks.lock().get(&id).map(|entry| TaskSnapshot {
            id,
            kind: entry.kind,
            status: entry.status.clone(),
        })
    }

    /// Parses the kind-specific parameters, prepares the task and runs it in the background.
    pub fn start<K: BackgroundTask>(
        &self,
        target: K::Target,
        params: &[u8],
        state: &DgwState,
    ) -> Result<TaskSnapshot, StartError> {
        match K::PERSISTENCE {
            Persistence::InMemory => {}
        }

        // The serde error is not logged because it may quote the rejected value, which could be the API key.
        let params = serde_json::from_slice::<K::Params>(params).map_err(|error| {
            warn!(
                task.kind = K::KIND,
                category = ?error.classify(),
                line = error.line(),
                column = error.column(),
                "Invalid task parameters"
            );
            StartError::InvalidParams("invalid_params")
        })?;

        let task = K::prepare(target, params, state)?;

        Ok(self.spawn(task))
    }

    fn spawn<K: BackgroundTask>(&self, task: K) -> TaskSnapshot {
        let id = Uuid::new_v4();

        self.tasks.lock().insert(
            id,
            TaskEntry {
                kind: K::KIND,
                status: TaskStatus::NotStarted,
            },
        );

        info!(task.id = %id, task.kind = K::KIND, "Background task created");

        let tasks = Arc::clone(&self.tasks);
        let slots = Arc::clone(&self.slots);
        let limits = self.limits;

        tokio::spawn(async move {
            let status = match Arc::clone(&slots).acquire_owned().await {
                Ok(permit) => {
                    let status = run_task(id, task, &tasks, limits.timeout).await;
                    drop(permit);
                    status
                }
                Err(_) => TaskStatus::Failed {
                    error: "task slots are closed".to_owned(),
                },
            };

            match &status {
                TaskStatus::Failed { error } => {
                    warn!(task.id = %id, task.kind = K::KIND, %error, "Background task failed");
                }
                _ => info!(task.id = %id, task.kind = K::KIND, "Background task succeeded"),
            }

            if let Some(entry) = tasks.lock().get_mut(&id) {
                entry.status = status;
            }

            tokio::time::sleep(limits.retention).await;
            tasks.lock().remove(&id);
        });

        TaskSnapshot {
            id,
            kind: K::KIND,
            status: TaskStatus::NotStarted,
        }
    }
}

async fn run_task<K: BackgroundTask>(id: Uuid, task: K, tasks: &TaskMap, timeout: Duration) -> TaskStatus {
    if let Some(entry) = tasks.lock().get_mut(&id) {
        entry.status = TaskStatus::Running {
            substate: to_json_value(&K::Substate::default()),
        };
    }

    info!(task.id = %id, task.kind = K::KIND, "Background task running");

    let progress = Progress {
        id,
        tasks: Arc::clone(tasks),
        _substate: PhantomData,
    };

    // The task runs on its own Tokio task so a panic ends as a failure instead of a task stuck in `Running`.
    let mut handle = tokio::spawn(task.run(progress));

    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(Ok(Ok(output))) => TaskStatus::Success {
            result: to_json_value(&output),
        },
        Ok(Ok(Err(error))) => TaskStatus::Failed {
            error: format!("{error:#}"),
        },
        Ok(Err(_)) => TaskStatus::Failed {
            error: "task panicked".to_owned(),
        },
        Err(_) => {
            handle.abort();
            TaskStatus::Failed {
                error: "task timed out".to_owned(),
            }
        }
    }
}

fn to_json_value<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_else(|error| {
        error!(%error, "Failed to serialize a task value");
        serde_json::Value::Null
    })
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;

    #[derive(Default, Serialize)]
    struct TestSubstate {
        step: u32,
    }

    struct TestTask {
        started: Option<oneshot::Sender<()>>,
        finish: oneshot::Receiver<anyhow::Result<u32>>,
    }

    impl BackgroundTask for TestTask {
        const KIND: &'static str = "test";
        const PERSISTENCE: Persistence = Persistence::InMemory;

        type Params = ();
        type Target = ();
        type Substate = TestSubstate;
        type Output = u32;

        fn prepare(_: (), (): (), _: &DgwState) -> Result<Self, StartError> {
            unreachable!("tests spawn test tasks directly")
        }

        async fn run(mut self, progress: Progress<TestSubstate>) -> anyhow::Result<u32> {
            progress.set(&TestSubstate { step: 1 });

            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }

            self.finish.await?
        }
    }

    struct Controls {
        started: oneshot::Receiver<()>,
        finish: oneshot::Sender<anyhow::Result<u32>>,
    }

    fn test_task() -> (TestTask, Controls) {
        let (started_tx, started_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = oneshot::channel();

        (
            TestTask {
                started: Some(started_tx),
                finish: finish_rx,
            },
            Controls {
                started: started_rx,
                finish: finish_tx,
            },
        )
    }

    fn registry(max_concurrent: usize, timeout: Duration) -> TaskRegistry {
        TaskRegistry::with_limits(Limits {
            max_concurrent,
            timeout,
            retention: Duration::from_secs(3600),
        })
    }

    async fn wait_for_final_status(registry: &TaskRegistry, id: Uuid) -> TaskStatus {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = registry.get(id).expect("task is registered").status;

                if matches!(status, TaskStatus::Success { .. } | TaskStatus::Failed { .. }) {
                    return status;
                }

                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("task finishes")
    }

    #[tokio::test]
    async fn status_goes_from_not_started_to_running_to_failed() {
        let registry = registry(1, Duration::from_secs(60));
        let (task, controls) = test_task();

        let snapshot = registry.spawn(task);
        assert_eq!(snapshot.status, TaskStatus::NotStarted);
        assert_eq!(snapshot.kind, "test");

        controls.started.await.expect("task starts");
        assert_eq!(
            registry.get(snapshot.id).expect("task").status,
            TaskStatus::Running {
                substate: serde_json::json!({ "step": 1 })
            }
        );

        let _ = controls.finish.send(Err(anyhow::anyhow!("boom")));
        assert_eq!(
            wait_for_final_status(&registry, snapshot.id).await,
            TaskStatus::Failed {
                error: "boom".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn success_carries_the_result() {
        let registry = registry(1, Duration::from_secs(60));
        let (task, controls) = test_task();

        let id = registry.spawn(task).id;
        let _ = controls.finish.send(Ok(42));

        assert_eq!(
            wait_for_final_status(&registry, id).await,
            TaskStatus::Success {
                result: serde_json::json!(42)
            }
        );
    }

    #[tokio::test]
    async fn concurrency_limit_keeps_extra_tasks_not_started() {
        let registry = registry(2, Duration::from_secs(60));
        let (first, first_controls) = test_task();
        let (second, second_controls) = test_task();
        let (third, mut third_controls) = test_task();

        let first_id = registry.spawn(first).id;
        let _second_id = registry.spawn(second).id;
        let third_id = registry.spawn(third).id;

        first_controls.started.await.expect("first starts");
        second_controls.started.await.expect("second starts");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(third_controls.started.try_recv().is_err());
        assert_eq!(registry.get(third_id).expect("task").status, TaskStatus::NotStarted);

        let _ = first_controls.finish.send(Ok(1));
        wait_for_final_status(&registry, first_id).await;

        third_controls.started.await.expect("third starts once a slot is free");
    }

    #[tokio::test]
    async fn task_times_out() {
        let registry = registry(1, Duration::from_millis(20));
        let (task, _controls) = test_task();

        let id = registry.spawn(task).id;

        assert_eq!(
            wait_for_final_status(&registry, id).await,
            TaskStatus::Failed {
                error: "task timed out".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn finished_task_is_removed_after_retention() {
        let registry = TaskRegistry::with_limits(Limits {
            max_concurrent: 1,
            timeout: Duration::from_secs(60),
            retention: Duration::from_millis(10),
        });
        let (task, controls) = test_task();

        let id = registry.spawn(task).id;
        let _ = controls.finish.send(Ok(1));

        tokio::time::timeout(Duration::from_secs(10), async {
            while registry.get(id).is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("task is removed");
    }

    #[test]
    fn unknown_task_is_none() {
        assert!(TaskRegistry::new().get(Uuid::new_v4()).is_none());
    }
}
