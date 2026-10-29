use std::sync::atomic::{AtomicUsize, Ordering};

use job_queue::Job as _;
use parking_lot::Mutex;
use provisioner_task::{ProvisionerTaskState, ProvisionerTaskStore};
use serde_json::json;

use super::*;
use crate::job_queue::{StoredJob, TestJobQueue};

const KIND: &str = "test.echo";

/// A value whose attempt waits until it is cancelled.
const HANG: u32 = u32::MAX;

/// A value whose attempt reports progress five times, half a second apart, then succeeds.
const PROGRESS: u32 = u32::MAX - 1;

/// Why an Echo attempt fails for good.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum EchoFailure {
    /// What the attempt needed is gone, as a secret kept in memory is after a restart.
    Gone,
}

/// Why an Echo attempt fails for now.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum EchoRecoverable {
    Busy,
}

type EchoError = AttemptError<EchoFailure, EchoRecoverable>;

#[derive(Debug, Serialize, serde::Deserialize)]
struct EchoParams {
    value: u32,
}

/// A task whose attempts return `outcome`, counting its runs and the records it ended.
struct Echo {
    outcome: fn(u32) -> Result<serde_json::Value, EchoError>,
    progress_timeout: time::Duration,
    runs: Arc<AtomicUsize>,
    ended: Arc<Mutex<Vec<Uuid>>>,
    /// Ends that fail before one succeeds.
    end_failures: Arc<AtomicUsize>,
    /// Why its unfinished records fail when Gateway starts again.
    restart_failure: Option<EchoFailure>,
}

#[async_trait]
impl ProvisionerTask for Echo {
    const KIND: &'static str = KIND;

    type Params = EchoParams;

    type Output = serde_json::Value;

    type Failure = EchoFailure;

    type Recoverable = EchoRecoverable;

    fn start_window(&self) -> time::Duration {
        time::Duration::hours(1)
    }

    fn progress_timeout(&self) -> time::Duration {
        self.progress_timeout
    }

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value {
        json!({ "after": last })
    }

    fn failed_payload(
        &self,
        error: &Permanent<EchoFailure, EchoRecoverable>,
        last: &serde_json::Value,
    ) -> serde_json::Value {
        json!({ "error": error, "last": last })
    }

    fn restart_failure(&self) -> Option<EchoFailure> {
        self.restart_failure.clone()
    }

    async fn run(&self, attempt: &Attempt, params: EchoParams) -> Result<serde_json::Value, EchoError> {
        self.runs.fetch_add(1, Ordering::SeqCst);

        match params.value {
            HANG => {
                attempt.cancel.cancelled().await;
                Err(AttemptError::Recoverable(EchoRecoverable::Busy))
            }
            PROGRESS => {
                // 4 s of work outlasts the first deadline, 2 to 3 s away, so only the progress keeps the attempt running.
                for step in 0..8 {
                    tokio::select! {
                        () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                        () = attempt.cancel.cancelled() => return Err(AttemptError::Recoverable(EchoRecoverable::Busy)),
                    }
                    attempt.report_progress(json!({ "step": step })).await;
                }
                Ok(json!("done"))
            }
            value => (self.outcome)(value),
        }
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        if self
            .end_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
            .is_ok()
        {
            anyhow::bail!("the end failed");
        }

        self.ended.lock().push(record.id);
        Ok(())
    }
}

/// The task store, failing to record an end when asked, as a database that is briefly unavailable does.
struct FailingStore {
    inner: provisioner_task_libsql::LibSqlProvisionerTaskStore,
    /// Successes that fail to be recorded before one is.
    success_failures: Arc<AtomicUsize>,
    /// Failures that fail to be recorded before one is.
    failure_failures: Arc<AtomicUsize>,
}

/// Whether one more of the `failures` left happens, counting it.
fn fails(failures: &AtomicUsize) -> bool {
    failures
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
        .is_ok()
}

#[async_trait]
impl ProvisionerTaskStore for FailingStore {
    async fn create(&self, task: NewProvisionerTaskRecord, now: OffsetDateTime) -> anyhow::Result<CreateOutcome> {
        self.inner.create(task, now).await
    }

    async fn get(&self, id: Uuid, now: OffsetDateTime) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
        self.inner.get(id, now).await
    }

    async fn start_attempt(
        &self,
        id: Uuid,
        job_token: Uuid,
        payload: serde_json::Value,
        deadline_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> anyhow::Result<AttemptStart> {
        self.inner.start_attempt(id, job_token, payload, deadline_at, now).await
    }

    async fn replace_job_token(&self, id: Uuid, job_token: Uuid, now: OffsetDateTime) -> anyhow::Result<bool> {
        self.inner.replace_job_token(id, job_token, now).await
    }

    async fn list_unfinished(&self, now: OffsetDateTime) -> anyhow::Result<Vec<ProvisionerTaskRecord>> {
        self.inner.list_unfinished(now).await
    }

    async fn update_running(
        &self,
        id: Uuid,
        payload: serde_json::Value,
        deadline_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> anyhow::Result<bool> {
        self.inner.update_running(id, payload, deadline_at, now).await
    }

    async fn succeed(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool> {
        if fails(&self.success_failures) {
            anyhow::bail!("the success could not be recorded");
        }

        self.inner.succeed(id, payload, now).await
    }

    async fn fail(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool> {
        if fails(&self.failure_failures) {
            anyhow::bail!("the failure could not be recorded");
        }

        self.inner.fail(id, payload, now).await
    }
}

struct Harness {
    manager: ProvisionerTaskManager<Echo>,
    job_queue: Arc<TestJobQueue>,
    runs: Arc<AtomicUsize>,
    ended: Arc<Mutex<Vec<Uuid>>>,
    end_failures: Arc<AtomicUsize>,
    success_failures: Arc<AtomicUsize>,
    failure_failures: Arc<AtomicUsize>,
}

impl Harness {
    async fn new(outcome: fn(u32) -> Result<serde_json::Value, EchoError>) -> Self {
        Self::with_progress_timeout(outcome, time::Duration::hours(1)).await
    }

    async fn with_progress_timeout(
        outcome: fn(u32) -> Result<serde_json::Value, EchoError>,
        progress_timeout: time::Duration,
    ) -> Self {
        Self::build(outcome, progress_timeout, None).await
    }

    async fn build(
        outcome: fn(u32) -> Result<serde_json::Value, EchoError>,
        progress_timeout: time::Duration,
        restart_failure: Option<EchoFailure>,
    ) -> Self {
        let conn = gateway_db::GatewayDb::open_path(":memory:")
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect");
        let success_failures = Arc::new(AtomicUsize::new(0));
        let failure_failures = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(FailingStore {
            inner: provisioner_task_libsql::LibSqlProvisionerTaskStore::open(conn)
                .await
                .expect("open task store"),
            success_failures: Arc::clone(&success_failures),
            failure_failures: Arc::clone(&failure_failures),
        });
        let job_queue = TestJobQueue::new().await;
        let runs = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(Mutex::new(Vec::new()));
        let end_failures = Arc::new(AtomicUsize::new(0));

        let manager = ProvisionerTaskManager::new(
            Echo {
                outcome,
                progress_timeout,
                runs: Arc::clone(&runs),
                ended: Arc::clone(&ended),
                end_failures: Arc::clone(&end_failures),
                restart_failure,
            },
            store,
            job_queue.durable(),
        );

        Self {
            manager,
            job_queue,
            runs,
            ended,
            end_failures,
            success_failures,
            failure_failures,
        }
    }

    async fn create(&self, value: u32) -> Uuid {
        let id = Uuid::new_v4();
        let outcome = self
            .manager
            .create(id, format!("target-{id}"), &EchoParams { value }, |_| Ok(()))
            .await
            .expect("create");
        assert!(matches!(outcome, CreateOutcome::Created(_)), "{outcome:?}");
        id
    }

    /// Takes the oldest queued job, read back as the job runner reads it, with when it runs.
    fn queued(&mut self) -> Option<(Box<dyn job_queue::Job>, Option<OffsetDateTime>)> {
        let StoredJob {
            name,
            json,
            schedule_for,
        } = self.job_queue.take()?;
        assert_eq!(name, KIND);
        let job: Box<dyn job_queue::Job> = Box::new(
            TaskJob::<Echo>::read_json(&json)
                .expect("valid job")
                .into_job(self.manager.clone()),
        );
        Some((job, schedule_for))
    }

    fn queued_job(&mut self) -> Box<dyn job_queue::Job> {
        self.queued().expect("a queued job").0
    }

    /// Takes every queued job.
    fn queued_jobs(&mut self) -> Vec<StoredJob> {
        std::iter::from_fn(|| self.job_queue.take()).collect()
    }

    async fn task(&self, id: Uuid) -> ProvisionerTaskRecord {
        self.manager
            .get(id, OffsetDateTime::now_utc())
            .await
            .expect("read task")
            .expect("task exists")
    }
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn only_a_new_task_runs_on_created_and_gets_a_job() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();
    let created = AtomicUsize::new(0);
    let create = || {
        harness
            .manager
            .create(id, "target".to_owned(), &EchoParams { value: 1 }, |_| {
                created.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
    };

    assert!(matches!(create().await.expect("create"), CreateOutcome::Created(_)));
    assert!(matches!(create().await.expect("again"), CreateOutcome::Existing(_)));

    assert_eq!(created.load(Ordering::SeqCst), 1);
    harness.queued_job();
    assert!(harness.job_queue.take().is_none(), "one job only");
}

// oracle: mutant a job that cannot be queued is ignored, so the Task stays queued and its creation succeeds
#[tokio::test]
async fn a_task_whose_job_cannot_be_queued_fails() {
    let harness = Harness::new(|value| Ok(json!(value))).await;
    harness.job_queue.close();
    let id = Uuid::new_v4();

    harness
        .manager
        .create(id, "target".to_owned(), &EchoParams { value: 1 }, |_| Ok(()))
        .await
        .expect_err("the job queue is gone");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload, json!({ "error": { "kind": "notQueued" }, "last": null }));
    assert_eq!(*harness.ended.lock(), [id], "what was set up for the Task is dropped");
}

// oracle: mutant the job is queued before the Task is prepared, so a Task that cannot be prepared still gets a job
#[tokio::test]
async fn a_task_that_cannot_be_prepared_fails_without_a_job() {
    let harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();

    harness
        .manager
        .create(id, "target".to_owned(), &EchoParams { value: 1 }, |_| {
            anyhow::bail!("no room for the secret")
        })
        .await
        .expect_err("preparing fails");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "notQueued" }));
    assert!(harness.job_queue.take().is_none(), "no job is queued");
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_superseded_job_runs_nothing_once_the_task_is_resumed() {
    let mut harness = Harness::new(|value| Ok(json!({ "echo": value }))).await;
    let id = harness.create(7).await;
    let mut stale = harness.queued_job();

    harness.manager.resume().await.expect("resume");
    let mut resumed = harness.queued_job();
    assert!(
        harness.job_queue.take().is_none(),
        "the unfinished Task gets one new job"
    );

    stale.run().await.expect("the stale job stops");
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
    assert_eq!(harness.task(id).await.attempts, 0, "a stale job counts no attempt");
    assert!(harness.ended.lock().is_empty(), "a stale job ends nothing");

    resumed.run().await.expect("the new job runs");
    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded);
    assert_eq!(task.payload, json!({ "echo": 7 }));
    assert_eq!(*harness.ended.lock(), [id]);

    harness.manager.resume().await.expect("resume again");
    assert!(harness.job_queue.take().is_none(), "a finished Task gets no new job");
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_task_that_cannot_be_queued_again_fails() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    harness.queued_job();
    harness.job_queue.close();

    harness.manager.resume().await.expect("resume");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed, "no job is left to run it");
    assert_eq!(task.payload["error"], json!({ "kind": "notQueued" }));
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: mutant resume skips a Task whose job may still be stored, so a Task created just before a crash never runs
#[tokio::test]
async fn resume_gives_every_unfinished_task_a_new_job() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let first = harness.create(1).await;
    let second = harness.create(2).await;
    let tokens = [
        harness.task(first).await.job_token,
        harness.task(second).await.job_token,
    ];
    // The jobs of the creation may be stored or lost; the manager never asks which.
    harness.queued_jobs();

    harness.manager.resume().await.expect("resume");

    assert_eq!(harness.queued_jobs().len(), 2, "one new job for each unfinished Task");
    assert_ne!(harness.task(first).await.job_token, tokens[0]);
    assert_ne!(harness.task(second).await.job_token, tokens[1]);
}

// oracle: mutant a Task that cannot outlive a restart stays unfinished until a job runs it
#[tokio::test]
async fn a_task_that_cannot_outlive_a_restart_fails_at_startup_and_is_ended() {
    let mut harness = Harness::build(
        |value| Ok(json!(value)),
        time::Duration::hours(1),
        Some(EchoFailure::Gone),
    )
    .await;
    let id = harness.create(1).await;
    let mut stale = harness.queued_job();

    harness.manager.resume().await.expect("resume");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed, "it fails before any job runs");
    assert_eq!(task.payload, json!({ "error": { "kind": "gone" }, "last": null }));

    let mut ending = harness.queued_job();
    stale.run().await.expect("the stale job stops");
    assert!(harness.ended.lock().is_empty(), "a stale job ends nothing");

    ending.run().await.expect("the new job ends the Task");
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0, "no attempt runs");
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: mutant a Task whose failure at startup cannot be recorded gets no new job, so nothing ends it
#[tokio::test]
async fn a_task_whose_restart_failure_cannot_be_recorded_still_gets_a_new_job() {
    let mut harness = Harness::build(
        |value| Ok(json!(value)),
        time::Duration::hours(1),
        Some(EchoFailure::Gone),
    )
    .await;
    let id = harness.create(1).await;
    let token = harness.task(id).await.job_token;
    harness.queued_jobs();
    harness.failure_failures.store(1, Ordering::SeqCst);

    harness.manager.resume().await.expect("resume");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Queued, "the failure was not recorded");
    assert_ne!(task.job_token, token);
    assert_eq!(harness.queued_jobs().len(), 1, "its new job runs it");
}

// oracle: mutant resume resets the attempts of a Task, so a Task that fails at each restart is retried forever
#[tokio::test]
async fn resume_keeps_the_attempts_a_task_made() {
    let mut harness = Harness::new(|_| Err(AttemptError::Recoverable(EchoRecoverable::Busy))).await;
    let id = harness.create(1).await;
    harness
        .queued_job()
        .run()
        .await
        .expect_err("the job queue runs the job again");

    harness.manager.resume().await.expect("resume");
    harness
        .queued_job()
        .run()
        .await
        .expect_err("the job queue runs the job again");

    assert_eq!(harness.task(id).await.attempts, 2);
}

// oracle: mutant a panicking attempt fails the Task as internal instead of panicked
#[tokio::test]
async fn a_panicking_attempt_fails_the_task() {
    let mut harness = Harness::new(|_| panic!("the attempt panics")).await;
    let id = harness.create(1).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(
        task.payload,
        json!({ "error": { "kind": "panicked" }, "last": { "after": null } }),
        "the failure keeps what the attempt started with"
    );
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_permanent_failure_fails_the_task_at_once() {
    let mut harness = Harness::new(|_| Err(AttemptError::of_kind(EchoFailure::Gone))).await;
    let id = harness.create(1).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, 1);
    assert_eq!(task.payload["error"], json!({ "kind": "gone" }));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_recoverable_failure_is_retried_up_to_the_last_attempt() {
    let mut harness = Harness::new(|_| Err(AttemptError::Recoverable(EchoRecoverable::Busy))).await;
    let id = harness.create(1).await;
    let mut job = harness.queued_job();

    for attempt in 1..MAX_ATTEMPTS {
        job.run().await.expect_err("the job queue runs the job again");

        let task = harness.task(id).await;
        assert_eq!(task.state, ProvisionerTaskState::Running, "{attempt}");
        assert!(
            harness.job_queue.take().is_none(),
            "the job queue runs the same job again"
        );
    }
    job.run().await.expect("the last attempt");
    assert!(harness.job_queue.take().is_none(), "no attempt after the last");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, MAX_ATTEMPTS);
    assert_eq!(
        task.payload["error"],
        json!({ "kind": "attemptsExhausted", "last": { "kind": "busy" } })
    );
}

// oracle: mutant a success that cannot be recorded is retried, so the work is done and paid for twice
#[tokio::test]
async fn a_success_that_cannot_be_recorded_fails_the_task_instead_of_running_again() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    harness.success_failures.store(1, Ordering::SeqCst);

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "internal" }));
    assert_eq!(harness.runs.load(Ordering::SeqCst), 1, "the work is not done again");
    assert_eq!(*harness.ended.lock(), [id]);
    assert!(harness.job_queue.take().is_none(), "no job is left");
}

// oracle: mutant an end that cannot be recorded goes back to the job queue, which runs the attempt again
#[tokio::test]
async fn an_end_that_cannot_be_recorded_is_left_to_a_job_past_the_deadline() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    harness.success_failures.store(1, Ordering::SeqCst);
    harness.failure_failures.store(1, Ordering::SeqCst);

    harness
        .queued_job()
        .run()
        .await
        .expect("nothing goes back to the job queue");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Running, "nothing could be recorded");
    assert_eq!(harness.runs.load(Ordering::SeqCst), 1);
    assert!(
        harness.ended.lock().is_empty(),
        "nothing is dropped while the Task may still run"
    );
    let (_, schedule_for) = harness.queued().expect("a job ends it later");
    assert!(
        schedule_for.is_some_and(|at| task.deadline_at < at),
        "the job runs once the store fails the Task"
    );
}

// oracle: mutant an end that can be neither recorded nor queued returns an error, so the job queue redoes the paid work
#[tokio::test]
async fn a_task_whose_end_cannot_be_recorded_or_queued_is_not_retried() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let mut job = harness.queued_job();
    harness.job_queue.close();
    harness.success_failures.store(1, Ordering::SeqCst);
    harness.failure_failures.store(1, Ordering::SeqCst);

    job.run().await.expect("the job queue does not run the attempt again");

    assert_eq!(harness.runs.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.task(id).await.state,
        ProvisionerTaskState::Running,
        "the store fails it at its deadline"
    );
}

// oracle: mutant the prelude starts an attempt whatever the attempts made, so a Task runs one attempt past the last
#[tokio::test]
async fn a_last_attempt_whose_failure_cannot_be_recorded_is_not_run_again() {
    let mut harness = Harness::new(|_| Err(AttemptError::Recoverable(EchoRecoverable::Busy))).await;
    let id = harness.create(1).await;
    let mut job = harness.queued_job();
    for _ in 1..MAX_ATTEMPTS {
        job.run().await.expect_err("the job queue runs the job again");
    }
    harness.failure_failures.store(1, Ordering::SeqCst);

    job.run().await.expect("its end is left to a job past the deadline");
    let task = harness.task(id).await;
    assert_eq!(
        task.state,
        ProvisionerTaskState::Running,
        "the failure was not recorded"
    );
    let (_, schedule_for) = harness.queued().expect("a job ends it later");
    assert!(schedule_for.is_some_and(|at| task.deadline_at < at));

    // As if Gateway stopped before the deadline, so a new job finds the Task still running.
    harness.manager.resume().await.expect("resume");
    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(
        harness.runs.load(Ordering::SeqCst),
        usize::try_from(MAX_ATTEMPTS).expect("a few attempts"),
        "no attempt past the last"
    );
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "internal" }));
}

// oracle: mutant a Task whose parameters cannot be read runs its attempt, or stays unfinished
#[tokio::test]
async fn invalid_parameters_fail_the_task() {
    let harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();
    let job_token = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    harness
        .manager
        .store()
        .create(
            NewProvisionerTaskRecord {
                id,
                kind: KIND.to_owned(),
                target: id.to_string(),
                params: json!({ "value": "not a number" }),
                deadline_at: now + time::Duration::hours(1),
                job_token,
            },
            now,
        )
        .await
        .expect("create");
    let json = json!({ "taskId": id, "jobToken": job_token }).to_string();
    let mut job = TaskJob::<Echo>::read_json(&json)
        .expect("valid job")
        .into_job(harness.manager.clone());

    job.run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "invalidTask" }));
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn an_end_that_fails_is_done_again_by_a_new_job_until_it_succeeds() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let mut job = harness.queued_job();
    harness.end_failures.store(2, Ordering::SeqCst);

    for _ in 0..2 {
        job.run().await.expect("the end is left to a new job");

        let (next, schedule_for) = harness.queued().expect("a new job");
        assert!(
            schedule_for.is_some_and(|at| OffsetDateTime::now_utc() < at),
            "it runs later"
        );
        assert!(harness.ended.lock().is_empty());
        job = next;
    }

    job.run().await.expect("the end succeeds");

    assert_eq!(harness.task(id).await.state, ProvisionerTaskState::Succeeded);
    assert_eq!(*harness.ended.lock(), [id]);
    assert!(harness.job_queue.take().is_none(), "no job is left");
}

// oracle: intent crates/provisioner-task/INTENT.md §Invariants
#[tokio::test]
async fn an_attempt_without_progress_is_cancelled_at_the_deadline() {
    let mut harness = Harness::with_progress_timeout(|value| Ok(json!(value)), time::Duration::seconds(2)).await;
    let id = harness.create(HANG).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "deadlinePassed" }));
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: intent crates/provisioner-task/INTENT.md §Invariants
#[tokio::test]
async fn progress_keeps_an_attempt_running_past_its_first_deadline() {
    let mut harness = Harness::with_progress_timeout(|value| Ok(json!(value)), time::Duration::seconds(3)).await;
    let id = harness.create(PROGRESS).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded, "{:?}", task.payload);
    assert_eq!(task.payload, json!("done"));
}

// oracle: property round-trip
#[tokio::test]
async fn the_job_is_read_back_from_its_json() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let job = harness.queued_job();

    let json = job.write_json().expect("job JSON");
    let read = TaskJob::<Echo>::read_json(&json)
        .expect("valid job")
        .into_job(harness.manager.clone());

    assert_eq!(read.task_id, id);
    assert_eq!(read.job_token, harness.task(id).await.job_token);
    assert_eq!(job.name(), KIND);
}
