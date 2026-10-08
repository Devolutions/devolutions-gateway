//! The provisioner task table in `gateway.db`: one row per Task DVLS asked Gateway to run.
//!
//! The tables are named `provisioner_task_*`, and this crate alone creates and migrates them. Their schema version is
//! the `schema_version` row of `provisioner_task_metadata`, not the file's `PRAGMA user_version`, because other
//! features keep their own tables in the same file.

#[macro_use]
extern crate tracing;

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use libsql::{Connection, Row, TransactionBehavior, params};
use provisioner_task::{
    CreateOutcome, NewProvisionerTask, ProvisionerTask, ProvisionerTaskState, ProvisionerTaskStore,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Every schema change ever made to the `provisioner_task_*` tables, oldest first. Only ever append to it.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/01_provisioner_task.sql")];

const SCHEMA_VERSION_KEY: &str = "schema_version";

const COLUMNS: &str =
    "id, kind, target, params, state, payload, attempts, created_at, started_at, finished_at, deadline_at";

/// Tasks kept in the `provisioner_task_records` table of `gateway.db`.
pub struct LibSqlProvisionerTaskStore {
    conn: Mutex<Connection>,
}

impl LibSqlProvisionerTaskStore {
    /// Opens the store on a `gateway.db` connection of its own, from `GatewayDb::connect`.
    ///
    /// Opening creates the `provisioner_task_*` tables or brings them up to date.
    pub async fn open(conn: Connection) -> anyhow::Result<Self> {
        migrate(&conn).await?;

        Ok(Self { conn: Mutex::new(conn) })
    }

    async fn find(conn: &Connection, id: Uuid) -> anyhow::Result<Option<ProvisionerTask>> {
        conn.query(
            &format!("SELECT {COLUMNS} FROM provisioner_task_records WHERE id = ?1"),
            params![id.to_string()],
        )
        .await
        .context("query task")?
        .next()
        .await
        .context("read task")?
        .as_ref()
        .map(task_from_row)
        .transpose()
    }

    async fn find_unfinished(conn: &Connection, kind: &str, target: &str) -> anyhow::Result<Option<ProvisionerTask>> {
        conn.query(
            &format!(
                "SELECT {COLUMNS} FROM provisioner_task_records
                 WHERE kind = ?1 AND target = ?2 AND state IN ('queued', 'running')"
            ),
            params![kind, target],
        )
        .await
        .context("query unfinished task")?
        .next()
        .await
        .context("read unfinished task")?
        .as_ref()
        .map(task_from_row)
        .transpose()
    }

    /// Fails `task` if it is unfinished and past its deadline, then returns it as stored.
    async fn expire(conn: &Connection, task: ProvisionerTask, now: OffsetDateTime) -> anyhow::Result<ProvisionerTask> {
        if task.state.is_finished() || now < task.deadline_at {
            return Ok(task);
        }

        let payload = serde_json::json!({
            "reason": "timed out",
            "details": { "lastPayload": task.payload },
            "attempts": task.attempts,
        });

        conn.execute(
            "UPDATE provisioner_task_records SET state = 'failed', payload = ?2, finished_at = ?3
             WHERE id = ?1 AND state IN ('queued', 'running')",
            params![task.id.to_string(), payload.to_string(), now.unix_timestamp()],
        )
        .await
        .context("fail overdue task")?;

        warn!(task.id = %task.id, task.kind = %task.kind, attempts = task.attempts, "Task timed out");

        Self::find(conn, task.id).await?.context("overdue task is missing")
    }

    /// Ends the Task as `state` if it is currently in one of `from`, given as an SQL list such as `'running'`.
    ///
    /// A Task past its deadline is failed as timed out first, and then not ended again.
    async fn finish(
        &self,
        id: Uuid,
        from: &'static str,
        state: ProvisionerTaskState,
        payload: serde_json::Value,
        now: OffsetDateTime,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin task finish")?;

        let Some(task) = Self::find(&tx, id).await? else {
            return Ok(false);
        };
        Self::expire(&tx, task, now).await?;

        let changed = tx
            .execute(
                &format!(
                    "UPDATE provisioner_task_records SET state = ?2, payload = ?3, finished_at = ?4
                     WHERE id = ?1 AND state IN ({from})"
                ),
                params![
                    id.to_string(),
                    state.as_str(),
                    payload.to_string(),
                    now.unix_timestamp()
                ],
            )
            .await
            .context("finish task")?;
        tx.commit().await.context("commit task finish")?;

        Ok(changed == 1)
    }
}

#[async_trait]
impl ProvisionerTaskStore for LibSqlProvisionerTaskStore {
    async fn create(&self, task: NewProvisionerTask, now: OffsetDateTime) -> anyhow::Result<CreateOutcome> {
        let conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin task creation")?;

        if let Some(existing) = Self::find(&tx, task.id).await? {
            let existing = Self::expire(&tx, existing, now).await?;
            let same_request =
                existing.kind == task.kind && existing.target == task.target && existing.params == task.params;
            tx.commit().await.context("commit task lookup")?;

            return Ok(if same_request {
                CreateOutcome::Existing(existing)
            } else {
                CreateOutcome::IdConflict(existing)
            });
        }

        if let Some(unfinished) = Self::find_unfinished(&tx, &task.kind, &task.target).await? {
            let unfinished = Self::expire(&tx, unfinished, now).await?;

            if !unfinished.state.is_finished() {
                return Ok(CreateOutcome::TargetBusy(unfinished));
            }
        }

        tx.execute(
            "INSERT INTO provisioner_task_records (id, kind, target, params, state, payload, created_at, deadline_at)
             VALUES (?1, ?2, ?3, ?4, 'queued', 'null', ?5, ?6)",
            params![
                task.id.to_string(),
                task.kind.clone(),
                task.target.clone(),
                task.params.to_string(),
                now.unix_timestamp(),
                task.deadline_at.unix_timestamp(),
            ],
        )
        .await
        .context("insert task")?;

        let created = Self::find(&tx, task.id).await?.context("created task is missing")?;
        tx.commit().await.context("commit task creation")?;

        Ok(CreateOutcome::Created(created))
    }

    async fn get(&self, id: Uuid, now: OffsetDateTime) -> anyhow::Result<Option<ProvisionerTask>> {
        let conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin task lookup")?;

        let Some(task) = Self::find(&tx, id).await? else {
            return Ok(None);
        };
        let task = Self::expire(&tx, task, now).await?;
        tx.commit().await.context("commit task lookup")?;

        Ok(Some(task))
    }

    async fn start_attempt(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool> {
        let conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin task attempt")?;

        let Some(task) = Self::find(&tx, id).await? else {
            return Ok(false);
        };
        let task = Self::expire(&tx, task, now).await?;
        let runs = !task.state.is_finished();

        if runs {
            tx.execute(
                "UPDATE provisioner_task_records
                 SET state = 'running', payload = ?2, attempts = attempts + 1, started_at = COALESCE(started_at, ?3)
                 WHERE id = ?1",
                params![id.to_string(), payload.to_string(), now.unix_timestamp()],
            )
            .await
            .context("start task attempt")?;
        }

        tx.commit().await.context("commit task attempt")?;

        Ok(runs)
    }

    async fn update_running(&self, id: Uuid, payload: serde_json::Value) -> anyhow::Result<bool> {
        let conn = self.conn.lock().await;
        let changed = conn
            .execute(
                "UPDATE provisioner_task_records SET payload = ?2 WHERE id = ?1 AND state = 'running'",
                params![id.to_string(), payload.to_string()],
            )
            .await
            .context("update running task")?;

        Ok(changed == 1)
    }

    async fn succeed(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool> {
        self.finish(id, "'running'", ProvisionerTaskState::Succeeded, payload, now)
            .await
    }

    async fn fail(&self, id: Uuid, payload: serde_json::Value, now: OffsetDateTime) -> anyhow::Result<bool> {
        self.finish(id, "'queued', 'running'", ProvisionerTaskState::Failed, payload, now)
            .await
    }
}

fn task_from_row(row: &Row) -> anyhow::Result<ProvisionerTask> {
    let timestamp = |index: i32, name: &str| -> anyhow::Result<OffsetDateTime> {
        let seconds = row.get::<i64>(index).with_context(|| format!("decode task {name}"))?;
        OffsetDateTime::from_unix_timestamp(seconds).with_context(|| format!("invalid task {name}"))
    };
    let optional_timestamp = |index: i32, name: &str| -> anyhow::Result<Option<OffsetDateTime>> {
        row.get::<Option<i64>>(index)
            .with_context(|| format!("decode task {name}"))?
            .map(|seconds| OffsetDateTime::from_unix_timestamp(seconds).with_context(|| format!("invalid task {name}")))
            .transpose()
    };
    let json = |index: i32, name: &str| -> anyhow::Result<serde_json::Value> {
        let text = row
            .get::<String>(index)
            .with_context(|| format!("decode task {name}"))?;
        serde_json::from_str(&text).with_context(|| format!("parse task {name}"))
    };

    Ok(ProvisionerTask {
        id: row
            .get::<String>(0)
            .context("decode task id")?
            .parse()
            .context("parse task id")?,
        kind: row.get::<String>(1).context("decode task kind")?,
        target: row.get::<String>(2).context("decode task target")?,
        params: json(3, "params")?,
        state: row
            .get::<String>(4)
            .context("decode task state")?
            .parse()
            .context("parse task state")?,
        payload: json(5, "payload")?,
        attempts: u32::try_from(row.get::<i64>(6).context("decode task attempts")?).context("invalid task attempts")?,
        created_at: timestamp(7, "creation time")?,
        started_at: optional_timestamp(8, "start time")?,
        finished_at: optional_timestamp(9, "finish time")?,
        deadline_at: timestamp(10, "deadline")?,
    })
}

/// Creates the `provisioner_task_*` tables or brings them up to date.
async fn migrate(conn: &Connection) -> anyhow::Result<()> {
    loop {
        // Another connection may migrate at the same time, so the version is read under the write lock.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .context("begin provisioner task migration")?;
        let version = schema_version(&tx).await?;

        let Some(migration) = MIGRATIONS.get(version) else {
            tx.rollback().await.context("end provisioner task migration")?;

            if MIGRATIONS.len() < version {
                bail!(
                    "provisioner task schema version {version} is newer than supported version {}",
                    MIGRATIONS.len()
                );
            }

            return Ok(());
        };

        let version = version + 1;
        tx.execute_batch(migration)
            .await
            .with_context(|| format!("apply provisioner task migration {version}"))?;
        tx.execute(
            "INSERT OR REPLACE INTO provisioner_task_metadata (key, value) VALUES (?1, ?2)",
            params![SCHEMA_VERSION_KEY, i64::try_from(version)?],
        )
        .await
        .with_context(|| format!("record provisioner task migration {version}"))?;
        tx.commit()
            .await
            .with_context(|| format!("commit provisioner task migration {version}"))?;
    }
}

/// Reads the version of the `provisioner_task_*` tables; 0 when there are none yet.
async fn schema_version(conn: &Connection) -> anyhow::Result<usize> {
    let metadata_exists = conn
        .query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'provisioner_task_metadata'",
            (),
        )
        .await
        .context("look for the provisioner task tables")?
        .next()
        .await
        .context("read the provisioner task tables")?
        .is_some();

    if !metadata_exists {
        return Ok(0);
    }

    let version = conn
        .query(
            "SELECT value FROM provisioner_task_metadata WHERE key = ?1",
            params![SCHEMA_VERSION_KEY],
        )
        .await
        .context("query provisioner task schema version")?
        .next()
        .await
        .context("read provisioner task schema version")?
        .context("provisioner task tables have no schema version")?
        .get::<i64>(0)
        .context("decode provisioner task schema version")?;

    usize::try_from(version).context("provisioner task schema version is out of range")
}
#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    async fn store() -> LibSqlProvisionerTaskStore {
        let conn = gateway_db::GatewayDb::open_path(":memory:")
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect to gateway database");
        LibSqlProvisionerTaskStore::open(conn)
            .await
            .expect("open provisioner task store")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp")
    }

    fn new_task(target: &str) -> NewProvisionerTask {
        NewProvisionerTask {
            id: Uuid::new_v4(),
            kind: String::from("recording.ai-analysis"),
            target: String::from(target),
            params: serde_json::json!({ "provider": "openai", "model": "gpt-6-luna" }),
            deadline_at: now() + Duration::hours(2),
        }
    }

    async fn create(store: &LibSqlProvisionerTaskStore, task: NewProvisionerTask) -> CreateOutcome {
        store.create(task, now()).await.expect("create task")
    }

    #[tokio::test]
    async fn created_task_is_queued() {
        let store = store().await;
        let task = new_task("session-1");

        let CreateOutcome::Created(created) = create(&store, task.clone()).await else {
            panic!("task must be created");
        };

        assert_eq!(created.state, ProvisionerTaskState::Queued);
        assert_eq!(created.attempts, 0);
        assert_eq!(created.params, task.params);
        assert_eq!(store.get(task.id, now()).await.expect("get task"), Some(created));
    }

    #[tokio::test]
    async fn same_request_again_returns_the_existing_task() {
        let store = store().await;
        let task = new_task("session-1");
        create(&store, task.clone()).await;

        assert!(matches!(create(&store, task).await, CreateOutcome::Existing(_)));
    }

    #[tokio::test]
    async fn same_id_with_other_parameters_conflicts() {
        let store = store().await;
        let task = new_task("session-1");
        create(&store, task.clone()).await;

        let mut other = task;
        other.params = serde_json::json!({ "provider": "anthropic" });

        assert!(matches!(create(&store, other).await, CreateOutcome::IdConflict(_)));
    }

    #[tokio::test]
    async fn one_unfinished_task_per_kind_and_target() {
        let store = store().await;
        let first = new_task("session-1");
        create(&store, first.clone()).await;

        let CreateOutcome::TargetBusy(busy) = create(&store, new_task("session-1")).await else {
            panic!("target must be busy");
        };
        assert_eq!(busy.id, first.id);
        assert!(matches!(
            create(&store, new_task("session-2")).await,
            CreateOutcome::Created(_)
        ));

        store
            .fail(first.id, serde_json::json!({}), now())
            .await
            .expect("finish task");
        assert!(matches!(
            create(&store, new_task("session-1")).await,
            CreateOutcome::Created(_)
        ));
    }

    #[tokio::test]
    async fn only_a_running_task_succeeds() {
        let store = store().await;
        let task = new_task("session-1");
        create(&store, task.clone()).await;

        assert!(
            !store
                .succeed(task.id, serde_json::json!({}), now())
                .await
                .expect("succeed queued task")
        );
        assert_eq!(
            store.get(task.id, now()).await.expect("get task").expect("task").state,
            ProvisionerTaskState::Queued
        );

        assert!(
            store
                .fail(task.id, serde_json::json!({ "reason": "not queued" }), now())
                .await
                .expect("fail queued task")
        );
        assert_eq!(
            store.get(task.id, now()).await.expect("get task").expect("task").state,
            ProvisionerTaskState::Failed
        );
    }

    #[tokio::test]
    async fn overdue_task_is_failed_and_frees_its_target() {
        let store = store().await;
        let mut overdue = new_task("session-1");
        overdue.deadline_at = now() - Duration::minutes(1);
        create(&store, overdue.clone()).await;
        store
            .start_attempt(
                overdue.id,
                serde_json::json!({ "done": 3, "total": 10 }),
                now() - Duration::minutes(2),
            )
            .await
            .expect("start attempt");

        assert!(matches!(
            create(&store, new_task("session-1")).await,
            CreateOutcome::Created(_)
        ));

        let failed = store
            .get(overdue.id, now())
            .await
            .expect("get task")
            .expect("task exists");
        assert_eq!(failed.state, ProvisionerTaskState::Failed);
        assert_eq!(failed.payload["reason"], "timed out");
        assert_eq!(failed.payload["attempts"], 1);
        assert_eq!(failed.payload["details"]["lastPayload"]["done"], 3);
    }

    #[tokio::test]
    async fn attempts_running_payload_and_finish() {
        let store = store().await;
        let task = new_task("session-1");
        create(&store, task.clone()).await;

        assert!(
            store
                .start_attempt(task.id, serde_json::json!({ "done": 0 }), now())
                .await
                .expect("start")
        );
        assert!(
            store
                .update_running(task.id, serde_json::json!({ "done": 1 }))
                .await
                .expect("update")
        );
        assert!(
            store
                .start_attempt(task.id, serde_json::json!({ "done": 1 }), now())
                .await
                .expect("retry")
        );

        let running = store.get(task.id, now()).await.expect("get task").expect("task exists");
        assert_eq!(running.state, ProvisionerTaskState::Running);
        assert_eq!(running.attempts, 2);
        assert_eq!(running.started_at, Some(now()));

        assert!(
            store
                .fail(task.id, serde_json::json!({ "reason": "boom" }), now())
                .await
                .expect("finish")
        );
        assert!(
            !store
                .succeed(task.id, serde_json::json!({}), now())
                .await
                .expect("finish again")
        );
        assert!(
            !store
                .start_attempt(task.id, serde_json::json!({}), now())
                .await
                .expect("start after finish")
        );
        assert!(
            !store
                .update_running(task.id, serde_json::json!({}))
                .await
                .expect("update after finish")
        );

        let finished = store.get(task.id, now()).await.expect("get task").expect("task exists");
        assert_eq!(finished.state, ProvisionerTaskState::Failed);
        assert_eq!(finished.payload["reason"], "boom");
        assert_eq!(finished.finished_at, Some(now()));
    }

    #[tokio::test]
    async fn running_task_succeeds_with_its_result() {
        let store = store().await;
        let task = new_task("session-1");
        create(&store, task.clone()).await;
        store
            .start_attempt(task.id, serde_json::json!({ "done": 0 }), now())
            .await
            .expect("start");

        assert!(
            store
                .succeed(task.id, serde_json::json!({ "log": "ai-analysis-0.slog" }), now())
                .await
                .expect("succeed")
        );

        let succeeded = store.get(task.id, now()).await.expect("get task").expect("task exists");
        assert_eq!(succeeded.state, ProvisionerTaskState::Succeeded);
        assert_eq!(succeeded.payload["log"], "ai-analysis-0.slog");
        assert_eq!(succeeded.finished_at, Some(now()));
    }

    #[tokio::test]
    async fn overdue_task_cannot_succeed_or_fail_with_another_reason() {
        let store = store().await;
        let mut overdue = new_task("session-1");
        overdue.deadline_at = now() + Duration::minutes(1);
        create(&store, overdue.clone()).await;
        store
            .start_attempt(overdue.id, serde_json::json!({ "done": 3 }), now())
            .await
            .expect("start");
        let late = now() + Duration::minutes(2);

        assert!(
            !store
                .succeed(overdue.id, serde_json::json!({ "log": "late" }), late)
                .await
                .expect("succeed late")
        );
        assert!(
            !store
                .fail(overdue.id, serde_json::json!({ "reason": "boom" }), late)
                .await
                .expect("fail late")
        );

        let failed = store
            .get(overdue.id, late)
            .await
            .expect("get task")
            .expect("task exists");
        assert_eq!(failed.state, ProvisionerTaskState::Failed);
        assert_eq!(failed.payload["reason"], "timed out");
        assert_eq!(failed.payload["details"]["lastPayload"]["done"], 3);
    }

    #[tokio::test]
    async fn overdue_task_is_failed_when_read_or_started() {
        let store = store().await;
        let mut overdue = new_task("session-1");
        overdue.deadline_at = now() - Duration::minutes(1);
        create(&store, overdue.clone()).await;

        assert!(
            !store
                .start_attempt(overdue.id, serde_json::json!({}), now())
                .await
                .expect("start attempt")
        );
        let read = store
            .get(overdue.id, now())
            .await
            .expect("get task")
            .expect("task exists");
        assert_eq!(read.state, ProvisionerTaskState::Failed);
        assert_eq!(read.payload["reason"], "timed out");

        let CreateOutcome::Existing(again) = create(&store, overdue).await else {
            panic!("same request must return the existing task");
        };
        assert_eq!(again.state, ProvisionerTaskState::Failed);
    }

    #[tokio::test]
    async fn unknown_task() {
        let store = store().await;

        assert_eq!(store.get(Uuid::new_v4(), now()).await.expect("get task"), None);
        assert!(
            !store
                .start_attempt(Uuid::new_v4(), serde_json::json!({}), now())
                .await
                .expect("start attempt")
        );
    }

    #[tokio::test]
    async fn new_tables_record_their_schema_version_in_metadata() {
        let store = store().await;
        let conn = store.conn.lock().await;

        assert_eq!(
            schema_version(&conn).await.expect("read schema version"),
            MIGRATIONS.len()
        );
    }

    #[tokio::test]
    async fn newer_schema_is_rejected() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let path = temp_dir.path().join("gateway.db");
        let db = gateway_db::GatewayDb::open_path(path.to_str().expect("temporary path is UTF-8"))
            .await
            .expect("open gateway database");
        drop(
            LibSqlProvisionerTaskStore::open(db.connect().await.expect("connect"))
                .await
                .expect("open provisioner task store"),
        );
        let conn = db.connect().await.expect("connect");
        conn.execute(
            "UPDATE provisioner_task_metadata SET value = 99 WHERE key = ?1",
            params![SCHEMA_VERSION_KEY],
        )
        .await
        .expect("set unsupported schema version");

        let error = LibSqlProvisionerTaskStore::open(conn)
            .await
            .err()
            .expect("newer schema must be rejected");
        assert!(error.to_string().contains("newer than supported"));
    }
}
