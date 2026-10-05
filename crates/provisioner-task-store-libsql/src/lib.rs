//! Records of the background tasks started by the provisioner (DVLS), stored in a libSQL database.
//!
//! Rows are never deleted, so the records can be audited later.

#[macro_use]
extern crate tracing;

use anyhow::Context as _;
use libsql::{Connection, Row, TransactionBehavior};
use uuid::Uuid;

// Released migrations are never modified; new ones are appended.
// The job queue in the same database owns `PRAGMA user_version`, so this schema keeps its version in a table.
const MIGRATIONS: &[&str] = &[
    // Migration 0
    "CREATE TABLE task (
        id TEXT NOT NULL PRIMARY KEY,
        kind TEXT NOT NULL,
        target BLOB NOT NULL,
        params BLOB NOT NULL,
        state INT NOT NULL CHECK (state IN (0, 1, 2, 3)),
        substate BLOB NULL,
        result BLOB NULL,
        error TEXT NULL,
        attempts INT NOT NULL DEFAULT 0,
        token_jti TEXT NOT NULL,
        created_at INT NOT NULL DEFAULT (unixepoch()),
        started_at INT NULL,
        finished_at INT NULL,
        updated_at INT NOT NULL DEFAULT (unixepoch())
    ) STRICT;

    CREATE TRIGGER update_task_updated_at_on_update AFTER UPDATE ON task
    BEGIN
        UPDATE task SET updated_at = unixepoch() WHERE id == NEW.id;
    END;

    CREATE INDEX idx_task_kind_created_at ON task(kind, created_at);",
];

const SELECT_COLUMNS: &str = "id, kind, json(target), json(params), state, json(substate), json(result), error, \
    attempts, token_jti, created_at, started_at, finished_at, updated_at";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    NotStarted,
    Running,
    Success,
    Failed,
}

impl TaskState {
    fn to_db(self) -> i64 {
        match self {
            TaskState::NotStarted => 0,
            TaskState::Running => 1,
            TaskState::Success => 2,
            TaskState::Failed => 3,
        }
    }

    fn from_db(value: i64) -> anyhow::Result<Self> {
        match value {
            0 => Ok(TaskState::NotStarted),
            1 => Ok(TaskState::Running),
            2 => Ok(TaskState::Success),
            3 => Ok(TaskState::Failed),
            _ => anyhow::bail!("unknown task state {value}"),
        }
    }
}

/// A task to record; `target` and `params` are JSON documents.
#[derive(Debug, Clone, Copy)]
pub struct NewTask<'a> {
    pub id: Uuid,
    pub kind: &'a str,
    pub target: &'a str,
    pub params: &'a str,
    pub token_jti: Uuid,
}

/// A stored task; JSON columns are returned as JSON text, timestamps as UNIX seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub id: Uuid,
    pub kind: String,
    pub target: String,
    pub params: String,
    pub state: TaskState,
    pub substate: Option<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub attempts: u32,
    pub token_jti: Uuid,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub updated_at: i64,
}

pub struct LibSqlProvisionerTaskStore {
    conn: Connection,
}

impl LibSqlProvisionerTaskStore {
    /// Applies the pending migrations on `conn`, which the caller has opened and configured.
    ///
    /// The database may hold other tables, such as a job queue.
    pub async fn init(conn: Connection) -> anyhow::Result<Self> {
        let store = Self { conn };
        store.migrate().await?;

        Ok(store)
    }

    pub async fn insert(&self, task: NewTask<'_>) -> anyhow::Result<()> {
        let sql_query = "INSERT INTO task (id, kind, target, params, state, token_jti)
            VALUES (:id, :kind, jsonb(:target), jsonb(:params), :state, :token_jti)";

        let params = (
            (":id", task.id.to_string()),
            (":kind", task.kind),
            (":target", task.target),
            (":params", task.params),
            (":state", TaskState::NotStarted.to_db()),
            (":token_jti", task.token_jti.to_string()),
        );

        trace!(%sql_query, task.id = %task.id, task.kind = task.kind, "Insert task");

        self.conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }

    pub async fn get(&self, id: Uuid) -> anyhow::Result<Option<TaskRecord>> {
        let sql_query = format!("SELECT {SELECT_COLUMNS} FROM task WHERE id = :id");

        let mut rows = self
            .conn
            .query(&sql_query, [(":id", id.to_string())])
            .await
            .context("failed to execute SQL query")?;

        match rows.next().await.context("failed to read the row")? {
            Some(row) => read_record(&row).map(Some),
            None => Ok(None),
        }
    }

    /// Starts a new attempt of an unfinished task and returns its attempt number, or `None` if the task is finished.
    pub async fn start_attempt(&self, id: Uuid, substate: &str) -> anyhow::Result<Option<u32>> {
        let sql_query = "UPDATE task
            SET
                state = :running,
                substate = jsonb(:substate),
                attempts = attempts + 1,
                started_at = coalesce(started_at, unixepoch())
            WHERE id = :id AND state IN (:not_started, :running)
            RETURNING attempts";

        let params = (
            (":running", TaskState::Running.to_db()),
            (":substate", substate),
            (":id", id.to_string()),
            (":not_started", TaskState::NotStarted.to_db()),
        );

        let mut rows = self
            .conn
            .query(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        match rows.next().await.context("failed to read the row")? {
            Some(row) => Ok(Some(row.get::<u32>(0).context("failed to read attempts")?)),
            None => Ok(None),
        }
    }

    /// Updates the substate of a running task.
    pub async fn set_substate(&self, id: Uuid, substate: &str) -> anyhow::Result<()> {
        let sql_query = "UPDATE task SET substate = jsonb(:substate) WHERE id = :id AND state = :running";

        let params = (
            (":substate", substate),
            (":id", id.to_string()),
            (":running", TaskState::Running.to_db()),
        );

        self.conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }

    /// Puts a running task back to `NotStarted` until its next attempt, keeping the error of the failed attempt.
    pub async fn retry_later(&self, id: Uuid, error: &str) -> anyhow::Result<()> {
        let sql_query = "UPDATE task
            SET state = :not_started, substate = NULL, error = :error
            WHERE id = :id AND state = :running";

        let params = (
            (":not_started", TaskState::NotStarted.to_db()),
            (":error", error),
            (":id", id.to_string()),
            (":running", TaskState::Running.to_db()),
        );

        self.conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }

    /// Marks an unfinished task as successful; returns `false` if it was already finished.
    pub async fn succeed(&self, id: Uuid, result: &str) -> anyhow::Result<bool> {
        self.finish(id, TaskState::Success, Some(result), None).await
    }

    /// Marks an unfinished task as failed; returns `false` if it was already finished.
    pub async fn fail(&self, id: Uuid, error: &str) -> anyhow::Result<bool> {
        self.finish(id, TaskState::Failed, None, Some(error)).await
    }

    async fn finish(
        &self,
        id: Uuid,
        state: TaskState,
        result: Option<&str>,
        error: Option<&str>,
    ) -> anyhow::Result<bool> {
        let sql_query = "UPDATE task
            SET
                state = :state,
                substate = NULL,
                result = jsonb(:result),
                error = :error,
                finished_at = unixepoch()
            WHERE id = :id AND state IN (:not_started, :running)";

        let params = (
            (":state", state.to_db()),
            (":result", result),
            (":error", error),
            (":id", id.to_string()),
            (":not_started", TaskState::NotStarted.to_db()),
            (":running", TaskState::Running.to_db()),
        );

        let changed = self
            .conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        Ok(changed > 0)
    }

    /// IDs of the tasks that are not finished yet.
    pub async fn unfinished(&self) -> anyhow::Result<Vec<Uuid>> {
        let sql_query = "SELECT id FROM task WHERE state IN (:not_started, :running) ORDER BY created_at";

        let params = (
            (":not_started", TaskState::NotStarted.to_db()),
            (":running", TaskState::Running.to_db()),
        );

        let mut rows = self
            .conn
            .query(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        let mut ids = Vec::new();

        while let Some(row) = rows.next().await.context("failed to read the row")? {
            ids.push(read_uuid(&row, 0)?);
        }

        Ok(ids)
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        let schema_version = self.query_schema_version().await?;

        match MIGRATIONS.get(schema_version..) {
            Some(remaining) if !remaining.is_empty() => {
                info!(
                    schema_version,
                    migration_count = MIGRATIONS.len() - schema_version,
                    "Start migration"
                );

                for (sql_query, migration_id) in remaining.iter().zip(schema_version..MIGRATIONS.len()) {
                    trace!(migration_id, %sql_query, "Apply migration");

                    // The migration and its version are committed together, so a crash never leaves a migration
                    // applied but not recorded, which would make every later start fail.
                    let tx = self
                        .conn
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .await
                        .with_context(|| format!("failed to begin migration {migration_id}"))?;

                    tx.execute_batch(sql_query)
                        .await
                        .with_context(|| format!("failed to execute migration {migration_id}"))?;

                    let version = i64::try_from(migration_id + 1).context("schema version is too big")?;

                    tx.execute("INSERT INTO task_schema_version (version) VALUES (?1)", [version])
                        .await
                        .context("failed to update the schema version")?;

                    tx.commit()
                        .await
                        .with_context(|| format!("failed to commit migration {migration_id}"))?;
                }

                info!("Migration complete");
            }
            None => {
                warn!(schema_version, "Task schema version is set to an unexpected value");
            }
            _ => {
                debug!(schema_version, "Database is already up to date");
            }
        }

        Ok(())
    }

    async fn query_schema_version(&self) -> anyhow::Result<usize> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS task_schema_version (version INT NOT NULL) STRICT",
                (),
            )
            .await
            .context("failed to create the schema version table")?;

        let row = self
            .conn
            .query("SELECT coalesce(max(version), 0) FROM task_schema_version", ())
            .await
            .context("failed to execute SQL query")?
            .next()
            .await
            .context("failed to read the row")?
            .context("no row returned")?;

        let value = row.get::<u64>(0).context("failed to read the schema version")?;

        usize::try_from(value).context("schema version is too big")
    }
}

fn read_uuid(row: &Row, idx: i32) -> anyhow::Result<Uuid> {
    let text = row.get::<String>(idx).context("failed to read UUID column")?;
    Uuid::parse_str(&text).context("invalid UUID")
}

fn read_record(row: &Row) -> anyhow::Result<TaskRecord> {
    Ok(TaskRecord {
        id: read_uuid(row, 0)?,
        kind: row.get(1).context("failed to read kind")?,
        target: row.get(2).context("failed to read target")?,
        params: row.get(3).context("failed to read params")?,
        state: TaskState::from_db(row.get(4).context("failed to read state")?)?,
        substate: row.get(5).context("failed to read substate")?,
        result: row.get(6).context("failed to read result")?,
        error: row.get(7).context("failed to read error")?,
        attempts: row.get(8).context("failed to read attempts")?,
        token_jti: read_uuid(row, 9)?,
        created_at: row.get(10).context("failed to read created_at")?,
        started_at: row.get(11).context("failed to read started_at")?,
        finished_at: row.get(12).context("failed to read finished_at")?,
        updated_at: row.get(13).context("failed to read updated_at")?,
    })
}
