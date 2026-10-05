#[macro_use]
extern crate tracing;

use anyhow::Context as _;
use async_trait::async_trait;
use job_queue::{DynJob, JobCtx, JobQueue, JobReader, RunnerWaker};
use libsql::Connection;
use time::OffsetDateTime;
use ulid::Ulid;
use uuid::Uuid;

#[rustfmt::skip]
pub use libsql;

/// Implementation of [`JobQueue`] using libSQL as the backend
///
/// This is inspired by 37signals' Solid Queue:
/// - <https://dev.37signals.com/introducing-solid-queue/>
/// - <https://github.com/rails/solid_queue/>
///
/// And "How to build a job queue with Rust and PostgreSQL" on kerkour.com:
/// - <https://kerkour.com/rust-job-queue-with-postgresql>
///
/// We use the 'user_version' value to store the migration state.
/// It's a very lightweight approach as it is just an integer at a fixed offset in the SQLite file.
/// - <https://sqlite.org/pragma.html#pragma_user_version>
/// - <https://www.sqlite.org/fileformat.html#user_version_number>
#[derive(typed_builder::TypedBuilder)]
pub struct LibSqlJobQueue {
    runner_waker: RunnerWaker,
    conn: Connection,
    #[builder(default = 5)]
    max_attempts: u32,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(u32)]
enum JobStatus {
    Queued,
    Running,
}

impl LibSqlJobQueue {
    async fn apply_pragmas(&self) -> anyhow::Result<()> {
        // Inspiration was taken from https://briandouglas.ie/sqlite-defaults/
        const PRAGMAS: &str = "
            -- https://www.sqlite.org/pragma.html#pragma_journal_mode
            -- Use a write-ahead log instead of a rollback journal to implement transactions.
            PRAGMA journal_mode = WAL;

            -- https://www.sqlite.org/pragma.html#pragma_synchronous
            -- TLDR: journal_mode WAL + synchronous NORMAL is a good combination.
            -- WAL mode is safe from corruption with synchronous=NORMAL
            -- The synchronous=NORMAL setting is a good choice for most applications running in WAL mode.
            PRAGMA synchronous = NORMAL;

            -- https://www.sqlite.org/pragma.html#pragma_busy_timeout
            -- Prevents SQLITE_BUSY errors by giving a timeout to wait for a locked resource before
            -- returning an error, useful for handling multiple concurrent accesses.
            -- 15 seconds is a good value for a backend application like a job queue.
            PRAGMA busy_timeout = 15000;

            -- https://www.sqlite.org/pragma.html#pragma_cache_size
            -- Reduce the number of disks reads by allowing more data to be cached in memory (3MB).
            PRAGMA cache_size = -3000;

            -- https://www.sqlite.org/pragma.html#pragma_auto_vacuum
            -- Reclaims disk space gradually as rows are deleted, instead of performing a full vacuum,
            -- reducing performance impact during database operations.
            PRAGMA auto_vacuum = INCREMENTAL;

            -- https://www.sqlite.org/pragma.html#pragma_temp_store
            -- Store temporary tables and data in memory for better performance
            PRAGMA temp_store = MEMORY;
        ";

        trace!(sql_query = %PRAGMAS, "PRAGMAs query");

        let mut batch_rows = self
            .conn
            .execute_batch(PRAGMAS)
            .await
            .context("failed to batch execute SQL query")?;

        while let Some(rows) = batch_rows.next_stmt_row() {
            let Some(mut rows) = rows else {
                continue;
            };

            while let Ok(Some(row)) = rows.next().await {
                trace!(?row, "PRAGMA row");
            }
        }

        Ok(())
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        let user_version = self.query_user_version().await?;

        match MIGRATIONS.get(user_version..) {
            Some(remaining) if !remaining.is_empty() => {
                info!(
                    user_version,
                    migration_count = MIGRATIONS.len() - user_version,
                    "Start migration"
                );

                for (sql_query, migration_id) in remaining.iter().zip(user_version..MIGRATIONS.len()) {
                    trace!(migration_id, %sql_query, "Apply migration");

                    self.conn
                        .execute_batch(sql_query)
                        .await
                        .with_context(|| format!("failed to execute migration {migration_id}"))?;

                    trace!(migration_id, "Applied migration");

                    self.update_user_version(migration_id + 1)
                        .await
                        .context("failed to update user version")?;
                }

                info!("Migration complete");
            }
            None => {
                warn!(user_version, "user_version is set to an unexpected value");
            }
            _ => {
                debug!(user_version, "Database is already up to date");
            }
        }

        Ok(())
    }

    async fn query_user_version(&self) -> anyhow::Result<usize> {
        let sql_query = "PRAGMA user_version";

        trace!(%sql_query, "Query user_version");

        let row = self
            .conn
            .query(sql_query, ())
            .await
            .context("failed to execute SQL query")?
            .next()
            .await
            .context("failed to read the row")?
            .context("no row returned")?;

        let value = row.get::<u64>(0).context("failed to read user_version value")?;

        Ok(usize::try_from(value).expect("number not too big"))
    }

    async fn update_user_version(&self, value: usize) -> anyhow::Result<()> {
        let value = u64::try_from(value).expect("number not too big");

        let sql_query = format!("PRAGMA user_version = {value}");

        trace!(%sql_query, "Update user_version");

        self.conn
            .execute(&sql_query, ())
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }
}

#[async_trait]
impl JobQueue for LibSqlJobQueue {
    async fn setup(&self) -> anyhow::Result<()> {
        self.apply_pragmas().await?;
        self.migrate().await?;
        Ok(())
    }

    async fn reset_claimed_jobs(&self) -> anyhow::Result<()> {
        let sql_query = "UPDATE job_queue SET status = :queued_status WHERE status = :running_status";

        let params = (
            (":running_status", JobStatus::Running as u32),
            (":queued_status", JobStatus::Queued as u32),
        );

        trace!(%sql_query, ?params, "Reset claimed jobs");

        let changed_count = self
            .conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        trace!(changed_count, "Jobs reset with success");

        Ok(())
    }

    async fn push_job(&self, job: &DynJob, schedule_for: Option<OffsetDateTime>) -> anyhow::Result<()> {
        let sql_query = "INSERT INTO job_queue
            (id, scheduled_for, failed_attempts, status, name, def)
            VALUES (:id, :scheduled_for, :failed_attempts, :status, :name, jsonb(:def))";

        // UUID v4 only provides randomness, which leads to fragmentation.
        // We use ULID instead to reduce index fragmentation.
        // https://github.com/ulid/spec
        let id = Uuid::from(Ulid::new()).to_string();

        let schedule_for = schedule_for.unwrap_or_else(OffsetDateTime::now_utc);

        let params = (
            (":id", id),
            (":scheduled_for", schedule_for.unix_timestamp()),
            (":failed_attempts", 0),
            (":status", JobStatus::Queued as u32),
            (":name", job.name()),
            (":def", job.write_json()?),
        );

        trace!(%sql_query, ?params, "Pushing a new job");

        self.conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        // Notify the waker that a new job is ready for processing.
        self.runner_waker.wake();

        Ok(())
    }

    async fn claim_jobs(&self, reader: &dyn JobReader, number_of_jobs: usize) -> anyhow::Result<Vec<JobCtx>> {
        let number_of_jobs = u32::try_from(number_of_jobs).context("number_of_jobs is too big")?;

        // If we were using Postgres, we would need to use `FOR UPDATE SKIP LOCKED`
        // in the SQL query to avoid blocking other readers/writers.
        // For MySQL, this would be `FOR UPDATE NOWAIT`
        // However, in SQLite / libSQL, there is only a single writer at a time.
        // As such, this directive doesn't exist.

        let sql_query = "UPDATE job_queue
            SET status = :running_status
            WHERE id IN (
                SELECT id
                FROM job_queue
                WHERE status = :queued_status AND failed_attempts < :max_attempts AND scheduled_for <= unixepoch()
                ORDER BY id
                LIMIT :number_of_jobs
            )
            RETURNING id, failed_attempts, name, json(def) as def";

        let params = (
            (":running_status", JobStatus::Running as u32),
            (":queued_status", JobStatus::Queued as u32),
            (":max_attempts", self.max_attempts),
            (":number_of_jobs", number_of_jobs),
        );

        trace!(%sql_query, ?params, "Claiming jobs");

        let mut rows = self
            .conn
            .query(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        let mut jobs = Vec::new();

        loop {
            let row = rows.next().await;

            let row = match row {
                Ok(row) => row,
                Err(error) => {
                    error!(%error, "Failed to get next row");
                    break;
                }
            };

            let Some(row) = row else {
                break;
            };

            match libsql::de::from_row::<'_, JobModel>(&row) {
                Ok(model) => match reader.read_json(&model.name, &model.def) {
                    Ok(job) => jobs.push(JobCtx {
                        id: model.id,
                        failed_attempts: model.failed_attempts,
                        job,
                    }),
                    Err(e) => {
                        error!(
                            error = format!("{e:#}"),
                            "Failed read job definition; delete the invalid job"
                        );
                        let _ = self.delete_job(model.id).await;
                    }
                },
                Err(error) => {
                    error!(%error, ?row, "Failed to read row");
                }
            }
        }

        return Ok(jobs);

        #[derive(serde::Deserialize, Debug, Clone)]
        struct JobModel {
            id: Uuid,
            failed_attempts: u32,
            name: String,
            def: String,
        }
    }

    async fn delete_job(&self, id: Uuid) -> anyhow::Result<()> {
        let sql_query = "DELETE FROM job_queue WHERE id = $1";
        let params = [id.to_string()];

        trace!(%sql_query, ?params, "Deleting job");

        self.conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }

    async fn fail_job(&self, id: Uuid, schedule_for: OffsetDateTime) -> anyhow::Result<()> {
        let sql_query = "UPDATE job_queue
            SET
                status = :queued_status,
                failed_attempts = failed_attempts + 1,
                scheduled_for = :scheduled_for
            WHERE id = :id";

        let params = (
            (":queued_status", JobStatus::Queued as u32),
            (":scheduled_for", schedule_for.unix_timestamp()),
            (":id", id.to_string()),
        );

        trace!(%sql_query, ?params, "Marking job as failed");

        self.conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }

    async fn clear_failed(&self) -> anyhow::Result<()> {
        let sql_query = "DELETE FROM job_queue WHERE failed_attempts >= $1";
        let params = [self.max_attempts];

        trace!(%sql_query, ?params, "Clearing failed jobs");

        let deleted_count = self
            .conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        trace!(deleted_count, "Cleared failed jobs with success");

        Ok(())
    }

    async fn next_scheduled_date(&self) -> anyhow::Result<Option<OffsetDateTime>> {
        let sql_query = "SELECT scheduled_for
            FROM job_queue
            WHERE status = :queued_status AND failed_attempts < :max_attempts
            ORDER BY scheduled_for ASC
            LIMIT 1";

        let params = (
            (":queued_status", JobStatus::Queued as u32),
            (":max_attempts", self.max_attempts),
        );

        trace!(%sql_query, ?params, "Fetching the earliest scheduled_for date");

        let mut rows = self
            .conn
            .query(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        let Some(row) = rows.next().await.context("failed to read the row")? else {
            return Ok(None);
        };

        let scheduled_for = row.get::<i64>(0).context("failed to read scheduled_for value")?;
        let scheduled_for =
            OffsetDateTime::from_unix_timestamp(scheduled_for).context("invalid UNIX timestamp for scheduled_for")?;

        Ok(Some(scheduled_for))
    }
}

// Typically, migrations should not be modified once released, and we should only be appending to this list.
const MIGRATIONS: &[&str] = &[
    // Migration 0
    "CREATE TABLE job_queue (
        id TEXT NOT NULL PRIMARY KEY,
        created_at INT NOT NULL DEFAULT (unixepoch()),
        updated_at INT NOT NULL DEFAULT (unixepoch()),
        scheduled_for INT NOT NULL,
        failed_attempts INT NOT NULL,
        status INT NOT NULL,
        name TEXT NOT NULL,
        def BLOB NOT NULL
    ) STRICT;

    CREATE TRIGGER update_job_updated_at_on_update AFTER UPDATE ON job_queue
    BEGIN
        UPDATE job_queue SET updated_at = unixepoch() WHERE id == NEW.id;
    END;

    CREATE INDEX idx_scheduled_for ON job_queue(scheduled_for);",
];
