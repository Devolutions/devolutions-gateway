#[macro_use]
extern crate tracing;

use anyhow::Context as _;
use async_trait::async_trait;
use job_queue::{DynJob, JobCtx, JobQueue, JobReader, RunnerWaker};
use libsql::Connection;
use ulid::Ulid;
use uuid::Uuid;

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
    instance_id: Uuid,
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
    async fn migrate(&self) -> anyhow::Result<()> {
        const MIGRATIONS: &[&str] = &["CREATE TABLE job_queue (
                id UUID NOT NULL PRIMARY KEY,
                instance_id UUID NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                failed_attempts INT NOT NULL,
                status INT NOT NULL,
                name TEXT NOT NULL,
                def JSONB NOT NULL
            );

            CREATE TRIGGER update_job_updated_at_on_update AFTER UPDATE ON job_queue
            BEGIN
                UPDATE job_queue SET updated_at = CURRENT_TIMESTAMP WHERE rowid == NEW.rowid;
            END;"];

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
                        .execute(sql_query, ())
                        .await
                        .with_context(|| format!("failed to execute migration {}", migration_id))?;

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

    async fn push_job(&self, job: &DynJob) -> anyhow::Result<()> {
        let sql_query = "INSERT INTO job_queue
            (id, instance_id, failed_attempts, status, name, def)
            VALUES (:id, :instance_id, :failed_attempts, :status, :name, jsonb(:def))";

        // UUID v4 provides no other information than randomness which cause fragmentation.
        // Reduce index fragmentation by using ULID instead.
        // https://github.com/ulid/spec
        let id = Uuid::from(Ulid::new());

        let params = (
            (":id", id.to_string()),
            (":instance_id", self.instance_id.to_string()),
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
            SET status = :new_status
            WHERE id IN (
                SELECT id
                FROM job_queue
                WHERE instance_id = :instance_id AND status = :current_status AND failed_attempts < :max_attempts
                ORDER BY id
                LIMIT :number_of_jobs
            )
            RETURNING id, name, json(def) as def";

        let params = (
            (":new_status", JobStatus::Running as u32),
            (":instance_id", self.instance_id.to_string()),
            (":current_status", JobStatus::Queued as u32),
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
                    Ok(job) => jobs.push(JobCtx { id: model.id, job }),
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

    async fn fail_job(&self, id: Uuid) -> anyhow::Result<()> {
        let sql_query = "UPDATE job_queue
            SET status = :new_status, failed_attempts = failed_attempts + 1
            WHERE id = :id";
        let params = ((":new_status", JobStatus::Queued as u32), (":id", id.to_string()));

        trace!(%sql_query, ?params, "Marking job as failed");

        self.conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        Ok(())
    }

    async fn clear_failed(&self) -> anyhow::Result<()> {
        let sql_query = "DELETE FROM job_queue WHERE instance_id = :instance_id AND failed_attempts >= :max_attempts";

        let params = (
            (":instance_id", self.instance_id.to_string()),
            (":max_attempts", self.max_attempts),
        );

        trace!(%sql_query, ?params, "Clearing failed jobs");

        let deleted_count = self
            .conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        trace!(deleted_count, "Cleared failed jobs with success");

        Ok(())
    }
}
