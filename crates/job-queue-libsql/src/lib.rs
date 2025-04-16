#[macro_use]
extern crate tracing;

use std::str::FromStr;

use anyhow::Context as _;
use async_trait::async_trait;
use job_queue::{CronJobCompact, JobCtx, JobQueue, JobReader, RunnerWaker, ScheduleFor};
use libsql::Connection;
use time::OffsetDateTime;
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

    async fn push_job_raw(&self, job_name: &str, job_def: String, schedule_for: ScheduleFor) -> anyhow::Result<()> {
        let sql_query = "INSERT INTO job_queue
            (id, scheduled_for, failed_attempts, status, name, def, cron)
            VALUES (:id, :scheduled_for, :failed_attempts, :status, :name, jsonb(:def), :cron)";

        // UUID v4 only provides randomness, which leads to fragmentation.
        // We use ULID instead to reduce index fragmentation.
        // https://github.com/ulid/spec
        let id = Uuid::from(Ulid::new()).to_string();

        let cron_expression = if let ScheduleFor::Cron(schedule) = &schedule_for {
            Some(schedule.to_string())
        } else {
            None
        };

        let schedule_for = match &schedule_for {
            ScheduleFor::Now => OffsetDateTime::now_utc(),
            ScheduleFor::Once(date) => *date,
            ScheduleFor::Cron(cron) => {
                let next_schdule_time = cron
                    .upcoming(chrono::Utc)
                    .next()
                    .context("failed to get next cron date")?;

                OffsetDateTime::from_unix_timestamp(next_schdule_time.timestamp())
                    .context("failed to convert timestamp to OffsetDateTime")?
                    .replace_nanosecond(next_schdule_time.timestamp_subsec_nanos())?
            }
        };

        let params = (
            (":id", id),
            (":scheduled_for", schedule_for.unix_timestamp()),
            (":failed_attempts", 0),
            (":status", JobStatus::Queued as u32),
            (":cron", cron_expression),
            (":name", job_name),
            (":def", job_def),
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

    async fn schedule_next_cron_job(&self, id: Uuid) -> anyhow::Result<u64> {
        let mut rows = self
            .conn
            .query("SELECT cron FROM job_queue WHERE id = ?", [id.to_string()])
            .await?;

        let Some(row) = rows.next().await.context("failed to read the row")? else {
            anyhow::bail!("no row returned");
        };

        let cron_expression = row.get::<String>(0).context("failed to read cron value")?;

        let cron = cron_clock::Schedule::from_str(&cron_expression).context("failed to parse cron expression")?;

        let next_schdule_time = cron
            .upcoming(chrono::Utc)
            .next()
            .context("failed to get next cron date")?;

        let offset_dt = OffsetDateTime::from_unix_timestamp(next_schdule_time.timestamp())
            .context("failed to convert timestamp to OffsetDateTime")?
            .replace_nanosecond(next_schdule_time.timestamp_subsec_nanos())?;

        let sql_query = "UPDATE job_queue
            SET scheduled_for = :scheduled_for,
            status = :status
            WHERE id = :id";

        let params = (
            (":scheduled_for", offset_dt.unix_timestamp()),
            (":status", JobStatus::Queued as u32),
            (":id", id.to_string()),
        );

        trace!(%sql_query, ?params, "Scheduling next cron job");
        let changed = self
            .conn
            .execute(sql_query, params)
            .await
            .context("failed to execute SQL query")?;

        // Notify the waker that a new job is ready for processing.
        self.runner_waker.wake();
        trace!("Scheduled next cron job");

        Ok(changed)
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
            RETURNING id, failed_attempts, name, json(def) as def, cron";

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
                        cron: model
                            .cron
                            .map(|c| {
                                let cron =
                                    cron_clock::Schedule::from_str(&c).context("failed to parse cron expression")?;
                                anyhow::Ok(cron)
                            })
                            .transpose()?,
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
            cron: Option<String>,
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

    async fn get_cron_jobs(&self) -> anyhow::Result<Vec<CronJobCompact>> {
        let sql_query = "SELECT id, name, cron FROM job_queue WHERE cron IS NOT NULL";

        trace!(%sql_query, "Fetching cron jobs");

        let mut rows = self
            .conn
            .query(sql_query, ())
            .await
            .context("failed to execute SQL query")?;

        let mut jobs = Vec::new();
        while let Some(row) = rows.next().await.context("failed to read the row")? {
            let job = libsql::de::from_row::<'_, CronJobCompact>(&row).context("failed to deserialize row")?;
            jobs.push(job);
        }

        Ok(jobs)
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
    // Migration 1
    "ALTER TABLE job_queue ADD COLUMN cron TEXT;",
];

#[cfg(test)]
mod test {
    use super::*;
    use job_queue::{Job, JobQueueExt, JobReader, ScheduleFor};

    #[derive(Debug)]
    struct DummyJob;

    #[async_trait::async_trait]
    impl Job for DummyJob {
        fn name(&self) -> &str {
            "dummy"
        }
        fn write_json(&self) -> anyhow::Result<String> {
            Ok("{}".to_owned())
        }

        async fn run(&mut self) -> anyhow::Result<()> {
            // Simulate some work
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            println!("Running DummyJob");
            Ok(())
        }
    }

    #[derive(Default)]
    struct DummyReader;

    #[async_trait::async_trait]
    impl JobReader for DummyReader {
        fn read_json(&self, _: &str, _: &str) -> anyhow::Result<Box<dyn Job>> {
            Ok(Box::new(DummyJob))
        }
    }

    async fn setup_queue() -> anyhow::Result<LibSqlJobQueue> {
        let db = libsql::Builder::new_local(":memory:").build().await?;

        let conn = db.connect()?;
        let queue = LibSqlJobQueue::builder()
            .conn(conn)
            .runner_waker(RunnerWaker::new(|| {}))
            .build();

        queue.setup().await?;
        Ok(queue)
    }

    #[tokio::test]
    async fn test_setup_migration() -> anyhow::Result<()> {
        let queue = setup_queue().await?;
        let mut rows = queue
            .conn
            .query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='job_queue'",
                (),
            )
            .await?;
        assert!(rows.next().await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn test_push_job() -> anyhow::Result<()> {
        let queue = setup_queue().await?;
        let job: Box<dyn Job> = Box::new(DummyJob);

        queue.push_job(&job, ScheduleFor::Now).await?;
        let mut rows = queue.conn.query("SELECT COUNT(*) FROM job_queue", ()).await?;
        let row = rows.next().await?.unwrap();
        let count: i64 = row.get(0)?;
        assert_eq!(count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_claim_jobs() -> anyhow::Result<()> {
        let queue = setup_queue().await?;
        let job: Box<dyn Job> = Box::new(DummyJob);

        queue
            .push_job_raw(job.name(), job.write_json()?, ScheduleFor::Now)
            .await?;
        let jobs = queue.claim_jobs(&DummyReader, 1).await?;
        assert_eq!(jobs.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_job() -> anyhow::Result<()> {
        let queue = setup_queue().await?;
        let job: Box<dyn Job> = Box::new(DummyJob);
        queue
            .push_job_raw(job.name(), job.write_json()?, ScheduleFor::Now)
            .await?;

        let jobs = queue.claim_jobs(&DummyReader, 1).await?;
        let job_id = jobs[0].id;

        queue.delete_job(job_id).await?;

        let mut rows = queue.conn.query("SELECT COUNT(*) FROM job_queue", ()).await?;
        let row = rows.next().await?.unwrap();
        let count: i64 = row.get(0)?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_cron_job_schedule() -> anyhow::Result<()> {
        let queue = setup_queue().await?;
        let job: Box<dyn Job> = Box::new(DummyJob);
        let cron_expr = cron_clock::Schedule::from_str("0/5 * * * * *")?;

        queue
            .push_job_raw(job.name(), job.write_json()?, ScheduleFor::Cron(cron_expr))
            .await?;

        let mut rows = queue.conn.query("SELECT cron FROM job_queue", ()).await?;
        let row = rows.next().await?.context("no row returned")?;

        let cron_val: String = row.get(0)?;

        assert_eq!(cron_val, "0/5 * * * * *");
        Ok(())
    }

    #[tokio::test]
    async fn test_schedule_next_cron_job() -> anyhow::Result<()> {
        let queue = setup_queue().await?;
        let job: Box<dyn Job> = Box::new(DummyJob);

        // Create a cron job that runs every 5 seconds
        let cron_expr = cron_clock::Schedule::from_str("0/5 * * * * *")?;
        queue
            .push_job_raw(job.name(), job.write_json()?, ScheduleFor::Cron(cron_expr))
            .await?;

        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        // Check that the job was inserted correctly
        let mut rows = queue.conn.query("SELECT * FROM job_queue", ()).await?;
        let row = rows.next().await?.unwrap();
        println!("Row: {:?}", row);

        // Claim the job
        let jobs = queue.claim_jobs(&DummyReader, 1).await?;
        println!(
            "Claimed jobs: {:?}",
            jobs.iter().map(|j| (j.id, j.job.name())).collect::<Vec<_>>()
        );
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].cron.is_some());
        let job_id = jobs[0].id;

        // get job by id
        let mut rows = queue
            .conn
            .query("SELECT * FROM job_queue WHERE id = ?", [job_id.to_string()])
            .await?;

        println!("Row: {:?}", rows.next().await?.unwrap());

        // Before rescheduling, the job's status should be Running (1)
        let mut rows = queue
            .conn
            .query("SELECT status FROM job_queue WHERE id = ?", [job_id.to_string()])
            .await?;
        let row = rows.next().await?.unwrap();
        let status: u32 = row.get(0)?;
        assert_eq!(status, JobStatus::Running as u32);

        // Schedule the next execution of the cron job
        let affected = queue.schedule_next_cron_job(job_id).await?;
        println!("Number of affected rows: {}", affected);

        // After rescheduling, verify:
        // 1. The job's status is Queued (0)
        // 2. The scheduled_for timestamp is in the future
        let mut rows = queue
            .conn
            .query(
                "SELECT status, scheduled_for FROM job_queue WHERE id = ?",
                [job_id.to_string()],
            )
            .await?;
        let row = rows.next().await?.unwrap();
        println!("Row: {:?}", row);
        let status: u32 = row.get(0)?;
        let scheduled_for: i64 = row.get(1)?;

        // The scheduled time should be in the future
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(scheduled_for > now, "scheduled_for should be in the future");
        assert_eq!(status, JobStatus::Queued as u32);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_cron_jobs() -> anyhow::Result<()> {
        let queue = setup_queue().await?;
        let job: Box<dyn Job> = Box::new(DummyJob);

        // No cron jobs initially
        let cron_jobs = queue.get_cron_jobs().await?;
        assert_eq!(cron_jobs.len(), 0, "Should have no cron jobs initially");

        // Add regular job (non-cron)
        queue.push_job(&job, ScheduleFor::Now).await?;

        // Verify cron jobs still empty
        let cron_jobs = queue.get_cron_jobs().await?;
        assert_eq!(cron_jobs.len(), 0, "Regular jobs should not appear in cron jobs list");

        // Add two cron jobs with different schedules
        let cron_expr1 = cron_clock::Schedule::from_str("0/5 * * * * *")?;
        let cron_expr2 = cron_clock::Schedule::from_str("0 0 * * * *")?;

        queue
            .push_job_raw(job.name(), job.write_json()?, ScheduleFor::Cron(cron_expr1))
            .await?;
        queue
            .push_job_raw(job.name(), job.write_json()?, ScheduleFor::Cron(cron_expr2))
            .await?;

        // Now we should have two cron jobs
        let cron_jobs = queue.get_cron_jobs().await?;
        assert_eq!(cron_jobs.len(), 2, "Should have two cron jobs");

        // Verify content of retrieved cron jobs
        for job in &cron_jobs {
            assert_eq!(job.name, "dummy", "Job name should be 'dummy'");
            assert!(
                job.cron == "0/5 * * * * *" || job.cron == "0 0 * * * *",
                "Cron expression should match one of the inserted values"
            );
        }

        // Ensure we have both cron expressions
        let expressions: Vec<_> = cron_jobs.iter().map(|j| j.cron.as_str()).collect();
        assert!(
            expressions.contains(&"0/5 * * * * *"),
            "Should contain first cron expression"
        );
        assert!(
            expressions.contains(&"0 0 * * * *"),
            "Should contain second cron expression"
        );

        Ok(())
    }
}
