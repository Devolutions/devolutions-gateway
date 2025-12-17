#![cfg_attr(
    unix,
    expect(
        dead_code,
        reason = "only used in the windows implementation, nothing is planned for linux yet"
    )
)]

use core::fmt;
use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use devolutions_gateway_task::{ShutdownSignal, Task};
use devolutions_pedm_shared::policy::{Assignment, ElevationResult, Profile, User};
use tracing::{info, warn};

mod err;

pub(crate) use err::DbError;

use crate::Config;
use crate::config::DbBackend;
use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions, JitElevationLogRow};

#[cfg(feature = "libsql")]
mod libsql;
#[cfg(feature = "libsql")]
pub(crate) use libsql::LibsqlConn;

#[cfg(feature = "postgres")]
mod pg;
#[cfg(feature = "postgres")]
use bb8::Pool;
#[cfg(feature = "postgres")]
use bb8_postgres::PostgresConnectionManager;
#[cfg(feature = "postgres")]
pub(crate) use pg::PgPool;
#[cfg(feature = "postgres")]
use tokio_postgres::NoTls;
#[cfg(feature = "postgres")]
use tokio_postgres::config::SslMode;

pub(crate) const CURRENT_SCHEMA_VERSION: i16 = 0;

/// A wrapper around the database connection.
#[derive(Clone)]
pub(crate) struct Db(pub Arc<dyn Database + Send + Sync>);

impl Deref for Db {
    type Target = dyn Database + Send + Sync;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl Db {
    /// Creates a new `Db` instance.
    pub(crate) async fn new(config: &Config) -> Result<Self, DbError> {
        let db: Arc<dyn Database + Send + Sync> = match config.db {
            #[cfg(feature = "libsql")]
            DbBackend::Libsql => {
                #[expect(clippy::unwrap_used)]
                let c = config.libsql.as_ref().unwrap(); // already checked by `Config::validate` at the end of the load function
                let db_obj = ::libsql::Builder::new_local(&c.path).build().await?;
                let conn = db_obj.connect()?;
                info!("Connecting to libSQL database at {}", c.path);
                Arc::new(LibsqlConn::new(conn))
            }
            #[cfg(feature = "postgres")]
            DbBackend::Postgres => {
                #[expect(clippy::unwrap_used)]
                let c = config.postgres.as_ref().unwrap(); // already checked by `Config::validate` at the end of the load function
                let mut pg_config = tokio_postgres::Config::new();
                pg_config.host(&c.host);
                pg_config.dbname(&c.dbname);
                if let Some(n) = c.port {
                    pg_config.port(n);
                }
                pg_config.user(&c.user);
                if let Some(s) = &c.password {
                    pg_config.password(s);
                }
                pg_config.ssl_mode(SslMode::Disable);

                let mgr = PostgresConnectionManager::new(pg_config, NoTls);
                let pool = Pool::builder().build(mgr).await?;

                info!(
                    "Connecting to postgres://{user}@{host}:{port}/{dbname}",
                    user = c.user,
                    host = c.host,
                    port = c.port.unwrap_or(5432),
                    dbname = c.dbname
                );
                // Check if the connection works.
                let conn = pool.get().await?;
                conn.query_one("SELECT 1", &[]).await?;
                drop(conn);
                Arc::new(PgPool::new(pool))
            }
        };
        info!("Successfully connected to the database");
        Ok(Self(db))
    }

    /// Sets up the database.
    ///
    /// The schema version is checked. Tables are created if needed, such as for first run.
    pub(crate) async fn setup(&self) -> Result<(), InitSchemaError> {
        match self.0.get_schema_version().await {
            Ok(version) => {
                info!("Schema version: {version}");
                if version != CURRENT_SCHEMA_VERSION {
                    return Err(InitSchemaError::VersionMismatch {
                        expected: CURRENT_SCHEMA_VERSION,
                        actual: version,
                    });
                }
            }
            Err(error) => {
                if error.is_table_does_not_exist() {
                    info!("Initializing schema");
                    self.0.init_schema().await?;
                } else {
                    return Err(error.into());
                }
            }
        }
        self.0.apply_pragmas().await?;
        Ok(())
    }
}

// FIXME: This is used in public ServeError but flagged as unreachable on Linux. Investigate if it should be re-exported or kept internal.
#[cfg_attr(
    not(windows),
    expect(
        unreachable_pub,
        reason = "used in public ServeError but flagged as unreachable on Linux"
    )
)]
#[derive(Debug)]
pub enum InitSchemaError {
    VersionMismatch { expected: i16, actual: i16 },
    Db(DbError),
}

impl core::error::Error for InitSchemaError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::VersionMismatch { .. } => None,
            Self::Db(e) => Some(e),
        }
    }
}

impl fmt::Display for InitSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "schema version mismatch: expected version {expected}, got version {actual}"
                )
            }
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl From<DbError> for InitSchemaError {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}

/// Abstracts database operations for backends such as Postgres or libSQL.
///
/// All queries required by the application are defined here. They must be implemented by each backend.
#[async_trait]
pub(crate) trait Database: Send + Sync {
    /// Returns the schema version from the `version` table.
    async fn get_schema_version(&self) -> Result<i16, DbError>;

    /// Initializes the database schema.
    ///
    /// This creates tables.
    async fn init_schema(&self) -> Result<(), DbError>;

    /// Applies pragmas, if applicable.
    async fn apply_pragmas(&self) -> Result<(), DbError>;

    /// Gets the latest request ID from the HTTP request table.
    ///
    /// This is used to set the atomic request counter.
    ///
    /// It returns an error if there is a database error, except for "no rows found". In that case, it returns 0.
    async fn get_last_request_id(&self) -> Result<i32, DbError>;

    /// Gets the time of the latest request.
    ///
    /// This is used in endpoints like `/about`.
    async fn get_last_request_time(&self) -> Result<Option<DateTime<Utc>>, DbError>;

    /// Logs the server startup.
    ///
    /// Returns the run ID.
    async fn log_server_startup(&self, start_time: DateTime<Utc>, pipe_name: &str) -> Result<i32, DbError>;

    /// Logs an HTTP request.
    ///
    /// This is used in the `LogLayer` middleware. Note that this query will only be executed after the response is sent.
    async fn log_http_request(&self, req_id: i32, method: &str, path: &str, status_code: i16) -> Result<(), DbError>;

    async fn insert_jit_elevation_result(&self, result: &ElevationResult) -> Result<(), DbError>;

    async fn get_profiles(&self) -> Result<Vec<Profile>, DbError>;

    async fn get_profiles_for_user(&self, user: &User) -> Result<Vec<Profile>, DbError>;

    async fn get_profile(&self, id: i64) -> Result<Option<Profile>, DbError>;

    async fn insert_profile(&self, profile: &Profile) -> Result<(), DbError>;

    async fn delete_profile(&self, id: i64) -> Result<(), DbError>;

    async fn get_assignments(&self) -> Result<Vec<Assignment>, DbError>;

    async fn get_assignment(&self, profile: &Profile) -> Result<Assignment, DbError>;

    async fn set_assignments(&self, profile_id: i64, users: Vec<User>) -> Result<(), DbError>;

    async fn set_user_profile(&self, user: &User, profile_id: i64) -> Result<(), DbError>;

    async fn get_user_profile(&self, user: &User) -> Result<Option<Profile>, DbError>;

    async fn get_user_id(&self, user: &User) -> Result<Option<i64>, DbError>;

    async fn get_users(&self) -> Result<Vec<User>, DbError>;

    async fn get_jit_elevation_log(&self, id: i64) -> Result<Option<JitElevationLogRow>, DbError>;

    async fn get_jit_elevation_logs(
        &self,
        query_options: JitElevationLogQueryOptions,
    ) -> Result<JitElevationLogPage, DbError>;
}

// Bridge for DB operations from synchronous functions.
// This may or may not be a temporary workaround.

pub(crate) struct DbHandleError<T> {
    pub(crate) db_error: Option<DbError>,
    pub(crate) value: T,
}

#[derive(Clone)]
pub(crate) struct DbHandle {
    tx: tokio::sync::mpsc::Sender<DbRequest>,
}

impl DbHandle {
    #[expect(clippy::result_large_err, reason = "suppressing for now")] // FIXME: Re-evaluate this suppression.
    pub(crate) fn insert_jit_elevation_result(
        &self,
        result: ElevationResult,
    ) -> Result<(), DbHandleError<ElevationResult>> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        match self
            .tx
            .blocking_send(DbRequest::InsertJitElevationResult { result, tx })
        {
            Ok(()) => match rx.blocking_recv() {
                Ok(db_result) => db_result,
                Err(_) => {
                    warn!("Did not receive the response from the async bridge task");
                    Ok(())
                }
            },
            Err(error) => {
                let DbRequest::InsertJitElevationResult { result, .. } = error.0;

                Err(DbHandleError {
                    db_error: None,
                    value: result,
                })
            }
        }
    }
}

pub(crate) enum DbRequest {
    InsertJitElevationResult {
        result: ElevationResult,
        tx: tokio::sync::oneshot::Sender<Result<(), DbHandleError<ElevationResult>>>,
    },
}

pub(crate) struct DbAsyncBridgeTask {
    db: Db,
    rx: tokio::sync::mpsc::Receiver<DbRequest>,
}

impl DbAsyncBridgeTask {
    pub(crate) fn new(db: Db) -> (DbHandle, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        (DbHandle { tx }, Self { db, rx })
    }
}

#[async_trait]
impl Task for DbAsyncBridgeTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "db-async-bridge";

    async fn run(mut self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                req = self.rx.recv() => {
                    let Some(req) = req else {
                        break;
                    };

                    match req {
                        DbRequest::InsertJitElevationResult { result, tx } => {
                            match self.db.insert_jit_elevation_result(&result).await {
                                Ok(()) => {
                                    let _ = tx.send(Ok(()));
                                }
                                Err(error) => {
                                    let _ = tx.send(Err(DbHandleError {
                                       db_error: Some(error),
                                       value: result,
                                    }));
                                }
                            }
                        }
                    }
                }
                _ = shutdown_signal.wait() => {
                    break;
                }
            }
        }

        Ok(())
    }
}
