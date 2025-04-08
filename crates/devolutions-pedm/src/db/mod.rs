use async_trait::async_trait;

mod err;

pub(crate) use err::DbError;

#[cfg(feature = "libsql")]
mod libsql;
#[cfg(feature = "libsql")]
pub(crate) use libsql::LibsqlConn;

#[cfg(feature = "postgres")]
mod pg;
#[cfg(feature = "postgres")]
pub(crate) use pg::PgPool;

/// Abstracts database operations for backends such as Postgres or libSQL.
///
/// All queries required by the application are defined here. They must be implemented by each backend.
#[async_trait]
pub(crate) trait Database: Send + Sync {
    /// Gets the latest request ID from the HTTP request table.
    ///
    /// This is used to set the atomic request counter.
    ///
    /// It returns an error if there is a database error, except for "no rows found". In that case, it returns 0.
    async fn get_latest_request_id(&self) -> Result<i32, DbError>;

    /// Logs the server startup.
    ///
    /// Returns the run ID.
    async fn log_server_startup(&self, pipe_name: &str) -> Result<i32, DbError>;

    /// Logs an HTTP request.
    ///
    /// This is used in the `LogLayer` middleware. Note that this query will only be executed after the response is sent.
    async fn log_http_request(&self, req_id: i32, method: &str, path: &str, status_code: i16) -> Result<(), DbError>;

    async fn insert_elevate_tmp_request(&self, req_id: i32, seconds: i32) -> Result<(), DbError>;
}
