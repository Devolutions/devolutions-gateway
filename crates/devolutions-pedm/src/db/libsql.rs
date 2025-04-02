use std::ops::Deref;

use async_trait::async_trait;
use libsql::params::IntoParams;
use libsql::{params, Row};

use super::{Database, DbError};

pub(crate) struct LibsqlConn(libsql::Connection);

impl LibsqlConn {
    pub(crate) fn new(conn: libsql::Connection) -> Self {
        Self(conn)
    }

    /// Executes a statement which returns a single row, returning it.
    ///
    /// Returns an error if the query does not return exactly one row.
    pub(crate) async fn query_one(&self, sql: &str, params: impl IntoParams) -> Result<Row, libsql::Error> {
        self.query(sql, params)
            .await?
            .next()
            .await?
            .ok_or(libsql::Error::QueryReturnedNoRows)
    }
}

impl Deref for LibsqlConn {
    type Target = libsql::Connection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl Database for LibsqlConn {
    async fn get_latest_request_id(&self) -> Result<i32, DbError> {
        match self
            .query_one("SELECT id FROM http_request ORDER BY id DESC LIMIT 1", ())
            .await
        {
            Ok(row) => Ok(row.get(0)?),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(DbError::Libsql(e)),
        }
    }

    async fn log_server_startup(&self, pipe_name: &str) -> Result<i32, DbError> {
        Ok(self
            .query_one("INSERT INTO pedm_run (pipe_name) VALUES (?) RETURNING id", [pipe_name])
            .await?
            .get(0)?)
    }

    async fn log_http_request(&self, req_id: i32, method: &str, path: &str, status_code: i16) -> Result<(), DbError> {
        self.execute(
            "INSERT INTO http_request (id, method, path, status_code) VALUES (?1, ?2, ?3, ?4)",
            params![req_id, method, path, status_code],
        )
        .await?;
        Ok(())
    }

    async fn insert_elevate_tmp_request(&self, req_id: i32, seconds: i32) -> Result<(), DbError> {
        self.execute(
            "INSERT INTO elevate_tmp_request (req_id, seconds) VALUES (?1, ?2)",
            params![req_id, seconds],
        )
        .await?;
        Ok(())
    }
}
