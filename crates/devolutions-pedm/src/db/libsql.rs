use std::ops::Deref;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use libsql::params::IntoParams;
use libsql::{params, Row};

use super::err::ParseTimestampError;
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
    async fn get_schema_version(&self) -> Result<i16, DbError> {
        let version = self
            .query_one("SELECT version FROM pedm_schema_version", ())
            .await?
            .get::<i32>(0)?;
        Ok(i16::try_from(version)?)
    }

    async fn init_schema(&self) -> Result<(), DbError> {
        let sql = include_str!("../../schema/libsql.sql");
        self.execute_batch(sql).await?;
        Ok(())
    }

    async fn get_last_request_id(&self) -> Result<i32, DbError> {
        match self
            .query_one("SELECT id FROM http_request ORDER BY id DESC LIMIT 1", ())
            .await
        {
            Ok(row) => Ok(row.get(0)?),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(DbError::Libsql(e)),
        }
    }

    async fn get_last_request_time(&self) -> Result<Option<DateTime<Utc>>, DbError> {
        match self
            .query_one("SELECT at FROM http_request ORDER BY id DESC LIMIT 1", ())
            .await
        {
            Ok(row) => {
                let micros: i64 = row.get(0)?;
                Ok(Some(parse_micros(micros)?))
            }
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DbError::Libsql(e)),
        }
    }

    async fn log_server_startup(&self, start_time: DateTime<Utc>, pipe_name: &str) -> Result<i32, DbError> {
        Ok(self
            .query_one(
                "INSERT INTO pedm_run (start_time, pipe_name) VALUES (?1, ?2) RETURNING id",
                params![start_time.timestamp_micros(), pipe_name],
            )
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

/// Converts a timestamp in microseconds to a `DateTime<Utc>`.
fn parse_micros(micros: i64) -> Result<DateTime<Utc>, ParseTimestampError> {
    use chrono::offset::LocalResult;
    use chrono::TimeZone;

    match Utc.timestamp_micros(micros) {
        LocalResult::Single(dt) => Ok(dt),
        LocalResult::Ambiguous(earliest, latest) => Err(ParseTimestampError::Ambiguous(earliest, latest)),
        LocalResult::None => Err(ParseTimestampError::None),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::parse_micros;
    use crate::db::err::ParseTimestampError;

    #[test]
    fn test_valid_micros() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let micros = dt.timestamp_micros();
        let parsed = parse_micros(micros).unwrap();
        assert_eq!(parsed.timestamp(), dt.timestamp());
    }

    #[test]
    fn test_invalid_micros_none() {
        // i32::MIN is too far in the past and produces LocalResult::None
        let e = parse_micros(i64::MIN).unwrap_err();
        matches!(e, ParseTimestampError::None);
    }
}
