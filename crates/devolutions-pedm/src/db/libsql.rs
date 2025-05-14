use std::ops::Deref;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use devolutions_pedm_shared::policy::{AuthenticodeSignatureStatus, ElevationResult, User};
use libsql::params::IntoParams;
use libsql::{params, Row, Transaction, Value};

use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions, JitElevationLogRow};

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

    async fn get_user_id(&self, user: &User) -> Result<Option<i64>, DbError> {
        let mut rows = self.query(
            "SELECT id FROM user WHERE account_name = ?1 AND domain_name = ?2 AND account_sid = ?3 AND domain_sid = ?4",
            params![user.account_name.as_str(), user.domain_name.as_str(), user.account_sid.as_str(), user.domain_sid.as_str()],
        ).await?;

        if let Some(row) = rows.next().await? {
            let id: i64 = row.get(0)?;
            return Ok(Some(id));
        } else {
            return Ok(None);
        }
    }

    async fn get_or_insert_user(&self, tx: &mut Transaction, user: &User) -> Result<i64, DbError> {
        let mut rows = tx.query(
            "SELECT id FROM user WHERE account_name = ?1 AND domain_name = ?2 AND account_sid = ?3 AND domain_sid = ?4",
            params![user.account_name.as_str(), user.domain_name.as_str(), user.account_sid.as_str(), user.domain_sid.as_str()],
        ).await?;

        if let Some(row) = rows.next().await? {
            let id: i64 = row.get(0)?;
            return Ok(id);
        }

        tx.execute(
            "INSERT INTO user (account_name, domain_name, account_sid, domain_sid)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                user.account_name.as_str(),
                user.domain_name.as_str(),
                user.account_sid.as_str(),
                user.domain_sid.as_str()
            ],
        )
        .await?;

        Ok(tx.last_insert_rowid())
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
        let version = self.query_one("SELECT version FROM version", ()).await?.get::<i64>(0)?;
        Ok(i16::try_from(version)?)
    }

    async fn init_schema(&self) -> Result<(), DbError> {
        let sql = include_str!("../../schema/libsql.sql");
        self.execute_batch(sql).await?;
        Ok(())
    }

    async fn apply_pragmas(&self) -> Result<(), DbError> {
        self.execute("PRAGMA foreign_keys = ON", params![]).await?;
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
                "INSERT INTO run (start_time, pipe_name) VALUES (?1, ?2) RETURNING id",
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

    async fn insert_jit_elevation_result(&self, result: &ElevationResult) -> Result<(), DbError> {
        let signature_status = Value::Integer(match result.request.target.signature.status {
            AuthenticodeSignatureStatus::Valid => 0,
            AuthenticodeSignatureStatus::Incompatible => 1,
            AuthenticodeSignatureStatus::NotSigned => 2,
            AuthenticodeSignatureStatus::HashMismatch => 3,
            AuthenticodeSignatureStatus::NotSupportedFileFormat => 4,
            AuthenticodeSignatureStatus::NotTrusted => 5,
        });

        let signature_issuer: Option<&str> = result
            .request
            .target
            .signature
            .signer
            .as_ref()
            .map(|s| s.issuer.as_str());

        let mut tx = self.transaction().await?;

        tx.execute(
            "INSERT INTO signature (authenticode_sig_status, issuer) VALUES (?1, ?2)",
            params![signature_status, signature_issuer],
        )
        .await?;

        let sig_id = self.last_insert_rowid();
        let user_id = self.get_or_insert_user(&mut tx, &result.request.target.user).await?;

        tx.execute("INSERT INTO jit_elevation_result (success, timestamp, asker_path, target_path, target_command_line, target_working_directory, target_sha1, target_sha256, target_user_id, target_signature_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)", 
        params![
            result.successful,
            result.request.unix_timestamp_seconds,
            result.request.asker.path.to_string_lossy(),
            result.request.target.path.to_string_lossy(),
            result.request.target.command_line.join(" "),
            result.request.target.working_directory.to_string_lossy(),
            result.request.target.hash.sha1.as_str(),
            result.request.target.hash.sha256.as_str(),
            user_id,
            sig_id
        ]).await?;

        tx.commit().await?;
        Ok(())
    }

    async fn get_jit_elevation_logs(
        &self,
        query_options: JitElevationLogQueryOptions,
    ) -> Result<JitElevationLogPage, DbError> {
        let user_id = if let Some(user) = &query_options.user {
            self.get_user_id(user).await?
        } else {
            None
        };

        let joins = String::from(" LEFT JOIN user u_display ON jit.target_user_id = u_display.id");
        let mut base_sql = String::from(" FROM jit_elevation_result jit");
        let mut where_clauses = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if user_id.is_some() {
            base_sql.push_str(" INNER JOIN user u ON jit.target_user_id = u.id");
            where_clauses.push("u.id = ?");
            params.push(user_id.into());
        }

        where_clauses.push("jit.timestamp >= ?");
        params.push(query_options.start_time.into());

        where_clauses.push("jit.timestamp <= ?");
        params.push(query_options.end_time.into());

        let where_sql = format!(" WHERE {}", where_clauses.join(" AND "));

        let count_sql = format!("SELECT COUNT(*) {}", &base_sql) + &where_sql;
        let total_records_row = self
            .query_one(&count_sql, libsql::params_from_iter(params.clone()))
            .await?;
        let total_records: i64 = total_records_row.get(0)?;
        let total_pages =
            ((total_records + query_options.page_size as i64 - 1) / query_options.page_size as i64) as u32;

        let sort_columns = ["success", "timestamp", "target_path", "target_user_id"];
        let sort_column = if sort_columns.contains(&query_options.sort_column.as_str()) {
            query_options.sort_column.as_str()
        } else {
            "timestamp"
        };
        let sort_order = if query_options.sort_descending { "DESC" } else { "ASC" };

        let limit = query_options.page_size as i64;
        let offset = (query_options.page_number.saturating_sub(1) * query_options.page_size) as i64;

        let select_sql = format!(
            "SELECT jit.id, jit.timestamp, jit.success, jit.asker_path, jit.target_path, u_display.account_name, u_display.domain_name, u_display.account_sid, u_display.domain_sid {} ORDER BY jit.{} {} LIMIT ? OFFSET ?",
            base_sql + &joins + &where_sql,
            sort_column,
            sort_order
        );

        params.push(limit.into());
        params.push(offset.into());

        let mut stmt = self.prepare(&select_sql).await?;
        let mut rows = stmt.query(libsql::params_from_iter(params)).await?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().await? {
            results.push(JitElevationLogRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                success: row.get(2)?,
                target_path: row.get(3)?,
                user: User {
                    account_name: row.get(4)?,
                    domain_name: row.get(5)?,
                    account_sid: row.get(6)?,
                    domain_sid: row.get(7)?,
                },
            });
        }

        Ok(JitElevationLogPage {
            total_pages: total_pages,
            total_records: total_records as u32,
            results,
        })
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
