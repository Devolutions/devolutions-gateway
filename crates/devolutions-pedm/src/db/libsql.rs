//! Concrete implementation of the `Database` trait for libSQL.
//!
//! It is important to note that Transaction` is owned and `Transaction::clone` returns a connection.
//! For these reasons, we run database operations serially.

use std::collections::HashMap;
use std::ops::Deref;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use devolutions_pedm_shared::policy::ElevationResult;
use futures_util::{StreamExt, TryStreamExt};
use libsql::params::IntoParams;
use libsql::{params, Row, Value};
use tracing::info;

use crate::account::{AccountWithId, AccountsDiff, DomainId, Sid};

use super::err::ParseTimestampError;
use super::util::{bulk_insert_statement_generic, query_args_inline_generic, query_args_single_generic};
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
        let version = self.query_one("SELECT version FROM version", ()).await?.get::<i64>(0)?;
        Ok(i16::try_from(version)?)
    }

    async fn init_schema(&self) -> Result<(), DbError> {
        let sql = include_str!("../../schema/libsql.sql");
        self.execute_batch(sql).await?;
        Ok(())
    }

    async fn apply_pragmas(&self) -> Result<(), DbError> {
        // TODO: run pragmas
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

    async fn get_accounts(&self) -> Result<Vec<AccountWithId>, DbError> {
        let statement = "SELECT a.id,
       n.name,
       d.id,
       d.subauth1,
       d.subauth2,
       d.subauth3,
       d.subauth4,
       s.relative_id
FROM account a
         JOIN account_name n ON a.id = n.id
    AND n.valid_to IS NULL
         JOIN account_sid sa ON a.id = sa.account_id
    AND sa.valid_to IS NULL
         JOIN sid s ON sa.sid_id = s.id
         JOIN domain d ON s.domain_id = d.id
         LEFT JOIN account_removed r ON a.id = r.id
    AND r.valid_to IS NULL
WHERE r.id IS NULL
ORDER BY n.name";

        self.query(statement, ())
            .await?
            .into_stream()
            .then(|row| async move {
                let row = row?;
                Ok(AccountWithId {
                    id: i16::try_from(row.get::<i64>(0)?)?,
                    name: row.get(1)?,
                    internal_domain_id: i16::try_from(row.get::<i64>(2)?)?,
                    sid: Sid {
                        domain_id: DomainId {
                            subauth1: u8::try_from(row.get::<i64>(3)?)?,
                            subauth2: u32::try_from(row.get::<i64>(4)?)?,
                            subauth3: u32::try_from(row.get::<i64>(5)?)?,
                            subauth4: u32::try_from(row.get::<i64>(6)?)?,
                        },
                        relative_id: i16::try_from(row.get::<i64>(7)?)?,
                    },
                })
            })
            .try_collect()
            .await
    }

    async fn update_accounts(&self, diff: &AccountsDiff) -> Result<(), DbError> {
        let tx = self.transaction().await?;
        tx.execute("INSERT INTO account_diff_request DEFAULT VALUES", ())
            .await?;

        if diff.is_empty() {
            tx.commit().await?;
            return Ok(());
        }

        // Add new accounts.
        if !(diff.added.is_empty() && diff.added_or_changed_sid.is_empty()) {
            let accounts = diff.added_all();

            // Insert SIDs into the `sid` table and get the DB-generated SID IDs.

            let new_domains = diff.potentially_new_domains();
            let mut domain_map = diff.known_domain_ids.clone();

            // Add potentially new domain IDs to the database and update the map with the DB-generated IDs.
            if !new_domains.is_empty() {
                let params = new_domains
                    .iter()
                    .flat_map(|id| {
                        [
                            id.subauth1.into(),
                            id.subauth2.into(),
                            id.subauth3.into(),
                            id.subauth4.into(),
                        ]
                    })
                    .collect::<Vec<Value>>();
                let mut statement = bulk_insert_statement(
                    "domain",
                    &["subauth1", "subauth2", "subauth3", "subauth4"],
                    new_domains.len(),
                );
                // The domain ID we are inserting may already exist. If it does exist, retrieve the existing ID.
                statement.push_str(" ON CONFLICT (subauth1, subauth2, subauth3, subauth4) DO UPDATE SET subauth1 = EXCLUDED.subauth1 RETURNING id");
                let db_domain_ids = tx
                    .query(&statement, params)
                    .await?
                    .into_stream()
                    .then(|row| async {
                        let val: i64 = row?.get(0)?;
                        Ok::<_, DbError>(i16::try_from(val)?)
                    })
                    .try_collect::<Vec<_>>()
                    .await?;
                let new_map = new_domains
                    .iter()
                    .cloned()
                    .zip(db_domain_ids.into_iter())
                    .collect::<HashMap<_, _>>();
                // Add to the existing map.
                domain_map.extend(new_map);
            }

            // Insert SIDs.
            let params = accounts
                .iter()
                .flat_map(|a| {
                    let domain_id = &domain_map[&a.sid.domain_id];
                    [(*domain_id), a.sid.relative_id]
                })
                .collect::<Vec<_>>();
            let mut statement = bulk_insert_statement("sid", &["domain_id", "relative_id"], accounts.len());
            statement.push_str(" RETURNING id");

            // Return the DB-generated SID IDs.
            let rows = tx.query(&statement, params).await?;
            let sid_ids = rows
                .into_stream()
                .then(|row| async { row?.get::<i64>(0) })
                .try_collect::<Vec<_>>()
                .await?;

            // Create accounts by inserting into the `account` table and get the account IDs.
            // This is a hacky way to insert multiple rows with default values in one statement.
            // Unfortunately, it doesn't support `RETURNING`.
            let mut statement = String::from("INSERT INTO account SELECT NULL");
            for _ in 0..accounts.len() {
                statement.push_str(" UNION ALL SELECT NULL");
            }
            #[allow(clippy::cast_possible_wrap)]
            let len = accounts.len() as i64;
            tx.execute(&statement, [len]).await?;

            // Get the newly created account IDs.
            let account_ids = tx
                .query("SELECT id FROM account ORDER BY id DESC LIMIT ?", [len])
                .await?
                .into_stream()
                .then(|row| async { row?.get::<i64>(0) })
                .try_collect::<Vec<_>>()
                .await?;

            // Insert account name.
            let params = account_ids
                .iter()
                .zip(&accounts)
                .flat_map(|(&id, a)| [id.into(), a.name.clone().into()])
                .collect::<Vec<Value>>();
            let statement = bulk_insert_statement("account_name", &["id", "name"], accounts.len());
            tx.execute(&statement, params).await?;

            // Insert account SID.
            let params = account_ids
                .iter()
                .zip(&sid_ids)
                .flat_map(|(account_id, sid)| [(*account_id).into(), (*sid).into()])
                .collect::<Vec<Value>>();
            let statement = bulk_insert_statement("account_sid", &["account_id", "sid_id"], accounts.len());
            tx.execute(&statement, params).await?;
        }

        // Remove accounts.
        if !diff.removed.is_empty() {
            info!("Accounts to remove");
            let records = &diff.removed;
            let params = records.iter().map(|id| Value::from(*id)).collect::<Vec<_>>();
            let statement = format!(
                "UPDATE account_removed SET valid_to = {NOW} WHERE id IN {} AND valid_to IS NULL",
                query_args_inline(records.len())
            );
            tx.execute(&statement, params.clone()).await?;
            let statement = format!(
                "INSERT INTO account_removed (id) VALUES {}",
                query_args_single(records.len())
            );
            tx.execute(&statement, params).await?;
        };

        // Update accounts with changed names.
        if !diff.changed_name.is_empty() {
            info!("accounts to update");
            let records = &diff.changed_name;
            let params = records
                .iter()
                .flat_map(|(id, name)| [(*id).into(), name.clone().into()])
                .collect::<Vec<Value>>();
            let statement = format!(
                "UPDATE account_name SET valid_to = {NOW} WHERE id IN {} AND valid_to IS NULL",
                query_args_single(records.len())
            );
            tx.execute(&statement, params.clone()).await?;
            let statement = bulk_insert_statement("account_name", &["id", "name"], records.len());
            tx.execute(&statement, params).await?;
        };
        tx.commit().await?;
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
        // TODO: execute the SQL query.
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

/// Constructs query args like `(?1), (?2), (?3)`.
fn query_args_single(num_records: usize) -> String {
    query_args_single_generic(num_records, '?')
}

/// Constructs n query args like `(?1, ?2, ?3)`.
///
/// This is useful for `IN`.
fn query_args_inline(num_records: usize) -> String {
    query_args_inline_generic(num_records, '?')
}

/// Constructs an insert statement for bulk inserts.
///
/// The output is like `INSERT INTO table_name (col1, col2, col3) VALUES (?1, ?2, ?3), (?4, ?5, ?6)`.
fn bulk_insert_statement(table_name: &str, col_names: &[&str], num_records: usize) -> String {
    bulk_insert_statement_generic(table_name, col_names, num_records, '?')
}

/// The current time in microseconds.
//
// We use this because `libsql` does not support creating scalar functions.
const NOW: &str = "(strftime('%s', 'now') * 1000000 + (strftime('%f', 'now') * 1000000) % 1000000)";

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use crate::db::err::ParseTimestampError;
    use crate::db::libsql::parse_micros;

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
