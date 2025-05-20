//! Concrete implementation of the `Database` trait for libSQL.
//!
//! It is important to note that Transaction` is owned and `Transaction::clone` returns a connection.
//! For these reasons, we run database operations serially.

use std::collections::HashMap;
use std::ops::Deref;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, TryStreamExt};
use libsql::params::IntoParams;
use libsql::{params, Row, Transaction, Value};

use devolutions_pedm_shared::policy::{AuthenticodeSignatureStatus, ElevationResult, Hash, Signature, Signer, User};
use tracing::info;

use crate::account::{AccountWithId, AccountsDiff, DomainId, Sid};
use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions, JitElevationLogRow};

use super::err::{InvalidEnumError, ParseTimestampError};
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

    async fn get_users(&self) -> Result<Vec<User>, DbError> {
        let mut stmt = self
            .prepare("SELECT id, account_name, domain_name, account_sid, domain_sid FROM user")
            .await?;

        let mut rows = stmt.query(params![]).await?;
        let mut users = Vec::new();

        while let Some(row) = rows.next().await? {
            users.push(User {
                account_name: row.get(1)?,
                domain_name: row.get(2)?,
                account_sid: row.get(3)?,
                domain_sid: row.get(4)?,
            });
        }

        Ok(users)
    }

    async fn get_jit_elevation_log(&self, id: i64) -> Result<Option<JitElevationLogRow>, DbError> {
        let mut stmt = self
            .prepare(
                "SELECT
                j.id,
                j.success,
                j.timestamp,
                j.asker_path,
                j.target_path,
                j.target_command_line,
                j.target_working_directory,
                j.target_sha1,
                j.target_sha256,
                u.account_name,
                u.domain_name,
                u.account_sid,
                u.domain_sid,
                s.id,
                s.authenticode_sig_status,
                s.issuer
             FROM jit_elevation_result j
             LEFT JOIN user u ON j.target_user_id = u.id
             LEFT JOIN signature s ON j.target_signature_id = s.id
             WHERE j.id = ?",
            )
            .await?;

        let mut rows = stmt.query(params![id]).await?;
        if let Some(row) = rows.next().await? {
            let target_user = match row.get::<Option<String>>(9)? {
                Some(account_name) => Some(User {
                    account_name,
                    domain_name: row.get(10)?,
                    account_sid: row.get(11)?,
                    domain_sid: row.get(12)?,
                }),
                None => None,
            };

            let target_signature = match row.get::<Option<i64>>(13)? {
                Some(_) => Some(Signature {
                    status: match row.get::<i64>(14)? {
                        0 => AuthenticodeSignatureStatus::Valid,
                        1 => AuthenticodeSignatureStatus::Incompatible,
                        2 => AuthenticodeSignatureStatus::NotSigned,
                        3 => AuthenticodeSignatureStatus::HashMismatch,
                        4 => AuthenticodeSignatureStatus::NotSupportedFileFormat,
                        5 => AuthenticodeSignatureStatus::NotTrusted,
                        n => {
                            return Err(DbError::InvalidEnum(InvalidEnumError {
                                value: n,
                                enum_name: "AuthenticodeSignatureStatus",
                            }))
                        }
                    },
                    signer: match row.get::<Option<String>>(15)? {
                        Some(issuer) => Some(Signer { issuer }),
                        None => None,
                    },
                    certificates: None,
                }),
                None => None,
            };

            Ok(Some(JitElevationLogRow {
                id: row.get(0)?,
                success: row.get(1)?,
                timestamp: row.get(2)?,
                asker_path: row.get(3)?,
                target_path: row.get(4)?,
                target_command_line: row.get(5)?,
                target_working_directory: row.get(6)?,
                target_hash: Some(Hash {
                    sha1: row.get(7)?,
                    sha256: row.get(8)?,
                }),
                user: target_user,
                target_signature,
            }))
        } else {
            Ok(None)
        }
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
            "SELECT jit.id, jit.timestamp, jit.success, jit.target_path, u_display.account_name, u_display.domain_name, u_display.account_sid, u_display.domain_sid {} ORDER BY jit.{} {} LIMIT ? OFFSET ?",
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
                user: Some(User {
                    account_name: row.get(4)?,
                    domain_name: row.get(5)?,
                    account_sid: row.get(6)?,
                    domain_sid: row.get(7)?,
                }),
                ..Default::default()
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
