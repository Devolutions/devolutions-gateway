use std::ops::Deref;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use devolutions_pedm_shared::policy::{
    Assignment, AuthenticodeSignatureStatus, ElevationKind, ElevationMethod, ElevationResult, Hash, Profile, Signature,
    Signer, User,
};
use libsql::params::IntoParams;
use libsql::{Row, Transaction, Value, params};

use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions, JitElevationLogRow};

use super::err::{DataIntegrityError, InvalidEnumError, ParseTimestampError};
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

    fn profile_from_row(row: &Row) -> Result<Profile, DbError> {
        Ok(Profile {
            id: row.get(0)?,
            name: row.get(1)?,
            description: row.get(2)?,
            elevation_method: match row.get::<i64>(3)? {
                0 => ElevationMethod::LocalAdmin,
                1 => ElevationMethod::VirtualAccount,
                n => {
                    return Err(DbError::InvalidEnum(InvalidEnumError {
                        value: n,
                        enum_name: "ElevationMethod",
                    }));
                }
            },
            default_elevation_kind: match row.get::<i64>(4)? {
                0 => ElevationKind::AutoApprove,
                1 => ElevationKind::Confirm,
                2 => ElevationKind::ReasonApproval,
                3 => ElevationKind::Deny,
                n => {
                    return Err(DbError::InvalidEnum(InvalidEnumError {
                        value: n,
                        enum_name: "ElevationKind",
                    }));
                }
            },
            target_must_be_signed: row.get::<bool>(5)?,
        })
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

        tx.execute(
            "INSERT INTO jit_elevation_result (
                success, 
                timestamp, 
                asker_path, 
                target_path,
                target_command_line,
                target_working_directory, 
                target_sha1, 
                target_sha256, 
                target_user_id, 
                target_signature_id) 
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
            ],
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn get_profiles(&self) -> Result<Vec<Profile>, DbError> {
        let stmt = self
            .prepare(
                "
            SELECT 
                id, 
                name, 
                description, 
                jit_elevation_method, 
                jit_elevation_default_kind, 
                jit_elevation_target_must_be_signed 
            FROM profile",
            )
            .await?;

        let mut rows = stmt.query(params![]).await?;
        let mut profiles = Vec::new();

        while let Some(row) = rows.next().await? {
            profiles.push(LibsqlConn::profile_from_row(&row)?);
        }

        Ok(profiles)
    }

    async fn get_profiles_for_user(&self, user: &User) -> Result<Vec<Profile>, DbError> {
        let stmt = self
            .prepare(
                "
                SELECT DISTINCT
                    p.id,
                    p.name,
                    p.description, 
                    p.jit_elevation_method, 
                    p.jit_elevation_default_kind,
                    p.jit_elevation_target_must_be_signed
                FROM profile p
                JOIN policy pol ON pol.profile_id = p.id
                JOIN user u
                    ON u.account_name = ?1
                    AND u.domain_name = ?2
                    AND u.account_sid = ?3
                    AND u.domain_sid = ?4
                WHERE pol.user_id = u.id;",
            )
            .await?;

        let mut rows = stmt
            .query(params![
                user.account_name.as_str(),
                user.domain_name.as_str(),
                user.account_sid.as_str(),
                user.domain_sid.as_str()
            ])
            .await?;
        let mut profiles = Vec::new();

        while let Some(row) = rows.next().await? {
            profiles.push(LibsqlConn::profile_from_row(&row)?);
        }

        Ok(profiles)
    }

    async fn get_profile(&self, id: i64) -> Result<Option<Profile>, DbError> {
        let mut stmt = self
            .prepare(
                "
                SELECT 
                    id, 
                    name, 
                    description, 
                    jit_elevation_method, 
                    jit_elevation_default_kind,
                    jit_elevation_target_must_be_signed 
                FROM profile 
                WHERE id = ?",
            )
            .await?;

        let row = stmt.query_row(params![id]).await;

        match row {
            Ok(r) => Ok(Some(LibsqlConn::profile_from_row(&r)?)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => return Err(e.into()),
        }
    }

    async fn insert_profile(&self, profile: &Profile) -> Result<(), DbError> {
        let elevation_method = Value::Integer(match profile.elevation_method {
            ElevationMethod::LocalAdmin => 0,
            ElevationMethod::VirtualAccount => 1,
        });
        let elevation_kind = Value::Integer(match profile.default_elevation_kind {
            ElevationKind::AutoApprove => 0,
            ElevationKind::Confirm => 1,
            ElevationKind::ReasonApproval => 2,
            ElevationKind::Deny => 3,
        });

        match profile.id {
            0 => {
                self.execute(
                    "
                    INSERT INTO profile (
                        name, 
                        description, 
                        jit_elevation_method, 
                        jit_elevation_default_kind, 
                        jit_elevation_target_must_be_signed)
                    VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        profile.name.as_str(),
                        match &profile.description {
                            Some(description) => Value::Text(description.clone()),
                            None => Value::Null,
                        },
                        elevation_method,
                        elevation_kind,
                        profile.target_must_be_signed,
                    ],
                )
                .await?;
            }
            _ => {
                self.execute(
                    "
                    UPDATE profile
                    SET 
                        name = ?2, 
                        description = ?3, 
                        jit_elevation_method = ?4, 
                        jit_elevation_default_kind = ?5, 
                        jit_elevation_target_must_be_signed = ?6
                    WHERE id = ?1",
                    params![
                        profile.id,
                        profile.name.as_str(),
                        match &profile.description {
                            Some(description) => Value::Text(description.clone()),
                            None => Value::Null,
                        },
                        elevation_method,
                        elevation_kind,
                        profile.target_must_be_signed,
                    ],
                )
                .await?;
            }
        }

        Ok(())
    }

    // TODO cascade deletes
    async fn delete_profile(&self, id: i64) -> Result<(), DbError> {
        self.execute("DELETE FROM profile WHERE id = ?1;", params![id]).await?;

        Ok(())
    }

    async fn get_assignments(&self) -> Result<Vec<Assignment>, DbError> {
        let mut assignments = Vec::new();
        let mut rows = self
            .query(
                "
                SELECT
                    p.id,
                    p.name,
                    p.description,
                    p.jit_elevation_method,
                    p.jit_elevation_default_kind,
                    p.jit_elevation_target_must_be_signed,
                    u.id,
                    u.account_name,
                    u.domain_name,
                    u.account_sid,
                    u.domain_sid
                FROM profile p
                LEFT JOIN policy pol ON pol.profile_id = p.id
                LEFT JOIN user u ON u.id = pol.user_id
                ORDER BY p.id;",
                params![],
            )
            .await?;

        let mut current_profile_id: Option<i64> = None;
        let mut current_assignment: Option<Assignment> = None;

        while let Some(row) = rows.next().await? {
            let profile_id = row.get::<i64>(0)?;

            if current_profile_id != Some(profile_id) {
                if let Some(a) = current_assignment.take() {
                    assignments.push(a);
                }

                current_profile_id = Some(profile_id);
                current_assignment = Some(Assignment {
                    profile: Profile {
                        id: profile_id,
                        name: row.get(1)?,
                        description: row.get(2)?,
                        elevation_method: match row.get::<i64>(3)? {
                            0 => ElevationMethod::LocalAdmin,
                            1 => ElevationMethod::VirtualAccount,
                            n => {
                                return Err(DbError::InvalidEnum(InvalidEnumError {
                                    value: n,
                                    enum_name: "ElevationMethod",
                                }));
                            }
                        },
                        default_elevation_kind: match row.get::<i64>(4)? {
                            0 => ElevationKind::AutoApprove,
                            1 => ElevationKind::Confirm,
                            2 => ElevationKind::ReasonApproval,
                            3 => ElevationKind::Deny,
                            n => {
                                return Err(DbError::InvalidEnum(InvalidEnumError {
                                    value: n,
                                    enum_name: "ElevationKind",
                                }));
                            }
                        },
                        target_must_be_signed: row.get::<bool>(5)?,
                    },
                    users: Vec::new(),
                });
            }

            if let Some(a) = current_assignment.as_mut() {
                let user_id: Option<i64> = row.get(6)?;

                if user_id.is_some() {
                    a.users.push(User {
                        account_name: row.get(7)?,
                        domain_name: row.get(8)?,
                        account_sid: row.get(9)?,
                        domain_sid: row.get(10)?,
                    });
                }
            }
        }

        if let Some(a) = current_assignment {
            assignments.push(a);
        }

        Ok(assignments)
    }

    async fn get_assignment(&self, profile: &Profile) -> Result<Assignment, DbError> {
        let mut users = Vec::new();

        let mut rows = self
            .query(
                "
                SELECT
                    u.account_name,
                    u.domain_name,
                    u.account_sid,
                    u.domain_sid
                FROM policy pol
                JOIN user u ON u.id = pol.user_id
                WHERE pol.profile_id = ?1
                ",
                params![profile.id],
            )
            .await?;

        while let Some(row) = rows.next().await? {
            users.push(User {
                account_name: row.get(0)?,
                domain_name: row.get(1)?,
                account_sid: row.get(2)?,
                domain_sid: row.get(3)?,
            });
        }

        Ok(Assignment {
            profile: profile.clone(),
            users,
        })
    }

    async fn set_assignments(&self, profile_id: i64, users: Vec<User>) -> Result<(), DbError> {
        let mut tx: Transaction = self.transaction().await?;

        tx.execute("DELETE FROM policy WHERE profile_id = ?1", params![profile_id])
            .await?;

        for user in users {
            let user_id = self.get_or_insert_user(&mut tx, &user).await?;

            tx.execute(
                "INSERT INTO policy (profile_id, user_id) VALUES (?1, ?2)",
                params![profile_id, user_id],
            )
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn set_user_profile(&self, user: &User, profile_id: i64) -> Result<(), DbError> {
        let user_id = self
            .get_user_id(user)
            .await?
            .ok_or(DbError::DataIntegrity(DataIntegrityError {
                message: "set_user_profile for unknown user.id",
            }))?;

        // TODO We're not properly atomic here, because there is a small chance of the user being removed
        self.execute(
            "
                INSERT INTO user_profile (user_id, profile_id)
                SELECT ?1, ?2
                WHERE ?2 IS NULL
                OR EXISTS (
                    SELECT 1 FROM policy WHERE user_id = ?1 AND profile_id = ?2
                )
                ON CONFLICT(user_id) DO UPDATE SET profile_id = excluded.profile_id;
            ",
            params![
                user_id,
                match profile_id {
                    0 => Value::Null,
                    _ => Value::Integer(profile_id),
                }
            ],
        )
        .await?;

        Ok(())
    }

    async fn get_user_profile(&self, user: &User) -> Result<Option<Profile>, DbError> {
        let user_id = self
            .get_user_id(user)
            .await?
            .ok_or(DbError::DataIntegrity(DataIntegrityError {
                message: "set_user_profile for unknown user.id",
            }))?;

        // TODO We're not properly atomic here, because there is a small chance of the user being removed
        let row = self
            .query_one(
                "
                SELECT p.id, p.name, p.description,
                    p.jit_elevation_method, p.jit_elevation_default_kind,
                    p.jit_elevation_target_must_be_signed
                FROM user u
                JOIN user_profile up ON up.user_id = u.id
                JOIN profile p ON p.id = up.profile_id
                WHERE u.id = ?1
                ",
                params![user_id],
            )
            .await;

        match row {
            Ok(r) => Ok(Some(LibsqlConn::profile_from_row(&r)?)),
            Err(libsql::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => return Err(e.into()),
        }
    }

    async fn get_users(&self) -> Result<Vec<User>, DbError> {
        let stmt = self
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

    async fn get_user_id(&self, user: &User) -> Result<Option<i64>, DbError> {
        let mut rows = self.query(
            "SELECT id FROM user WHERE account_name = ?1 AND domain_name = ?2 AND account_sid = ?3 AND domain_sid = ?4",
            params![user.account_name.as_str(), user.domain_name.as_str(), user.account_sid.as_str(), user.domain_sid.as_str()],
        ).await?;

        if let Some(row) = rows.next().await? {
            let id: i64 = row.get(0)?;
            Ok(Some(id))
        } else {
            Ok(None)
        }
    }

    async fn get_jit_elevation_log(&self, id: i64) -> Result<Option<JitElevationLogRow>, DbError> {
        let stmt = self
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
                            }));
                        }
                    },
                    signer: row.get::<Option<String>>(15)?.map(|issuer| Signer { issuer }),
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

        let mut count_sql = format!("SELECT COUNT(*) {}", &base_sql);
        count_sql.push_str(&where_sql);
        let total_records_row = self
            .query_one(&count_sql, libsql::params_from_iter(params.clone()))
            .await?;
        let total_records: i64 = total_records_row.get(0)?;
        let total_pages = u32::try_from(
            (total_records + i64::from(query_options.page_size) - 1) / i64::from(query_options.page_size),
        )?;

        let sort_columns = ["success", "timestamp", "target_path", "target_user_id"];
        let sort_column = if sort_columns.contains(&query_options.sort_column.as_str()) {
            query_options.sort_column.as_str()
        } else {
            "timestamp"
        };
        let sort_order = if query_options.sort_descending { "DESC" } else { "ASC" };

        let limit = i64::from(query_options.page_size);
        let offset = i64::from(query_options.page_number.saturating_sub(1) * query_options.page_size);

        base_sql.push_str(&joins);
        base_sql.push_str(&where_sql);
        let select_sql = format!(
            "SELECT jit.id, jit.timestamp, jit.success, jit.target_path, u_display.account_name, u_display.domain_name, u_display.account_sid, u_display.domain_sid {base_sql} ORDER BY jit.{sort_column} {sort_order} LIMIT ? OFFSET ?"
        );

        params.push(limit.into());
        params.push(offset.into());

        let stmt = self.prepare(&select_sql).await?;
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
            total_pages,
            total_records: u32::try_from(total_records)?,
            results,
        })
    }
}

/// Converts a timestamp in microseconds to a `DateTime<Utc>`.
fn parse_micros(micros: i64) -> Result<DateTime<Utc>, ParseTimestampError> {
    use chrono::TimeZone;
    use chrono::offset::LocalResult;

    match Utc.timestamp_micros(micros) {
        LocalResult::Single(dt) => Ok(dt),
        LocalResult::Ambiguous(earliest, latest) => Err(ParseTimestampError::Ambiguous(earliest, latest)),
        LocalResult::None => Err(ParseTimestampError::None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

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
