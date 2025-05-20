#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use std::collections::HashMap;
use std::ops::Deref;

use async_trait::async_trait;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use chrono::{DateTime, Utc};
use futures_util::try_join;
use tokio_postgres::types::ToSql;
use tokio_postgres::NoTls;

use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions};
use devolutions_pedm_shared::policy::ElevationResult;

use crate::account::{AccountWithId, AccountsDiff, DomainId, Sid};

use super::util::{bulk_insert_statement_generic, query_args_inline_generic, query_args_single_generic};
use super::{Database, DbError};

type Params<'a> = Vec<&'a (dyn ToSql + Sync)>;

pub(crate) struct PgPool(Pool<PostgresConnectionManager<NoTls>>);

impl PgPool {
    pub(crate) fn new(pool: Pool<PostgresConnectionManager<NoTls>>) -> Self {
        Self(pool)
    }
}

impl Deref for PgPool {
    type Target = Pool<PostgresConnectionManager<NoTls>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl Database for PgPool {
    async fn get_schema_version(&self) -> Result<i16, DbError> {
        Ok(self
            .get()
            .await?
            .query_one("SELECT version FROM version", &[])
            .await?
            .get(0))
    }

    async fn init_schema(&self) -> Result<(), DbError> {
        let sql = include_str!("../../schema/pg.sql");
        self.get().await?.batch_execute(sql).await?;
        Ok(())
    }

    async fn apply_pragmas(&self) -> Result<(), DbError> {
        // nothing to do
        Ok(())
    }

    async fn get_last_request_id(&self) -> Result<i32, DbError> {
        Ok(self
            .get()
            .await?
            .query_opt("SELECT id FROM http_request ORDER BY id DESC LIMIT 1", &[])
            .await?
            .map(|r| r.get(0))
            .unwrap_or_default())
    }

    async fn get_last_request_time(&self) -> Result<Option<DateTime<Utc>>, DbError> {
        Ok(self
            .get()
            .await?
            .query_opt("SELECT at FROM http_request ORDER BY id DESC LIMIT 1", &[])
            .await?
            .map(|r| r.get(0)))
    }

    async fn log_server_startup(&self, start_time: DateTime<Utc>, pipe_name: &str) -> Result<i32, DbError> {
        Ok(self
            .get()
            .await?
            .query_one(
                "INSERT INTO run (start_time, pipe_name) VALUES ($1, $2) RETURNING id",
                &[&start_time, &pipe_name],
            )
            .await?
            .get(0))
    }

    async fn log_http_request(&self, req_id: i32, method: &str, path: &str, status_code: i16) -> Result<(), DbError> {
        self.get()
            .await?
            .execute(
                "INSERT INTO http_request (id, method, path, status_code) VALUES ($1, $2, $3, $4)",
                &[&req_id, &method, &path, &status_code],
            )
            .await?;
        Ok(())
    }

    async fn get_accounts(&self) -> Result<Vec<AccountWithId>, DbError> {
        Ok(self
            .get()
            .await?
            .query(
                "SELECT a.id,
       n.name,
       d.id,
       d.subauth1,
       d.subauth2,
       d.subauth3,
       d.subauth4,
       s.relative_id
FROM account a
         JOIN account_name n ON a.id = n.id
    AND n.during @> now()
         JOIN account_sid sa
              ON a.id = sa.account_id
                  AND sa.during @> now()
         JOIN sid s ON sa.sid_id = s.id
         JOIN domain d ON s.domain_id = d.id
         LEFT JOIN account_removed r ON a.id = r.id
    AND r.during @> now()
WHERE r.id IS NULL
ORDER BY n.name",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| AccountWithId {
                id: row.get(0),
                name: row.get(1),
                internal_domain_id: row.get(2),
                sid: Sid {
                    domain_id: DomainId {
                        subauth1: row.get::<_, i16>(3) as u8,
                        subauth2: row.get::<_, i64>(4) as u32,
                        subauth3: row.get::<_, i64>(5) as u32,
                        subauth4: row.get::<_, i64>(6) as u32,
                    },
                    relative_id: row.get(7),
                },
            })
            .collect())
    }

    async fn update_accounts(&self, diff: &AccountsDiff) -> Result<(), DbError> {
        let mut conn = self.get().await?;
        let tx = conn.transaction().await?;
        tx.execute("INSERT INTO account_diff_request DEFAULT VALUES", &[])
            .await?;

        if diff.is_empty() {
            tx.commit().await?;
            return Ok(());
        }

        let add_fut = async {
            if diff.added.is_empty() && diff.added_or_changed_sid.is_empty() {
                return Ok::<_, tokio_postgres::Error>(());
            }
            let accounts = diff.added_all();

            // Insert SIDs into the `sid` table and get the DB-generated SID IDs.
            let sid_fut = async {
                let new_domains = diff.potentially_new_domains();
                let mut domain_map = diff.known_domain_ids.clone();

                // Add potentially new domain IDs to the database and update the map with the DB-generated IDs.
                if !new_domains.is_empty() {
                    let mut params: Params<'_> = Vec::with_capacity(new_domains.len() * 4);
                    // Convert some types.
                    let parts = new_domains
                        .iter()
                        .map(|id| {
                            (
                                i16::from(id.subauth1),
                                i64::from(id.subauth2),
                                i64::from(id.subauth3),
                                i64::from(id.subauth4),
                            )
                        })
                        .collect::<Vec<_>>();
                    for (subauth1, subauth2, subauth3, subauth4) in parts.iter().take(new_domains.len()) {
                        params.push(subauth1);
                        params.push(subauth2);
                        params.push(subauth3);
                        params.push(subauth4);
                    }
                    let mut statement = bulk_insert_statement(
                        "domain",
                        &["subauth1", "subauth2", "subauth3", "subauth4"],
                        new_domains.len(),
                    );
                    // The domain ID we are inserting may already exist. If it does exist, retrieve the existing ID.
                    statement.push_str(" ON CONFLICT (subauth1, subauth2, subauth3, subauth4) DO UPDATE SET subauth1 = EXCLUDED.subauth1 RETURNING id");
                    let db_domain_ids: Vec<i16> = tx
                        .query(&statement, &params)
                        .await?
                        .into_iter()
                        .map(|row| row.get(0))
                        .collect::<Vec<i16>>();
                    let new_map = new_domains
                        .iter()
                        .cloned()
                        .zip(db_domain_ids.into_iter())
                        .collect::<HashMap<_, _>>();
                    // Add to the existing map.
                    domain_map.extend(new_map);
                };

                // Insert SIDs.
                let mut params: Params<'_> = Vec::with_capacity(accounts.len() * 2);
                for a in &accounts {
                    // look up the domain ID in map
                    let domain_id = &domain_map[&a.sid.domain_id];
                    params.push(domain_id);
                    params.push(&a.sid.relative_id);
                }
                let mut statement = bulk_insert_statement("sid", &["domain_id", "relative_id"], accounts.len());
                statement.push_str(" RETURNING id");

                // Return the DB-generated SID IDs.
                Ok(tx
                    .query(&statement, &params)
                    .await?
                    .into_iter()
                    .map(|row| row.get(0))
                    .collect::<Vec<i16>>())
            };

            // Create accounts by inserting into the `account` table and get the account IDs.
            let account_fut = async {
                Ok(tx
                    .query(
                        "INSERT INTO account SELECT FROM generate_series(1, $1) RETURNING id",
                        &[&(accounts.len() as i32)],
                    )
                    .await?
                    .into_iter()
                    .map(|row| row.get(0))
                    .collect::<Vec<i16>>())
            };
            let (sid_ids, account_ids) = try_join!(sid_fut, account_fut)?;

            // Insert account name.
            let name_fut = async {
                let mut params: Params<'_> = Vec::with_capacity(accounts.len() * 2);
                for (i, a) in accounts.iter().enumerate() {
                    params.push(&account_ids[i]);
                    params.push(&a.name);
                }
                let statement = bulk_insert_statement("account_name", &["id", "name"], accounts.len());
                tx.execute(&statement, &params).await?;
                Ok(())
            };
            // Insert account SID.
            let account_sid_fut = async {
                let mut params: Params<'_> = Vec::with_capacity(accounts.len() * 2);
                for i in 0..accounts.len() {
                    params.push(&account_ids[i]);
                    params.push(&sid_ids[i]);
                }
                let statement = bulk_insert_statement("account_sid", &["account_id", "sid_id"], accounts.len());
                tx.execute(&statement, &params).await?;
                Ok(())
            };
            try_join!(name_fut, account_sid_fut)?;
            Ok(())
        };

        let remove_fut = async {
            if diff.removed.is_empty() {
                return Ok(());
            }
            let records = &diff.removed;
            let mut params: Params<'_> = Vec::with_capacity(records.len());
            for id in records.iter() {
                params.push(id);
            }
            let statement = format!(
                "UPDATE account_removed SET during = tstzrange(lower(during), now()) WHERE id IN {} AND during @> now()",
                query_args_inline(records.len())
            );
            tx.execute(&statement, &params).await?;
            let statement = format!(
                "INSERT INTO account_removed (id) VALUES {}",
                query_args_single(records.len())
            );
            tx.execute(&statement, &params).await?;
            Ok(())
        };
        let changed_name_fut = async {
            if diff.changed_name.is_empty() {
                return Ok(());
            }
            let records = &diff.changed_name;
            let mut update_params: Params<'_> = Vec::with_capacity(records.len());
            let mut insert_params: Params<'_> = Vec::with_capacity(records.len() * 2);
            for (id, name) in records.iter() {
                update_params.push(id);
                insert_params.push(id);
                insert_params.push(name);
            }
            let statement = format!(
                "UPDATE account_name SET during = tstzrange(lower(during), now()) WHERE id IN {} AND during @> now()",
                query_args_inline(records.len())
            );
            tx.execute(&statement, &update_params).await?;
            let statement = bulk_insert_statement("account_name", &["id", "name"], records.len());
            tx.execute(&statement, &insert_params).await?;
            Ok(())
        };
        try_join!(add_fut, remove_fut, changed_name_fut).map_err(DbError::from)?;
        tx.commit().await?;
        Ok(())
    }

    async fn insert_elevate_tmp_request(&self, req_id: i32, seconds: i32) -> Result<(), DbError> {
        self.get()
            .await?
            .execute(
                "INSERT INTO elevate_tmp_request (req_id, seconds) VALUES ($1, $2)",
                &[&req_id, &seconds],
            )
            .await?;
        Ok(())
    }

    async fn get_users(&self) -> Result<Vec<User>, DbError> {
        unimplemented!()
    }

    async fn insert_jit_elevation_result(&self, result: &ElevationResult) -> Result<(), DbError> {
        unimplemented!()
    }

    async fn get_jit_elevation_log(&self, id: i64) -> Result<Option<JitElevationLogRow>, DbError> {
        unimplemented!()
    }

    async fn get_jit_elevation_logs(
        &self,
        query_options: JitElevationLogQueryOptions,
    ) -> Result<JitElevationLogPage, DbError> {
        unimplemented!()
    }
}

/// Constructs query args like `($1), ($2), ($3)`.
fn query_args_single(num_records: usize) -> String {
    query_args_single_generic(num_records, '$')
}

/// Constructs n query args like `($1, $2, $3)`.
///
/// This is useful for `IN`.
fn query_args_inline(num_records: usize) -> String {
    query_args_inline_generic(num_records, '$')
}

/// Constructs an insert statement for bulk inserts.
///
/// The output is like `INSERT INTO table_name (col1, col2, col3) VALUES ($1, $2, $3), ($4, $5, $6)`.
fn bulk_insert_statement(table_name: &str, col_names: &[&str], num_records: usize) -> String {
    bulk_insert_statement_generic(table_name, col_names, num_records, '$')
}
