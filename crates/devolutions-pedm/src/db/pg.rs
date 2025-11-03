use std::ops::Deref;

use async_trait::async_trait;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use chrono::{DateTime, Utc};
use devolutions_pedm_shared::policy::ElevationResult;
use tokio_postgres::NoTls;

use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions};

use super::{Database, DbError};

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

    async fn get_users(&self) -> Result<Vec<User>, DbError> {
        unimplemented!()
    }

    async fn get_user_id(&self, user: &User) -> Result<Option<i64>, DbError> {
        unimplemented!()
    }

    async fn insert_jit_elevation_result(&self, _result: &ElevationResult) -> Result<(), DbError> {
        unimplemented!()
    }

    async fn get_jit_elevation_log(&self, id: i64) -> Result<Option<JitElevationLogRow>, DbError> {
        unimplemented!()
    }

    async fn get_jit_elevation_logs(
        &self,
        _query_options: JitElevationLogQueryOptions,
    ) -> Result<JitElevationLogPage, DbError> {
        unimplemented!()
    }
}
