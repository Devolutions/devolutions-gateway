use std::ops::Deref;

use async_trait::async_trait;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use chrono::{DateTime, Utc};
use tokio_postgres::NoTls;

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
            .query_one("SELECT version FROM pedm_schema_version", &[])
            .await?
            .get(0))
    }

    async fn init_schema(&self) -> Result<(), DbError> {
        let sql = include_str!("../../schema/pg.sql");
        self.get().await?.batch_execute(sql).await?;
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
            .map(|r| r.get(0))
            .unwrap_or_default())
    }

    async fn log_server_startup(&self, start_time: DateTime<Utc>, pipe_name: &str) -> Result<i32, DbError> {
        Ok(self
            .get()
            .await?
            .query_one(
                "INSERT INTO pedm_run (start_time, pipe_name) VALUES ($1, $2) RETURNING id",
                &[&start_time, &pipe_name],
            )
            .await?
            .get(0))
    }

    async fn log_http_request(&self, req_id: i32, method: &str, path: &str, status_code: i16) -> Result<(), DbError> {
        self.get()
            .await?
            .query_one(
                "INSERT INTO http_request (id, method, path, status_code) VALUES ($1, $2, $3, $4)",
                &[&req_id, &method, &path, &status_code],
            )
            .await?;
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
}
