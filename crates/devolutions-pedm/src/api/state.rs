use core::{error, fmt};
use std::sync::atomic::AtomicI32;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use camino::Utf8PathBuf;
use hyper::StatusCode;
use parking_lot::RwLock;
use tracing::info;

use crate::config::{Config, ConfigError, DbBackend};
use crate::db::{Database, DbError};
use crate::policy::{LoadPolicyError, Policy};

#[cfg(feature = "libsql")]
use crate::db::LibsqlConn;

#[cfg(feature = "postgres")]
use bb8::Pool;
#[cfg(feature = "postgres")]
use bb8_postgres::PostgresConnectionManager;
#[cfg(feature = "postgres")]
use tokio_postgres::config::SslMode;
#[cfg(feature = "postgres")]
use tokio_postgres::NoTls;

#[cfg(feature = "postgres")]
use crate::db::PgPool;

#[derive(Clone)]
pub(crate) struct AppState {
    /// Request counter.
    ///
    /// The current count is the last used request ID.
    ///
    /// TODO: implement a check to ensure that there is only one PEDM instance running at any given time
    pub(crate) req_counter: Arc<AtomicI32>,
    pub(crate) db: Arc<dyn Database + Send + Sync>,
    pub(crate) policy: Arc<RwLock<Policy>>,
}

impl AppState {
    pub(crate) async fn load(config_path: Option<Utf8PathBuf>) -> Result<Self, AppStateError> {
        let config = if let Some(path) = config_path {
            Config::load_from_path(&path)
        } else {
            Config::load_from_default_path()
        }?;

        let db: Arc<dyn Database + Send + Sync> = match config.db {
            #[cfg(feature = "libsql")]
            DbBackend::Libsql => {
                #[expect(clippy::unwrap_used)]
                let c = config.libsql.unwrap(); // already checked by `Config::validate` at the end of the load function
                let db_obj = libsql::Builder::new_local(&c.path)
                    .build()
                    .await
                    .map_err(DbError::from)?;
                let conn = db_obj.connect().map_err(DbError::from)?;
                info!("Connecting to LibSQL database at {}", c.path);
                Arc::new(LibsqlConn::new(conn))
            }
            #[cfg(feature = "postgres")]
            DbBackend::Postgres => {
                #[expect(clippy::unwrap_used)]
                let c = config.postgres.unwrap(); // already checked by `Config::validate` at the end of the load function
                let mut pg_config = tokio_postgres::Config::new();
                pg_config.host(&c.host);
                pg_config.dbname(&c.dbname);
                if let Some(n) = c.port {
                    pg_config.port(n);
                }
                pg_config.user(c.user);
                if let Some(s) = c.password {
                    pg_config.password(s);
                }
                pg_config.ssl_mode(SslMode::Disable);

                let mgr = PostgresConnectionManager::new(pg_config, NoTls);
                let pool = Pool::builder().build(mgr).await.map_err(DbError::from)?;

                info!("Connecting to Postgres database {} on host {}", c.dbname, c.host);
                Arc::new(PgPool::new(pool))
            }
        };

        let policy = Policy::load()?;

        let last_req_id = db.get_latest_request_id().await?;

        Ok(Self {
            req_counter: Arc::new(AtomicI32::new(last_req_id)),
            db,
            policy: Arc::new(RwLock::new(policy)),
        })
    }
}

/// Axum extractor for an object that is `Database`.
pub(crate) struct Db(pub Arc<dyn Database + Send + Sync>);

impl<S> FromRequestParts<S> for Db
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        Ok(Db(Arc::clone(&app_state.db)))
    }
}

impl FromRef<AppState> for Arc<RwLock<Policy>> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.policy)
    }
}

#[derive(Debug)]
pub enum AppStateError {
    Config(ConfigError),
    LoadPolicy(LoadPolicyError),
    Db(DbError),
}

impl error::Error for AppStateError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Config(e) => Some(e),
            Self::LoadPolicy(e) => Some(e),
            Self::Db(e) => Some(e),
        }
    }
}

impl fmt::Display for AppStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
            Self::LoadPolicy(e) => e.fmt(f),
            Self::Db(e) => e.fmt(f),
        }
    }
}
impl From<ConfigError> for AppStateError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}
impl From<LoadPolicyError> for AppStateError {
    fn from(e: LoadPolicyError) -> Self {
        Self::LoadPolicy(e)
    }
}
impl From<DbError> for AppStateError {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}
