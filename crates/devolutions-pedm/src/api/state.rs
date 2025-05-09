use core::{error, fmt};
use std::sync::atomic::AtomicI32;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use chrono::Utc;
use hyper::StatusCode;
use parking_lot::RwLock;

use crate::db::{Database, Db, DbError, DbHandle};
use crate::model::StartupInfo;
use crate::policy::{LoadPolicyError, Policy};

/// Axum application state.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) startup_info: StartupInfo,
    /// Request counter.
    ///
    /// The current count is the last used request ID.
    ///
    /// TODO: implement a check to ensure that there is only one PEDM instance running at any given time
    pub(crate) req_counter: Arc<AtomicI32>,
    pub(crate) db: Arc<dyn Database + Send + Sync>,
    pub(crate) db_handle: DbHandle,
    pub(crate) policy: Arc<RwLock<Policy>>,
}

impl AppState {
    pub(crate) async fn new(db: Db, db_handle: DbHandle, pipe_name: &str) -> Result<Self, AppStateError> {
        let policy = Policy::load()?;

        let last_req_id = db.get_last_request_id().await?;
        let startup_time = Utc::now();
        let run_id = db.log_server_startup(startup_time, pipe_name).await?;

        let startup_info = StartupInfo {
            run_id,
            request_count: last_req_id,
            start_time: startup_time,
        };

        Ok(Self {
            startup_info,
            req_counter: Arc::new(AtomicI32::new(last_req_id)),
            db: db.0,
            db_handle,
            policy: Arc::new(RwLock::new(policy)),
        })
    }
}

/// Axum extractor for an object that is `Database`.
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

/// Axum extractor for an object that is `DbHandle`.
impl<S> FromRequestParts<S> for DbHandle
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        Ok(app_state.db_handle.clone())
    }
}

impl FromRef<AppState> for Arc<RwLock<Policy>> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.policy)
    }
}

#[derive(Debug)]
pub enum AppStateError {
    LoadPolicy(LoadPolicyError),
    Db(DbError),
}

impl error::Error for AppStateError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::LoadPolicy(e) => Some(e),
            Self::Db(e) => Some(e),
        }
    }
}

impl fmt::Display for AppStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadPolicy(e) => e.fmt(f),
            Self::Db(e) => e.fmt(f),
        }
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
