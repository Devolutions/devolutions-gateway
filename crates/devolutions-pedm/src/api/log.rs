use crate::api::{AppState, Db, NamedPipeConnectInfo};
use crate::error::Error;
use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions, JitElevationLogRow};
use aide::NoApi;
use aide::axum::ApiRouter;
use axum::extract::{Path, State};
use axum::{Extension, Json};

use super::policy::PathIdParameter;

async fn get_jit_elevation_log_id(
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(_state)): NoApi<State<AppState>>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<JitElevationLogRow>, Error> {
    let row = db.get_jit_elevation_log(id.id).await?.ok_or(Error::NotFound)?;

    if row.user.as_ref() != Some(&named_pipe_info.user) && !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    Ok(Json(row))
}

async fn get_jit_elevation_logs(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(_state)): NoApi<State<AppState>>,
    NoApi(Db(db)): NoApi<Db>,
    Json(query_options): Json<JitElevationLogQueryOptions>,
) -> Result<Json<JitElevationLogPage>, Error> {
    if query_options.user.as_ref() != Some(&named_pipe_info.user)
        && !named_pipe_info.token.is_elevated()?
    {
        return Err(Error::AccessDenied);
    }

    let page = db.get_jit_elevation_logs(query_options).await?;
    Ok(Json(page))
}

pub(crate) fn log_router() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/jit", aide::axum::routing::get(get_jit_elevation_logs))
        .api_route("/jit/{id}", aide::axum::routing::get(get_jit_elevation_log_id))
}
