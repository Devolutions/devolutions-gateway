use crate::api::{AppState, Db, NamedPipeConnectInfo};
use crate::error::Error;
use crate::log::{JitElevationLogPage, JitElevationLogQueryOptions};
use aide::axum::ApiRouter;
use aide::NoApi;
use axum::extract::State;
use axum::{Extension, Json};

async fn get_jit_elevation_logs(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(_state)): NoApi<State<AppState>>,
    NoApi(Db(db)): NoApi<Db>,
    Json(query_options): Json<JitElevationLogQueryOptions>,
) -> Result<Json<JitElevationLogPage>, Error> {
    if query_options.user.as_ref().map_or(true, |u| u != &named_pipe_info.user) {
        if !named_pipe_info.token.is_elevated()? {
            return Err(Error::AccessDenied);
        }
    }

    let page = db.get_jit_elevation_logs(query_options).await?;
    Ok(Json(page))
}

pub(crate) fn log_router() -> ApiRouter<AppState> {
    ApiRouter::new().api_route("/jit", aide::axum::routing::get(get_jit_elevation_logs))
}
