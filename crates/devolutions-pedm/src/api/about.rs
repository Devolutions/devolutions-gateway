use std::sync::atomic::Ordering;

use aide::NoApi;
use axum::Json;
use axum::extract::State;
use chrono::{TimeZone, Utc};

use crate::db::Db;
use crate::model::AboutData;

use super::err::HandlerError;
use super::state::AppState;

/// Gets info about the current state of the application.
pub(crate) async fn about(
    NoApi(State(state)): NoApi<State<AppState>>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<AboutData>, HandlerError> {
    Ok(Json(AboutData {
        run_id: state.startup_info.run_id,
        start_time: state.startup_info.start_time,
        startup_request_count: state.startup_info.request_count,
        current_request_count: state.req_counter.load(Ordering::Relaxed),
        last_request_time: db
            .get_last_request_time()
            .await?
            .or_else(|| Utc.timestamp_opt(0, 0).single()),
        version: win_api_wrappers::utils::get_exe_version()?,
    }))
}
