use std::sync::atomic::Ordering;

use aide::NoApi;
use axum::extract::State;
use axum::Json;

use super::err::HandlerError;
use super::state::AppState;
use crate::db::Db;
use crate::model::AboutData;

/// Gets info about the current state of the application.
pub(crate) async fn about(
    NoApi(State(state)): NoApi<State<AppState>>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<AboutData>, HandlerError> {
    let requests_received = state.req_counter.load(Ordering::Relaxed) - state.startup_info.startup_request_count;

    Ok(Json(AboutData {
        startup_info: state.startup_info,
        requests_received,
        last_request_time: db.get_last_request_time().await?,
    }))
}
