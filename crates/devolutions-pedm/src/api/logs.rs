use axum::{Extension, Json};
use devolutions_pedm_shared::policy::ElevationResult;
use tracing::info;

use crate::error::Error;
use crate::log;

use super::NamedPipeConnectInfo;

pub(crate) async fn get_logs(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
) -> Result<Json<Vec<ElevationResult>>, Error> {
    info!(user = ?named_pipe_info.user, "Querying logs for user");

    Ok(Json(log::query_logs(Some(&named_pipe_info.user))?))
}
