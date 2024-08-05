use axum::Extension;
use tracing::info;

use crate::elevations;
use crate::error::Error;

use super::NamedPipeConnectInfo;

pub async fn post_revoke(Extension(named_pipe_info): Extension<NamedPipeConnectInfo>) -> Result<(), Error> {
    info!(user = ?named_pipe_info.user, "Revoking admin privileges for user");

    elevations::revoke(&named_pipe_info.user);

    Ok(())
}
