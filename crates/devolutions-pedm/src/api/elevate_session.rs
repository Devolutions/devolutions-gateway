use axum::Extension;
use tracing::info;

use crate::error::Error;
use crate::{elevations, policy};

use super::NamedPipeConnectInfo;

pub async fn post_elevate_session(Extension(named_pipe_info): Extension<NamedPipeConnectInfo>) -> Result<(), Error> {
    let policy = policy::policy().read();

    if let Some(profile) = policy.user_current_profile(&named_pipe_info.user) {
        if !profile.elevation_settings.session.enabled {
            info!(user = ?named_pipe_info.user, "User tried to elevate session, but wasn't allowed");
            return Err(Error::AccessDenied);
        }

        info!(user = ?named_pipe_info.user, "Elevating user until revocation");

        elevations::elevate_session(named_pipe_info.user);

        Ok(())
    } else {
        info!(user = ?named_pipe_info.user, "User tried to elevate session, but wasn't assigned to profile");
        Err(Error::AccessDenied)
    }
}
