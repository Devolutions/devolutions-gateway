use aide::axum::routing::{get, put};
use aide::axum::ApiRouter;
use axum::extract::Path;
use axum::{Extension, Json};
use devolutions_pedm_shared::policy::{Profile, User};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::error::Error;
use crate::policy;

use super::NamedPipeConnectInfo;

async fn get_profiles(Extension(named_pipe_info): Extension<NamedPipeConnectInfo>) -> Result<Json<Vec<Uuid>>, Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let policy = policy::policy().read();

    Ok(Json(policy.profiles().map(|p| p.id).collect()))
}

async fn post_profiles(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Json(profile): Json<Profile>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let mut policy = policy::policy().write();

    policy.add_profile(profile)?;

    Ok(())
}

async fn get_profiles_id(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Path(id): Path<PathIdParameter>,
) -> Result<Json<Profile>, Error> {
    let policy = policy::policy().read();

    let profile = if named_pipe_info.token.is_elevated()? {
        policy.profile(&id.id).ok_or(Error::NotFound)?
    } else {
        policy
            .user_profile(&named_pipe_info.user, &id.id)
            .ok_or(Error::AccessDenied)?
    };

    Ok(Json(profile.clone()))
}

async fn put_profiles_id(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Path(id): Path<PathIdParameter>,
    Json(profile): Json<Profile>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let mut policy = policy::policy().write();

    policy.replace_profile(&id.id, profile)?;

    Ok(())
}

async fn delete_profiles_id(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Path(id): Path<PathIdParameter>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let mut policy = policy::policy().write();

    policy.remove_profile(&id.id)?;

    Ok(())
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
struct GetProfilesMeResponse {
    pub active: Uuid,
    pub available: Vec<Uuid>,
}

#[derive(Deserialize, JsonSchema)]
struct PathIdParameter {
    pub id: Uuid,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
struct OptionalId {
    pub id: Option<Uuid>,
}

async fn get_me(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
) -> Result<Json<GetProfilesMeResponse>, Error> {
    info!(user = ?named_pipe_info.user, "Querying profiles for user");
    let policy = policy::policy().read();

    Ok(Json(GetProfilesMeResponse {
        active: policy
            .user_current_profile(&named_pipe_info.user)
            .map(|p| p.id)
            .unwrap_or_else(Uuid::nil),
        available: policy
            .user_profiles(&named_pipe_info.user)
            .into_iter()
            .map(|p| p.id)
            .collect(),
    }))
}

async fn put_me(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Json(id): Json<OptionalId>,
) -> Result<(), Error> {
    let mut policy = policy::policy().write();

    policy.set_user_current_profile(named_pipe_info.user, id.id)?;

    Ok(())
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
struct Assignment {
    pub profile: Profile,
    pub users: Vec<User>,
}

async fn get_assignments(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
) -> Result<Json<Vec<Assignment>>, Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let policy = policy::policy().read();

    let assignments = policy
        .assignments()
        .iter()
        .filter_map(|(id, users)| {
            let profile = policy.profile(id)?;

            Some(Assignment {
                profile: profile.clone(),
                users: users.clone(),
            })
        })
        .collect();

    Ok(Json(assignments))
}

async fn put_assignments_id(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    Path(id): Path<PathIdParameter>,
    Json(users): Json<Vec<User>>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let mut policy = policy::policy().write();

    policy.set_assignments(id.id, users)?;

    Ok(())
}

pub fn policy_router() -> ApiRouter {
    ApiRouter::new()
        .api_route("/me", get(get_me).put(put_me))
        .api_route("/profiles", get(get_profiles).post(post_profiles))
        .api_route(
            "/profiles/:id",
            get(get_profiles_id).put(put_profiles_id).delete(delete_profiles_id),
        )
        .api_route("/assignments", get(get_assignments))
        .api_route("/assignments/:id", put(put_assignments_id))
}
