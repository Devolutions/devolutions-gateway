use std::sync::Arc;

use aide::axum::routing::{get, put};
use aide::axum::ApiRouter;
use aide::NoApi;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use devolutions_pedm_shared::policy::{Profile, User};
use parking_lot::RwLock;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::state::AppState;
use super::{Db, NamedPipeConnectInfo};
use crate::error::Error;
use crate::policy::Policy;

async fn post_profiles(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
    Json(profile): Json<Profile>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }
    let mut policy = policy.write();
    policy.add_profile(profile)?;
    Ok(())
}

async fn get_profiles_id(
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
) -> Result<Json<Profile>, Error> {
    let policy = policy.read();
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
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
    Json(profile): Json<Profile>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }
    let mut policy = policy.write();
    policy.replace_profile(&id.id, profile)?;
    Ok(())
}

async fn delete_profiles_id(
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }
    let mut policy = policy.write();
    policy.remove_profile(&id.id)?;
    Ok(())
}

/// Returns some information about the current user and active profiles.
///
/// If there is no active profile, the `active` UUID will be full of zeroes.
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
struct GetProfilesMeResponse {
    pub(crate) active: Uuid,
    pub(crate) available: Vec<Uuid>,
}

#[derive(Deserialize, JsonSchema)]
struct PathIdParameter {
    pub(crate) id: Uuid,
}

#[derive(Deserialize, JsonSchema)]
pub struct PathIntIdPath {
    pub id: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
struct OptionalId {
    pub(crate) id: Option<Uuid>,
}

/// Returns the active profile ID if there is one, and a list of available profiles.
///
/// This is similar to `get_profiles`, except it presumably requires less permissions.
async fn get_me(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
) -> Result<Json<GetProfilesMeResponse>, Error> {
    let policy = policy.read();

    Ok(Json(GetProfilesMeResponse {
        active: policy
            .user_current_profile(&named_pipe_info.user)
            .map(|p| p.id)
            .unwrap_or_default(),
        available: policy
            .user_profiles(&named_pipe_info.user)
            .into_iter()
            .map(|p| p.id)
            .collect(),
    }))
}

/// Returns the list of profile IDs for the current user.
async fn get_profiles(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
) -> Result<Json<Vec<Uuid>>, Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }
    let policy = policy.read();
    Ok(Json(policy.profiles().map(|p| p.id).collect()))
}

/// Sets the profile ID to the specified ID.
async fn set_profile_id(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
    Json(id): Json<OptionalId>,
) -> Result<(), Error> {
    let mut policy = policy.write();

    policy.set_profile_id(named_pipe_info.user, id.id)?;

    Ok(())
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
struct Assignment {
    pub(crate) profile: Profile,
    pub(crate) users: Vec<User>,
}

async fn get_assignments(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
) -> Result<Json<Vec<Assignment>>, Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let policy = policy.read();

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
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(policy)): NoApi<State<Arc<RwLock<Policy>>>>,
    Json(users): Json<Vec<User>>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let mut policy = policy.write();

    policy.set_assignments(id.id, users)?;

    Ok(())
}

async fn get_users(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(State(_policy)): NoApi<State<Arc<RwLock<Policy>>>>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<Vec<User>>, Error> {
    let mut users = db.get_users().await?;

    if !named_pipe_info.token.is_elevated()? {
        users = users.into_iter().filter(|u| u == &named_pipe_info.user).collect();
    }

    Ok(Json(users))
}

pub(crate) fn policy_router() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/me", get(get_me).put(set_profile_id))
        .api_route("/profiles", get(get_profiles).post(post_profiles))
        .api_route(
            "/profiles/{id}",
            get(get_profiles_id).put(put_profiles_id).delete(delete_profiles_id),
        )
        .api_route("/assignments", get(get_assignments))
        .api_route("/assignments/{id}", put(put_assignments_id))
        .api_route("/users", get(get_users))
}
