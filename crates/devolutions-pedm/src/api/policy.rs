use aide::NoApi;
use aide::axum::ApiRouter;
use aide::axum::routing::{get, put};
use axum::extract::Path;
use axum::{Extension, Json};
use devolutions_pedm_shared::policy::{Assignment, Profile, User};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::state::AppState;
use super::{Db, NamedPipeConnectInfo};
use crate::error::Error;

async fn post_profiles(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
    Json(profile): Json<Profile>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    db.insert_profile(&profile).await?;
    Ok(())
}

async fn get_profiles_id(
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<Profile>, Error> {
    let profile = match db.get_profile(id.id).await? {
        Some(p) => {
            if named_pipe_info.token.is_elevated()? {
                Ok(p)
            } else {
                let assignments = db.get_assignment(&p).await?;

                if assignments.users.contains(&named_pipe_info.user) {
                    Ok(p)
                } else {
                    Err(Error::AccessDenied)
                }
            }
        }
        None => Err(Error::NotFound),
    }?;

    Ok(Json(profile))
}

async fn delete_profiles_id(
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    db.delete_profile(id.id).await?;
    Ok(())
}

/// Returns some information about the current user and active profiles.
///
/// If there is no active profile, the `active` UUID will be full of zeroes.
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
struct GetProfilesMeResponse {
    pub(crate) active: i64,
    pub(crate) available: Vec<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub(super) struct PathIdParameter {
    pub id: i64,
}

/// Returns the active profile ID if there is one, and a list of available profiles.
async fn get_me(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<GetProfilesMeResponse>, Error> {
    match db.get_user_id(&named_pipe_info.user).await? {
        Some(_) => {
            let selected_profile = db.get_user_profile(&named_pipe_info.user).await?;
            let profiles = db.get_profiles_for_user(&named_pipe_info.user).await?;

            Ok(Json(GetProfilesMeResponse {
                active: selected_profile.map_or(0, |p| p.id),
                available: profiles.into_iter().map(|p| p.id).collect(),
            }))
        }
        None => Ok(Json(GetProfilesMeResponse {
            active: 0,
            available: vec![],
        })),
    }
}

/// Returns the list of profile IDs.
async fn get_profiles(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<Vec<i64>>, Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let profiles = db.get_profiles().await?;
    Ok(Json(profiles.into_iter().map(|p| p.id).collect()))
}

/// Sets the profile ID to the specified ID.
async fn set_profile_id(
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<(), Error> {
    // The databse should validate that the user can only select an assigned profile
    db.set_user_profile(&named_pipe_info.user, id.id).await?;
    Ok(())
}

async fn get_assignments(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<Vec<Assignment>>, Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    let assignments = db.get_assignments().await?;
    Ok(Json(assignments))
}

async fn put_assignments_id(
    Path(id): Path<PathIdParameter>,
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
    Json(users): Json<Vec<User>>,
) -> Result<(), Error> {
    if !named_pipe_info.token.is_elevated()? {
        return Err(Error::AccessDenied);
    }

    db.set_assignments(id.id, users).await?;
    Ok(())
}

async fn get_users(
    Extension(named_pipe_info): Extension<NamedPipeConnectInfo>,
    NoApi(Db(db)): NoApi<Db>,
) -> Result<Json<Vec<User>>, Error> {
    let mut users = db.get_users().await?;

    if !named_pipe_info.token.is_elevated()? {
        users.retain(|u| u == &named_pipe_info.user);
    }

    Ok(Json(users))
}

pub(crate) fn policy_router() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/me", get(get_me))
        .api_route("/me/{id}", put(set_profile_id))
        .api_route("/profiles", get(get_profiles).post(post_profiles))
        .api_route("/profiles/{id}", get(get_profiles_id).delete(delete_profiles_id))
        .api_route("/assignments", get(get_assignments))
        .api_route("/assignments/{id}", put(put_assignments_id))
        .api_route("/users", get(get_users))
}
