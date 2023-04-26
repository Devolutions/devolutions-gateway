use crate::config::ConfHandle;
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpError;
use crate::token::{AccessScope, AccessTokenClaims};
use anyhow::Context as _;
use saphir::body::json::Json;
use saphir::controller::Controller;
use saphir::file::File;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::request::Request;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub struct JrecController {
    pub conf_handle: ConfHandle,
}

#[controller(name = "jet/jrec")]
impl JrecController {
    #[get("/list")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::RecordingsRead)"#)]
    async fn list_recordings(&self) -> Result<Json<Vec<Uuid>>, HttpError> {
        list_recordings(&self.conf_handle).await
    }

    #[get("/pull/{id}/{filename}")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Jrec"#)]
    async fn pull_recording_file(&self, id: Uuid, filename: String, req: Request) -> Result<File, HttpError> {
        pull_recording_file(&self.conf_handle, id, &filename, req).await
    }
}

fn list_uuid_dirs(dir_path: &Path) -> anyhow::Result<Vec<Uuid>> {
    let read_dir = fs::read_dir(dir_path).context("couldn’t read directory")?;

    let list = read_dir
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.is_dir() {
                let file_name = path.file_name()?.to_str()?;
                let uuid = Uuid::parse_str(file_name).ok()?;
                Some(uuid)
            } else {
                None
            }
        })
        .collect();

    Ok(list)
}

/// Lists all recordings stored on this instance
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "ListRecordings",
    tag = "Jrec",
    path = "/jet/jrec/list",
    responses(
        (status = 200, description = "List of recordings on this Gateway instance", body = [Uuid]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.recordings.read"])),
))]
pub(crate) async fn list_recordings(conf_handle: &ConfHandle) -> Result<Json<Vec<Uuid>>, HttpError> {
    let conf = conf_handle.get_conf();
    let dirs = list_uuid_dirs(conf.recording_path.as_std_path())
        .map_err(HttpError::internal().with_msg("failed recording listing").err())?;
    Ok(Json(dirs))
}

/// Retrieves a recording file for a given session
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "PullRecordingFile",
    tag = "Jrec",
    path = "/jet/jrec/pull/{id}/{filename}",
    params(
        ("id" = Uuid, Path, description = "Recorded session ID"),
        ("filename" = String, Path, description = "Name of recording file to retrieve"),
    ),
    responses(
        (status = 200, description = "Recording file", body = Vec<u8>),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "File not found"),
    ),
    security(("jrec_token" = ["pull"])),
))]
pub(crate) async fn pull_recording_file(
    conf_handle: &ConfHandle,
    id: Uuid,
    filename: &str,
    mut req: Request,
) -> Result<File, HttpError> {
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(HttpError::bad_request().msg("invalid file name"));
    }

    let claims = req
        .extensions_mut()
        .remove::<AccessTokenClaims>()
        .ok_or_else(|| HttpError::unauthorized().msg("identity is missing (token)"))?;

    let AccessTokenClaims::Jrec(claims) = claims else {
        return Err(HttpError::forbidden().msg("token not allowed"));
    };

    if id != claims.jet_aid {
        return Err(HttpError::forbidden().msg("not allowed to read this recording"));
    }

    let path = conf_handle
        .get_conf()
        .recording_path
        .join(id.to_string())
        .join(filename);

    if !path.exists() || !path.is_file() {
        return Err(HttpError::not_found().msg("requested file does not exist"));
    }

    File::open(path.as_str()).await.map_err(HttpError::internal().err())
}
