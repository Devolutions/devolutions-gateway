use crate::config::ConfHandle;
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpError;
use crate::token::AccessScope;
use saphir::body::json::Json;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::request::Request;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub struct RecordingsController {
    pub conf_handle: ConfHandle,
}

#[controller(name = "jet/jrec/list")]
impl RecordingsController {
    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::RecordingsRead)"#)]
    async fn get_recordings(&self) -> Result<Json<Vec<String>>, HttpError> {
        get_recordings(&self.conf_handle).await
    }
}

fn list_uuid_dirs(dir_path: &Path) -> Vec<String> {
    fs::read_dir(dir_path)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                path.file_name()
                    .and_then(|name| Uuid::parse_str(name.to_str().unwrap()).ok())
                    .map(|uuid| uuid.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Lists recordings
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetRecordings",
    tag = "Recordings",
    path = "/jet/jrec/list",
    responses(
        (status = 200, description = "Recordings for this Gateway", body = Recording),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.recordings.read"])),
))]
pub(crate) async fn get_recordings(conf_handle: &ConfHandle) -> Result<Json<Vec<String>>, HttpError> {
    let conf = conf_handle.get_conf();
    let recording_path = conf.recording_path.to_owned();
    let dirs = list_uuid_dirs(recording_path.as_std_path());
    Ok(Json(dirs))
}
