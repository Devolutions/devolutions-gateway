use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::Context as _;
use axum::extract::ws::WebSocket;
use axum::extract::{self, ConnectInfo, Query, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::{delete, get};
use axum::{Json, Router};
use devolutions_gateway_task::ShutdownSignal;
use hyper::StatusCode;
use tracing::Instrument as _;
use uuid::Uuid;

use crate::extract::{JrecToken, RecordingDeleteScope, RecordingsReadScope};
use crate::http::{HttpError, HttpErrorBuilder};
use crate::recording::RecordingMessageSender;
use crate::token::{JrecTokenClaims, RecordingFileType, RecordingOperation};
use crate::DgwState;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/push/:id", get(jrec_push))
        .route("/delete/:id", delete(jrec_delete))
        .route("/list", get(list_recordings))
        .route("/pull/:id/:filename", get(pull_recording_file))
        .route("/play", get(get_player))
        .route("/play/*path", get(get_player))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecPushQueryParam {
    file_type: RecordingFileType,
}

async fn jrec_push(
    State(DgwState {
        shutdown_signal,
        recordings,
        ..
    }): State<DgwState>,
    JrecToken(claims): JrecToken,
    Query(query): Query<JrecPushQueryParam>,
    extract::Path(session_id): extract::Path<Uuid>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if claims.jet_rop != RecordingOperation::Push {
        return Err(HttpError::forbidden().msg("expected push operation"));
    }

    let response = ws.on_upgrade(move |ws| {
        handle_jrec_push(
            ws,
            recordings,
            shutdown_signal,
            claims,
            query.file_type,
            session_id,
            source_addr,
        )
    });

    Ok(response)
}

async fn handle_jrec_push(
    ws: WebSocket,
    recordings: RecordingMessageSender,
    shutdown_signal: ShutdownSignal,
    claims: JrecTokenClaims,
    file_type: RecordingFileType,
    session_id: Uuid,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = crate::recording::ClientPush::builder()
        .client_stream(stream)
        .recordings(recordings)
        .claims(claims)
        .file_type(file_type)
        .session_id(session_id)
        .shutdown_signal(shutdown_signal)
        .build()
        .run()
        .instrument(info_span!("jrec", client = %source_addr))
        .await;

    if let Err(error) = result {
        error!(client = %source_addr, error = format!("{error:#}"), "WebSocket-JREC failure");
    }
}

/// Lists all recordings stored on this instance
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    operation_id = "DeleteRecording",
    tag = "Jrec",
    path = "/jet/jrec/delete/{id}",
    params(
        ("id" = Uuid, Path, description = "Recorded session ID"),
    ),
    responses(
        (status = 200, description = "Recording matching the ID in the path has been deleted"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 406, description = "The recording is still ongoing and can't be deleted yet"),
    ),
    security(("scope_token" = ["gateway.recording.delete"])),
))]
async fn jrec_delete(
    State(DgwState {
        conf_handle,
        recordings,
        ..
    }): State<DgwState>,
    _scope: RecordingDeleteScope,
    extract::Path(session_id): extract::Path<Uuid>,
) -> Result<(), HttpError> {
    let state = recordings
        .get_state(session_id)
        .await
        .map_err(HttpError::internal().with_msg("failed recording listing").err())?;

    if state.is_some() {
        return Err(
            HttpErrorBuilder::new(StatusCode::CONFLICT).msg("Attempted to delete a recording for an ongoing session")
        );
    }

    let recording_path = conf_handle.get_conf().recording_path.join(session_id.to_string());

    debug!(%recording_path, "Delete recording");

    tokio::fs::remove_dir_all(recording_path)
        .await
        .map_err(HttpError::internal().with_msg("failed to delete recording").err())?;

    Ok(())
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
pub(crate) async fn list_recordings(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    _scope: RecordingsReadScope,
) -> Result<Json<Vec<Uuid>>, HttpError> {
    let conf = conf_handle.get_conf();
    let recording_path = conf.recording_path.as_std_path();

    let dirs = if recording_path.exists() {
        list_uuid_dirs(recording_path).map_err(HttpError::internal().with_msg("failed recording listing").err())?
    } else {
        // If the recording directory does not exist, it means that there is no recording yet
        Vec::new()
    };

    return Ok(Json(dirs));

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
pub(crate) async fn pull_recording_file<ReqBody>(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    extract::Path((id, filename)): extract::Path<(Uuid, String)>,
    JrecToken(claims): JrecToken,
    request: axum::http::Request<ReqBody>,
) -> Result<Response<tower_http::services::fs::ServeFileSystemResponseBody>, HttpError>
where
    ReqBody: Send + 'static,
{
    use tower::ServiceExt as _;

    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(HttpError::bad_request().msg("invalid file name"));
    }

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

    let response = tower_http::services::ServeFile::new(path)
        .oneshot(request)
        .await
        .map_err(HttpError::internal().err())?;

    Ok(response)
}

async fn get_player<ReqBody>(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    path: Option<extract::Path<String>>,
    mut request: axum::http::Request<ReqBody>,
) -> Result<Response<tower_http::services::fs::ServeFileSystemResponseBody>, HttpError>
where
    ReqBody: Send + 'static,
{
    use tower::ServiceExt as _;
    use tower_http::services::{ServeDir, ServeFile};

    let conf = conf_handle.get_conf();

    let path = path.map(|path| path.0).unwrap_or_else(|| "/".to_owned());

    debug!(path, "Requested player ressource");

    *request.uri_mut() = axum::http::Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(HttpError::internal().with_msg("invalid ressource path").err())?;

    let player_root = conf.web_app.static_root_path.join("player/");
    let player_index = conf.web_app.static_root_path.join("player/index.html");

    match ServeDir::new(player_root)
        .fallback(ServeFile::new(player_index))
        .append_index_html_on_directories(true)
        .oneshot(request)
        .await
    {
        Ok(response) => Ok(response),
        Err(never) => match never {},
    }
}
