use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::Context as _;
use axum::extract::ws::WebSocket;
use axum::extract::{self, ConnectInfo, Query, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::{delete, get};
use axum::{Json, Router};
use camino::{Utf8Path, Utf8PathBuf};
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
        .route("/delete", delete(jrec_delete_many))
        .route("/list", get(list_recordings))
        .route("/pull/:id/:filename", get(pull_recording_file))
        .route("/list/realtime", get(list_realtime_recordings))
        .route("/realtime/:id/:filename", get(stream_recording))
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

/// Deletes a recording stored on this instance
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
        (status = 404, description = "The specified recording was not found"),
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
    let is_active = recordings.active_recordings.contains(session_id);

    if is_active {
        return Err(
            HttpErrorBuilder::new(StatusCode::CONFLICT).msg("attempted to delete a recording for an ongoing session")
        );
    }

    let recording_path = conf_handle.get_conf().recording_path.join(session_id.to_string());

    if !recording_path.exists() {
        return Err(HttpErrorBuilder::new(StatusCode::NOT_FOUND)
            .msg("attempted to delete a recording not found on this instance"));
    }

    delete_recording(&recording_path)
        .await
        .map_err(HttpError::internal().with_msg("failed to delete recording").err())?;

    Ok(())
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct DeleteManyResult {
    /// Number of recordings found
    found_count: usize,
    /// Number of recordings not found
    not_found_count: usize,
}

/// Mass-deletes recordings stored on this instance
///
/// If you try to delete more than 50,000 recordings at once, you should split the list into multiple requests.
/// Bigger payloads will be rejected with 413 Payload Too Large.
///
/// The request processing consist in
/// 1) checking if one of the recording is active,
/// 2) counting the number of recordings not found on this instance.
///
/// When a recording is not found on this instance, a counter is incremented.
/// This number is returned as part of the response.
/// You may use this information to detect anomalies on your side.
/// For instance, this suggests the list of recordings on your side is out of date,
/// and you may want re-index.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    operation_id = "DeleteManyRecordings",
    tag = "Jrec",
    path = "/jet/jrec/delete",
    request_body(content = Vec<Uuid>, description = "JSON-encoded list of session IDs", content_type = "application/json"),
    responses(
        (status = 200, description = "Mass recording deletion task was successfully started", body = DeleteManyResult),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 406, description = "A recording is still ongoing and can't be deleted yet (nothing is deleted)"),
        (status = 413, description = "Request payload is too large"),
    ),
    security(("scope_token" = ["gateway.recording.delete"])),
))]
async fn jrec_delete_many(
    State(DgwState {
        conf_handle,
        recordings,
        job_queue_handle,
        ..
    }): State<DgwState>,
    _scope: RecordingDeleteScope,
    Json(delete_list): Json<Vec<Uuid>>,
) -> Result<Json<DeleteManyResult>, HttpError> {
    use std::collections::HashSet;

    const THRESHOLD: usize = 50_000;
    const CHUNK_SIZE: usize = 1_000;

    if delete_list.len() > THRESHOLD {
        return Err(HttpErrorBuilder::new(StatusCode::PAYLOAD_TOO_LARGE).msg("delete list is too big"));
    }

    let recording_path = conf_handle.get_conf().recording_path.clone();
    let active_recordings = recordings.active_recordings.cloned();

    // Given the threshold of 50,000, it's high unlikely that check_preconditions takes more than 250ms to execute.
    // It typically takes between 50ms and 100ms depending on the hardware.
    let ProcessResult {
        not_found_count,
        found_count,
        recording_paths,
    } = process_request(delete_list, &recording_path, &active_recordings)?;

    for chunk in recording_paths.chunks(CHUNK_SIZE) {
        job_queue_handle
            .enqueue(DeleteRecordingsJob {
                recording_paths: chunk.to_vec(),
            })
            .await
            .map_err(
                HttpError::internal()
                    .with_msg("couldn't enqueue the deletion task")
                    .err(),
            )?;
    }

    let delete_many_result = DeleteManyResult {
        found_count,
        not_found_count,
    };

    return Ok(Json(delete_many_result));

    struct ProcessResult {
        not_found_count: usize,
        found_count: usize,
        recording_paths: Vec<(Uuid, Utf8PathBuf)>,
    }

    fn process_request(
        delete_list: Vec<Uuid>,
        recording_path: &Utf8Path,
        active_recordings: &HashSet<Uuid>,
    ) -> Result<ProcessResult, HttpError> {
        let conflict = delete_list.iter().any(|id| active_recordings.contains(id));

        if conflict {
            return Err(HttpErrorBuilder::new(StatusCode::CONFLICT)
                .msg("attempted to delete a recording for an ongoing session"));
        }

        let mut not_found_count = 0;

        let recording_paths: Vec<(Uuid, Utf8PathBuf)> = delete_list
            .into_iter()
            .filter_map(|session_id| {
                let path = recording_path.join(session_id.to_string());

                if !path.exists() {
                    warn!(%path, %session_id, "Attempted to delete a recording not found on this instance");
                    not_found_count += 1;
                    None
                } else {
                    Some((session_id, path))
                }
            })
            .collect();

        let found_count = recording_paths.len();

        let result = ProcessResult {
            not_found_count,
            found_count,
            recording_paths,
        };

        Ok(result)
    }
}

#[derive(Deserialize, Serialize)]
pub struct DeleteRecordingsJob {
    recording_paths: Vec<(Uuid, Utf8PathBuf)>,
}

impl DeleteRecordingsJob {
    pub const NAME: &'static str = "delete-recordings";
}

#[axum::async_trait]
impl job_queue::Job for DeleteRecordingsJob {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(self).context("failed to serialize RemuxAction")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        for (session_id, path) in core::mem::take(&mut self.recording_paths) {
            if let Err(error) = delete_recording(&path).await {
                debug!(
                    error = format!("{error:#}"),
                    "Failed to delete recording for session {session_id}"
                );
            }
        }

        Ok(())
    }
}

async fn delete_recording(recording_path: &Utf8Path) -> anyhow::Result<()> {
    info!(%recording_path, "Delete recording");

    tokio::fs::remove_dir_all(&recording_path)
        .await
        .with_context(|| format!("failed to remove folder {recording_path}"))?;

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

pub(crate) async fn list_realtime_recordings(
    State(DgwState { recordings, .. }): State<DgwState>,
    _scope: RecordingsReadScope,
) -> Result<Json<Vec<Uuid>>, HttpError> {
    let recordings = recordings.active_recordings.copy_set().into_iter().collect();
    Ok(Json(recordings))
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

async fn stream_recording(
    State(DgwState {
        recordings,
        shutdown_signal,
        conf_handle,
        ..
    }): State<DgwState>,
    extract::Path((id, filename)): extract::Path<(Uuid, String)>,
    JrecToken(claims): JrecToken,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
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

    crate::streaming::stream_file(path, ws, shutdown_signal, recordings, id)
        .await
        .map_err(HttpError::internal().err())
}
