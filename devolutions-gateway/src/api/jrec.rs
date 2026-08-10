use std::fs;
use std::io::{self, Seek as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use axum::body::Body;
use axum::extract::ws::{CloseFrame, WebSocket};
use axum::extract::{self, ConnectInfo, Query, State, WebSocketUpgrade};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderValue};
use axum::response::Response;
use axum::routing::{delete, get};
use axum::{Json, Router};
use bytes::Bytes;
use cadeau::xmf;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_task::ShutdownSignal;
use futures::stream;
use hyper::StatusCode;
use tokio::io::AsyncReadExt as _;
use tracing::Instrument as _;
use uuid::Uuid;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

use crate::DgwState;
use crate::api::heartbeat::recording_storage_health;
use crate::extract::{JrecToken, RecordingDeleteScope, RecordingsReadScope};
use crate::http::{HttpError, HttpErrorBuilder};
use crate::recording::{PushOutcome, RecordingMessageSender};
use crate::token::{JrecTokenClaims, RecordingFileType, RecordingOperation};

/// Read chunk size when streaming a finished session ZIP from the temp file.
const ZIP_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum files in a session ZIP (`recording.json` + clips).
///
/// Reconnect windows only mint a small number of clips per session in practice;
/// this bound blocks pathological manifests without rejecting normal multi-clip packages.
const MAX_RECORDING_ZIP_FILES: usize = 128;

/// Maximum total uncompressed payload (bytes) for a session ZIP download.
///
/// Chosen to cover multi-hour WebM packages with headroom while limiting concurrent bulk pulls.
const MAX_RECORDING_ZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/push/{id}", get(jrec_push))
        .route("/delete/{id}", delete(jrec_delete))
        .route("/delete", delete(jrec_delete_many))
        .route("/list", get(list_recordings))
        .route("/pull/{id}", get(pull_recording_session))
        .route("/pull/{id}/{filename}", get(pull_recording_file))
        .route("/play", get(get_player))
        .route("/play/{*path}", get(get_player))
        .route("/shadow/{id}", get(shadow_recording))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecPushQueryParam {
    file_type: RecordingFileType,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JrecListQueryParam {
    #[serde(default)]
    active: bool,
}

async fn jrec_push(
    State(DgwState {
        shutdown_signal,
        recordings,
        conf_handle,
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

    let conf = conf_handle.get_conf();

    // Pre-flight: refuse the upgrade up-front when the recording storage cannot accept
    // a new stream. Returning HTTP 507 here gives the client a clear, actionable status
    // before the WebSocket is even established, so it can avoid a doomed session entirely.
    //
    // The recording directory is created lazily by design (see #1746) so that disk-space
    // reporting still works on a not-yet-mounted volume. Ensure it exists for the probe
    // below; if creation itself fails, surface that as 507.
    if let Err(error) = tokio::fs::create_dir_all(&conf.recording_path).await {
        warn!(
            client = %source_addr,
            %session_id,
            %error,
            "Refusing JREC push: failed to ensure recording storage directory"
        );
        return Err(HttpErrorBuilder::new(StatusCode::INSUFFICIENT_STORAGE).msg("recording storage is not accessible"));
    }

    let storage = recording_storage_health(conf.recording_path.as_std_path());
    if !storage.recording_storage_is_writeable {
        warn!(client = %source_addr, %session_id, "Refusing JREC push: recording storage is not writable");
        return Err(HttpErrorBuilder::new(StatusCode::INSUFFICIENT_STORAGE).msg("recording storage is not writable"));
    }
    if let (Some(min), Some(available)) = (
        conf.min_recording_storage_free_space,
        storage.recording_storage_available_space,
    ) && available < min
    {
        warn!(
            client = %source_addr,
            %session_id,
            available_bytes = available,
            min_bytes = min,
            "Refusing JREC push: free space below configured minimum"
        );
        return Err(HttpErrorBuilder::new(StatusCode::INSUFFICIENT_STORAGE)
            .msg("recording storage below minimum free-space threshold"));
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
            Duration::from_secs(conf_handle.get_conf().debug.ws_keep_alive_interval),
        )
    });

    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn handle_jrec_push(
    ws: WebSocket,
    recordings: RecordingMessageSender,
    shutdown_signal: ShutdownSignal,
    claims: JrecTokenClaims,
    file_type: RecordingFileType,
    session_id: Uuid,
    source_addr: SocketAddr,
    keep_alive_interval: Duration,
) {
    let (stream, close_handle) = crate::ws::handle(
        ws,
        crate::ws::KeepAliveShutdownSignal(shutdown_signal.clone()),
        keep_alive_interval,
    );

    let result = crate::recording::ClientPush::builder()
        .client_stream(stream)
        .recordings(recordings)
        .claims(claims)
        .file_type(file_type)
        .session_id(session_id)
        .shutdown_signal(shutdown_signal)
        .build()
        .run()
        .instrument(info_span!("jrec", client = %source_addr, %session_id))
        .await;

    match result {
        Ok(PushOutcome::Done) => close_handle.normal_close().await,
        Ok(PushOutcome::StorageFull) => {
            warn!(client = %source_addr, %session_id, "JREC push closed: storage full");
            close_handle.app_close(STORAGE_FULL_CLOSE_CODE).await;
        }
        Err(error) => {
            close_handle.server_error("forwarding failure".to_owned()).await;
            error!(client = %source_addr, error = format!("{error:#}"), "WebSocket-JREC failure");
        }
    }
}

/// WebSocket close code sent on `/jrec/push/{id}` when the recording storage volume is full
/// and the stream cannot continue.
///
/// Codes in 4000-4999 are reserved for private application use per
/// <https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code>.
const STORAGE_FULL_CLOSE_CODE: u16 = 4010;

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
        (status = 409, description = "The recording is still ongoing and can't be deleted yet"),
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
        (status = 409, description = "A recording is still ongoing and can't be deleted yet (nothing is deleted)"),
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

#[async_trait::async_trait]
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
    params(
        ("active" = bool, Query, description = "When true, only the active recordings are returned"),
    ),
    responses(
        (status = 200, description = "List of recordings on this Gateway instance", body = [Uuid]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.recordings.read"])),
))]
pub(crate) async fn list_recordings(
    State(DgwState {
        conf_handle,
        recordings,
        ..
    }): State<DgwState>,
    Query(query): Query<JrecListQueryParam>,
    _scope: RecordingsReadScope,
) -> Result<Json<Vec<Uuid>>, HttpError> {
    if query.active {
        let recordings = recordings.active_recordings.cloned().into_iter().collect();
        return Ok(Json(recordings));
    }

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

/// Downloads an entire recorded session as a ZIP archive
///
/// The archive always contains `recording.json` and every clip listed in that manifest that is present on disk.
/// A single-clip session is still returned as a ZIP so callers can use one download contract for every recording.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "PullRecordingSession",
    tag = "Jrec",
    path = "/jet/jrec/pull/{id}",
    params(
        ("id" = Uuid, Path, description = "Recorded session ID"),
    ),
    responses(
        (status = 200, description = "ZIP archive containing the recording session", body = Vec<u8>, content_type = "application/zip"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Recording not found"),
        (status = 413, description = "Recording package exceeds download size or file-count limits"),
    ),
    security(("jrec_token" = ["pull"])),
))]
pub(crate) async fn pull_recording_session(
    State(DgwState {
        conf_handle,
        shutdown_signal,
        ..
    }): State<DgwState>,
    extract::Path(id): extract::Path<Uuid>,
    JrecToken(claims): JrecToken,
) -> Result<Response, HttpError> {
    if claims.jet_rop != RecordingOperation::Pull {
        return Err(HttpError::forbidden().msg("expected pull operation"));
    }

    if id != claims.jet_aid {
        return Err(HttpError::forbidden().msg("not allowed to read this recording"));
    }

    let recording_dir = conf_handle.get_conf().recording_path.join(id.to_string());

    if !recording_dir.is_dir() {
        return Err(HttpError::not_found().msg("requested recording does not exist"));
    }

    // Snapshot membership once so a reconnect cannot widen the package after we start packaging.
    let plan = snapshot_recording_zip_plan(&recording_dir).await?;
    enforce_recording_zip_limits(&recording_dir, &plan).await?;

    let body = recording_zip_body(recording_dir, plan, id, shutdown_signal).await?;
    let mut response = Response::new(body);

    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/zip"));

    let disposition = format!("attachment; filename=\"{id}.zip\"");
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).map_err(HttpError::internal().err())?,
    );

    Ok(response)
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

    if claims.jet_rop != RecordingOperation::Pull {
        return Err(HttpError::forbidden().msg("expected pull operation"));
    }

    if !is_safe_recording_file_name(&filename) {
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

    if !path.is_file() {
        return Err(HttpError::not_found().msg("requested file does not exist"));
    }

    let mut response = tower_http::services::ServeFile::new(&path)
        .oneshot(request)
        .await
        .map_err(HttpError::internal().err())?;

    let content_type = path
        .extension()
        .and_then(RecordingFileType::from_extension)
        .and_then(RecordingFileType::content_type);

    if let Some(content_type) = content_type {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    }

    Ok(response)
}

/// Minimal `recording.json` view used when packaging a session download.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordingZipManifest {
    files: Vec<RecordingZipManifestFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordingZipManifestFile {
    file_name: String,
}

fn is_safe_recording_file_name(file_name: &str) -> bool {
    !file_name.is_empty() && !file_name.contains("..") && !file_name.contains('/') && !file_name.contains('\\')
}

/// Immutable package membership for one download attempt.
///
/// `manifest_bytes` are the exact `recording.json` contents used to derive `clip_names`,
/// so the archived manifest cannot drift from the clips included in the ZIP.
#[derive(Debug, Clone)]
struct RecordingZipPlan {
    manifest_bytes: Vec<u8>,
    clip_names: Vec<String>,
}

impl RecordingZipPlan {
    fn entry_count(&self) -> usize {
        1 /* recording.json */ + self.clip_names.len()
    }
}

/// Snapshots `recording.json` and the clip files it references at call time.
async fn snapshot_recording_zip_plan(recording_dir: &Utf8Path) -> Result<RecordingZipPlan, HttpError> {
    let manifest_path = recording_dir.join("recording.json");
    let manifest_bytes = tokio::fs::read(&manifest_path).await.map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            HttpError::not_found().msg("requested recording does not exist")
        } else {
            HttpError::internal()
                .with_msg("failed to read recording manifest")
                .build(anyhow::Error::new(error).context(format!("read recording manifest at {manifest_path}")))
        }
    })?;

    let manifest: RecordingZipManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        // Corrupt/incomplete package: treat as missing recording for the pull contract.
        debug!(
            error = format!("{error:#}"),
            path = %manifest_path,
            "Invalid recording manifest"
        );
        HttpError::not_found().msg("requested recording does not exist")
    })?;

    let mut clip_names = Vec::with_capacity(manifest.files.len());
    for file in manifest.files {
        if !is_safe_recording_file_name(&file.file_name) {
            warn!(
                file_name = %file.file_name,
                "Skipping unsafe recording file name from manifest"
            );
            continue;
        }

        let path = recording_dir.join(&file.file_name);
        if path.is_file() {
            clip_names.push(file.file_name);
        } else {
            warn!(
                file_name = %file.file_name,
                path = %path,
                "Skipping missing recording file listed in manifest"
            );
        }
    }

    Ok(RecordingZipPlan {
        manifest_bytes,
        clip_names,
    })
}

/// Identifies which fixed session-ZIP safety bound a package exceeds, if any.
fn recording_zip_limits_exceeded(file_count: usize, total_bytes: u64) -> Option<RecordingZipLimitKind> {
    if file_count > MAX_RECORDING_ZIP_FILES {
        Some(RecordingZipLimitKind::FileCount)
    } else if total_bytes > MAX_RECORDING_ZIP_BYTES {
        Some(RecordingZipLimitKind::TotalBytes)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordingZipLimitKind {
    FileCount,
    TotalBytes,
}

impl RecordingZipLimitKind {
    const fn message(self) -> &'static str {
        match self {
            Self::FileCount => "recording package exceeds maximum file count for download",
            Self::TotalBytes => "recording package exceeds maximum size for download",
        }
    }
}

/// Rejects session packages that are too large to stream safely through this endpoint.
///
/// Limits are evaluated up front from directory metadata so the client gets a clear HTTP error
/// instead of a multi-gigabyte transfer that may time out or pressure the host.
async fn enforce_recording_zip_limits(recording_dir: &Utf8Path, plan: &RecordingZipPlan) -> Result<(), HttpError> {
    let mut total_bytes = u64::try_from(plan.manifest_bytes.len()).unwrap_or(u64::MAX);
    for file_name in &plan.clip_names {
        let path = recording_dir.join(file_name);
        let metadata = tokio::fs::metadata(&path).await.map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                HttpError::not_found().msg("requested recording does not exist")
            } else {
                HttpError::internal()
                    .with_msg("failed to stat recording file for download limits")
                    .build(error)
            }
        })?;
        total_bytes = total_bytes.saturating_add(metadata.len());
    }

    match recording_zip_limits_exceeded(plan.entry_count(), total_bytes) {
        None => Ok(()),
        Some(kind) => {
            warn!(
                ?kind,
                file_count = plan.entry_count(),
                total_bytes,
                file_limit = MAX_RECORDING_ZIP_FILES,
                byte_limit = MAX_RECORDING_ZIP_BYTES,
                path = %recording_dir,
                "Refusing recording ZIP download: package exceeds safety limits"
            );
            Err(HttpErrorBuilder::new(StatusCode::PAYLOAD_TOO_LARGE).msg(kind.message()))
        }
    }
}

/// Builds a complete, interoperable ZIP then streams it.
///
/// Packaging uses the standard `zip` crate with known entry sizes/CRC so common OS unzippers accept the archive.
/// The snapshotted manifest bytes are written as-is (not re-read), keeping membership consistent.
async fn recording_zip_body(
    recording_dir: Utf8PathBuf,
    plan: RecordingZipPlan,
    session_id: Uuid,
    mut shutdown_signal: ShutdownSignal,
) -> Result<Body, HttpError> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_shutdown = Arc::clone(&cancel);
    tokio::spawn(async move {
        shutdown_signal.wait().await;
        cancel_for_shutdown.store(true, Ordering::Relaxed);
    });

    let recording_dir_for_build = PathBuf::from(recording_dir.as_std_path());
    let plan_for_build = plan;
    let built = tokio::task::spawn_blocking(move || {
        build_recording_zip_archive(&recording_dir_for_build, &plan_for_build, &cancel)
    })
    .await
    .map_err(|error| {
        HttpError::internal()
            .with_msg("recording ZIP worker failed")
            .build(error)
    })?
    .map_err(|error| {
        if error.root_cause().downcast_ref::<RecordingZipCancelled>().is_some() {
            HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("recording download cancelled")
        } else {
            warn!(
                error = format!("{error:#}"),
                session.id = %session_id,
                "Failed to build recording ZIP archive"
            );
            HttpError::internal()
                .with_msg("failed to build recording ZIP archive")
                .build(error)
        }
    })?;

    let (std_file, temp_path) = built.into_parts();
    let file = tokio::fs::File::from_std(std_file);
    Ok(Body::from_stream(zip_file_body_stream(file, temp_path)))
}

#[derive(Debug)]
struct RecordingZipCancelled;

impl std::fmt::Display for RecordingZipCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("recording ZIP build cancelled")
    }
}

impl std::error::Error for RecordingZipCancelled {}

/// Writes a STORED ZIP with valid local-file headers to a temporary file.
fn build_recording_zip_archive(
    recording_dir: &Path,
    plan: &RecordingZipPlan,
    cancel: &AtomicBool,
) -> anyhow::Result<tempfile::NamedTempFile> {
    if cancel.load(Ordering::Relaxed) {
        return Err(anyhow::Error::new(RecordingZipCancelled));
    }

    let mut tmp = tempfile::NamedTempFile::new().context("create temp file for recording ZIP")?;
    {
        let mut zip = zip::ZipWriter::new(tmp.as_file_mut());
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

        zip.start_file("recording.json", options)
            .context("start recording.json ZIP entry")?;
        zip.write_all(&plan.manifest_bytes)
            .context("write recording.json ZIP entry")?;

        for file_name in &plan.clip_names {
            if cancel.load(Ordering::Relaxed) {
                return Err(anyhow::Error::new(RecordingZipCancelled));
            }

            let path = recording_dir.join(file_name);
            let mut file =
                fs::File::open(&path).with_context(|| format!("open recording file at {}", path.display()))?;

            zip.start_file(file_name.as_str(), options)
                .with_context(|| format!("start ZIP entry for {file_name}"))?;
            io::copy(&mut file, &mut zip).with_context(|| format!("write ZIP entry for {file_name}"))?;
        }

        zip.finish().context("finish ZIP archive")?;
    }

    tmp.as_file_mut().sync_all().context("sync recording ZIP temp file")?;
    tmp.as_file_mut()
        .seek(io::SeekFrom::Start(0))
        .context("rewind recording ZIP temp file")?;
    Ok(tmp)
}

fn zip_file_body_stream(
    file: tokio::fs::File,
    temp_path: tempfile::TempPath,
) -> impl stream::Stream<Item = Result<Bytes, io::Error>> {
    stream::unfold(
        ZipFileBodyState {
            file,
            // Keep the temp path alive until the response body is fully consumed or dropped.
            _temp_path: temp_path,
            buffer: vec![0u8; ZIP_CHUNK_SIZE],
            finished: false,
        },
        |mut state| async move {
            if state.finished {
                return None;
            }

            match state.file.read(&mut state.buffer).await {
                Ok(0) => {
                    state.finished = true;
                    None
                }
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(&state.buffer[..n]);
                    Some((Ok(chunk), state))
                }
                Err(error) => {
                    state.finished = true;
                    Some((Err(error), state))
                }
            }
        },
    )
}

struct ZipFileBodyState {
    file: tokio::fs::File,
    _temp_path: tempfile::TempPath,
    buffer: Vec<u8>,
    finished: bool,
}

async fn get_player<ReqBody>(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    path: Option<extract::Path<String>>,
    request: axum::http::Request<ReqBody>,
) -> Result<Response<tower_http::services::fs::ServeFileSystemResponseBody>, HttpError>
where
    ReqBody: Send + 'static,
{
    let conf = conf_handle.get_conf();

    let player_root = conf.web_app.static_root_path.join("player/");
    let player_index = conf.web_app.static_root_path.join("player/index.html");

    crate::http::serve_dir(request, path, player_root, player_index).await
}

// Code from 4000 to 4999 are reserved for private custom use
// https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code
enum StreamerCloseCode {
    StreamingEnded = 4001,
    InternalError = 4002,
    Forbidden = 4003,
}

impl From<StreamerCloseCode> for CloseFrame {
    fn from(code: StreamerCloseCode) -> Self {
        CloseFrame {
            code: code as u16 as extract::ws::CloseCode,
            reason: extract::ws::Utf8Bytes::from_static(""),
        }
    }
}

async fn shadow_recording(
    State(DgwState { recordings, .. }): State<DgwState>,
    extract::Path(id): extract::Path<Uuid>,
    JrecToken(claims): JrecToken,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if id != claims.jet_aid {
        return close_with_error(ws, StreamerCloseCode::Forbidden);
    }

    if !recordings.active_recordings.contains(id) {
        return close_with_error(ws, StreamerCloseCode::StreamingEnded);
    }

    let Ok(Some(crate::recording::OnGoingRecordingState::Connected)) = recordings.get_state(id).await else {
        return close_with_error(ws, StreamerCloseCode::StreamingEnded);
    };

    if !xmf::is_init() {
        warn!(%id, "Shadow recording rejected: XMF native library is not loaded");
        return close_with_error(ws, StreamerCloseCode::InternalError);
    }

    let Ok(notify) = recordings.subscribe_to_recording_finish(id).await else {
        warn!(%id, "Shadow recording rejected: failed to subscribe to recording finish");
        return close_with_error(ws, StreamerCloseCode::InternalError);
    };

    let Ok(recording_files) = recordings.list_files(id).await else {
        warn!(%id, "Shadow recording rejected: failed to list recording files");
        return close_with_error(ws, StreamerCloseCode::InternalError);
    };

    let Some(recording_path) = recording_files.last() else {
        warn!(%id, "Shadow recording rejected: no recording files found");
        return close_with_error(ws, StreamerCloseCode::InternalError);
    };

    return crate::streaming::stream_file(recording_path, ws, notify, recordings, id)
        .await
        .map_err(|_| HttpError::internal().msg("failed to stream file"));

    fn close_with_error(ws: WebSocketUpgrade, code: StreamerCloseCode) -> Result<Response, HttpError> {
        Ok(ws.on_upgrade(move |mut ws| async move {
            let _ = ws.send(extract::ws::Message::Close(Some(code.into()))).await;
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use http_body_util::BodyExt as _;
    use zip::ZipArchive;

    use super::*;

    #[test]
    fn rejects_unsafe_recording_file_names() {
        assert!(is_safe_recording_file_name("recording-0.webm"));
        assert!(is_safe_recording_file_name("recording.json"));
        assert!(!is_safe_recording_file_name(""));
        assert!(!is_safe_recording_file_name("../secret.webm"));
        assert!(!is_safe_recording_file_name("a/b.webm"));
        assert!(!is_safe_recording_file_name("a\\b.webm"));
    }

    #[tokio::test]
    async fn snapshots_manifest_files_for_zip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");

        let manifest = serde_json::json!({
            "sessionId": "11111111-1111-1111-1111-111111111111",
            "startTime": 1,
            "duration": 10,
            "files": [
                { "fileName": "recording-0.webm", "startTime": 1, "duration": 5 },
                { "fileName": "recording-1.webm", "startTime": 6, "duration": 5 },
                { "fileName": "missing.webm", "startTime": 11, "duration": 1 },
                { "fileName": "../escape.webm", "startTime": 12, "duration": 1 }
            ]
        });
        let manifest_bytes = manifest.to_string().into_bytes();

        tokio::fs::write(dir_path.join("recording.json"), &manifest_bytes)
            .await
            .expect("write manifest");
        tokio::fs::write(dir_path.join("recording-0.webm"), b"clip-zero")
            .await
            .expect("write clip 0");
        tokio::fs::write(dir_path.join("recording-1.webm"), b"clip-one")
            .await
            .expect("write clip 1");

        let plan = snapshot_recording_zip_plan(&dir_path)
            .await
            .unwrap_or_else(|error| panic!("snapshot plan: {error}"));
        assert_eq!(plan.manifest_bytes, manifest_bytes);
        assert_eq!(
            plan.clip_names,
            vec!["recording-0.webm".to_owned(), "recording-1.webm".to_owned()]
        );
    }

    #[tokio::test]
    async fn zip_keeps_snapshotted_manifest_when_disk_manifest_changes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");

        let original = serde_json::json!({
            "sessionId": "22222222-2222-2222-2222-222222222222",
            "startTime": 1,
            "duration": 2,
            "files": [
                { "fileName": "recording-0.webm", "startTime": 1, "duration": 2 }
            ]
        })
        .to_string()
        .into_bytes();

        tokio::fs::write(dir_path.join("recording.json"), &original)
            .await
            .expect("write original manifest");
        tokio::fs::write(dir_path.join("recording-0.webm"), b"clip-zero")
            .await
            .expect("write clip 0");

        let plan = snapshot_recording_zip_plan(&dir_path)
            .await
            .unwrap_or_else(|error| panic!("snapshot plan: {error}"));

        // Simulate a reconnect rewriting the live manifest after the download snapshot.
        let updated = serde_json::json!({
            "sessionId": "22222222-2222-2222-2222-222222222222",
            "startTime": 1,
            "duration": 4,
            "files": [
                { "fileName": "recording-0.webm", "startTime": 1, "duration": 2 },
                { "fileName": "recording-1.webm", "startTime": 3, "duration": 2 }
            ]
        })
        .to_string()
        .into_bytes();
        tokio::fs::write(dir_path.join("recording.json"), &updated)
            .await
            .expect("rewrite manifest");
        tokio::fs::write(dir_path.join("recording-1.webm"), b"clip-one")
            .await
            .expect("write clip 1");

        let archive =
            build_recording_zip_archive(dir_path.as_std_path(), &plan, &AtomicBool::new(false)).expect("build zip");
        let mut zip = ZipArchive::new(archive.reopen().expect("reopen zip")).expect("open zip");
        assert_eq!(zip.len(), 2);

        let mut manifest_entry = zip.by_name("recording.json").expect("manifest entry");
        let mut archived_manifest = Vec::new();
        manifest_entry
            .read_to_end(&mut archived_manifest)
            .expect("read archived manifest");
        assert_eq!(archived_manifest, original);
        assert_ne!(archived_manifest, updated);
    }

    #[tokio::test]
    async fn streams_interoperable_zip_with_all_listed_clips() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");

        let manifest = serde_json::json!({
            "sessionId": "22222222-2222-2222-2222-222222222222",
            "startTime": 1,
            "duration": 4,
            "files": [
                { "fileName": "recording-0.webm", "startTime": 1, "duration": 2 },
                { "fileName": "recording-1.webm", "startTime": 3, "duration": 2 }
            ]
        });
        let manifest_bytes = manifest.to_string().into_bytes();

        tokio::fs::write(dir_path.join("recording.json"), &manifest_bytes)
            .await
            .expect("write manifest");
        tokio::fs::write(dir_path.join("recording-0.webm"), b"first-clip")
            .await
            .expect("write clip 0");
        tokio::fs::write(dir_path.join("recording-1.webm"), b"second-clip")
            .await
            .expect("write clip 1");

        let plan = snapshot_recording_zip_plan(&dir_path)
            .await
            .unwrap_or_else(|error| panic!("snapshot plan: {error}"));
        let (shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
        let body = recording_zip_body(dir_path.clone(), plan, Uuid::nil(), shutdown_signal)
            .await
            .unwrap_or_else(|error| panic!("build body: {error}"));
        let zip_bytes = body.collect().await.expect("collect ZIP body").to_bytes().to_vec();
        drop(shutdown_handle);

        assert_eq!(&zip_bytes[..2], b"PK");

        // Interop: standard zip crate reader (same class of local-header expectations as OS tools).
        let cursor = io::Cursor::new(zip_bytes);
        let mut archive = ZipArchive::new(cursor).expect("parse zip with standard reader");
        assert_eq!(archive.len(), 3);

        let expected = [
            ("recording.json", manifest_bytes.as_slice()),
            ("recording-0.webm", b"first-clip".as_slice()),
            ("recording-1.webm", b"second-clip".as_slice()),
        ];
        for (name, payload) in expected {
            let mut entry = archive.by_name(name).unwrap_or_else(|_| panic!("missing {name}"));
            let mut content = Vec::new();
            entry.read_to_end(&mut content).expect("read entry");
            assert_eq!(content, payload, "payload mismatch for {name}");
            assert_eq!(entry.compression(), CompressionMethod::Stored);
        }
    }

    #[tokio::test]
    async fn missing_manifest_is_not_found() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");

        let error = snapshot_recording_zip_plan(&dir_path)
            .await
            .expect_err("missing manifest");
        assert_eq!(error.code, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn corrupt_manifest_is_not_found() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");

        tokio::fs::write(dir_path.join("recording.json"), b"{not-json")
            .await
            .expect("write corrupt manifest");

        let error = snapshot_recording_zip_plan(&dir_path)
            .await
            .expect_err("corrupt manifest");
        assert_eq!(error.code, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn manifest_read_failure_is_internal_error_with_context() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");
        tokio::fs::create_dir(dir_path.join("recording.json"))
            .await
            .expect("create manifest directory");

        let error = snapshot_recording_zip_plan(&dir_path)
            .await
            .expect_err("manifest read should fail");
        assert_eq!(error.code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            error
                .source
                .as_deref()
                .is_some_and(|source| source.to_string().contains("read recording manifest at")),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn missing_clip_during_build_fails_before_body() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");

        let plan = RecordingZipPlan {
            manifest_bytes: b"{}".to_vec(),
            clip_names: vec!["missing-clip.webm".to_owned()],
        };
        let (_shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
        let error = recording_zip_body(dir_path, plan, Uuid::nil(), shutdown_signal)
            .await
            .expect_err("missing clip should fail packaging");
        assert_eq!(error.code, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn zip_limits_allow_typical_packages() {
        assert_eq!(recording_zip_limits_exceeded(1, 0), None);
        assert_eq!(recording_zip_limits_exceeded(2, 200 * 1024 * 1024), None);
        assert_eq!(
            recording_zip_limits_exceeded(MAX_RECORDING_ZIP_FILES, MAX_RECORDING_ZIP_BYTES),
            None
        );
    }

    #[test]
    fn zip_limits_reject_pathological_packages() {
        assert_eq!(
            recording_zip_limits_exceeded(MAX_RECORDING_ZIP_FILES + 1, 1),
            Some(RecordingZipLimitKind::FileCount)
        );
        assert_eq!(
            recording_zip_limits_exceeded(1, MAX_RECORDING_ZIP_BYTES + 1),
            Some(RecordingZipLimitKind::TotalBytes)
        );
    }

    #[tokio::test]
    async fn enforce_limits_rejects_too_many_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 path");

        let mut clip_names = Vec::with_capacity(MAX_RECORDING_ZIP_FILES);
        for index in 0..MAX_RECORDING_ZIP_FILES {
            let name = format!("f-{index}.bin");
            tokio::fs::write(dir_path.join(&name), b"x").await.expect("write file");
            clip_names.push(name);
        }

        let plan = RecordingZipPlan {
            manifest_bytes: b"{}".to_vec(),
            clip_names,
        };
        let error = enforce_recording_zip_limits(&dir_path, &plan)
            .await
            .expect_err("too many files");
        assert_eq!(error.code, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
