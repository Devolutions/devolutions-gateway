use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::ws::WebSocket;
use axum::extract::{self, ConnectInfo, Query, State, WebSocketUpgrade};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::fs::File;
use tracing::Instrument as _;
use uuid::Uuid;

use crate::config::Conf;
use crate::extract::{JrecToken, RecordingsReadScope};
use crate::http::HttpError;
use crate::token::{JrecTokenClaims, RecordingFileType, RecordingOperation};
use crate::DgwState;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/push/:id", get(jrec_push))
        .route("/list", get(list_recordings))
        .route("/pull/:id/:filename", get(pull_recording_file))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecPushQueryParam {
    file_type: RecordingFileType,
}

async fn jrec_push(
    State(DgwState { conf_handle, .. }): State<DgwState>,
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

    let response =
        ws.on_upgrade(move |ws| handle_jrec_push(ws, conf, claims, query.file_type, session_id, source_addr));

    Ok(response)
}

async fn handle_jrec_push(
    ws: WebSocket,
    conf: Arc<Conf>,
    claims: JrecTokenClaims,
    file_type: RecordingFileType,
    session_id: Uuid,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = crate::jrec::ClientPush::builder()
        .client_stream(stream)
        .conf(conf)
        .claims(claims)
        .file_type(file_type)
        .session_id(session_id)
        .build()
        .run()
        .instrument(info_span!("jrec", client = %source_addr))
        .await;

    if let Err(error) = result {
        error!(client = %source_addr, error = format!("{error:#}"), "WebSocket-JREC failure");
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
pub(crate) async fn list_recordings(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    _scope: RecordingsReadScope,
) -> Result<Json<Vec<Uuid>>, HttpError> {
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
    State(DgwState { conf_handle, .. }): State<DgwState>,
    extract::Path((id, filename)): extract::Path<(Uuid, String)>,
    JrecToken(claims): JrecToken,
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

    let file = File::open(path).await.map_err(HttpError::internal().err())?;

    Ok(axum_extra::body::AsyncReadBody::new(file).into_response())
}
