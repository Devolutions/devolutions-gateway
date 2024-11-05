use anyhow::Context;
use axum::{body::Body, response::Response};
use streamer::streamer::{reopenable_file::ReOpenableFile, webm_stream};
use uuid::Uuid;

use crate::{recording::OnGoingRecordingState, token::RecordingFileType, ws::websocket_compat};

pub(crate) async fn stream_file(
    path: camino::Utf8PathBuf,
    ws: axum::extract::WebSocketUpgrade,
    shutdown_signal: devolutions_gateway_task::ShutdownSignal,
    recordings: crate::recording::RecordingMessageSender,
    recording_id: Uuid,
) -> anyhow::Result<Response<Body>> {
    // 1. Identify the file type.
    if path.extension() != Some(RecordingFileType::WebM.extension()) {
        return Err(anyhow::anyhow!("invalid file type"));
    }

    // 2. If the file is actively being recorded, then proceed.
    let Ok(Some(OnGoingRecordingState::Connected)) = recordings.get_state(recording_id).await else {
        return Err(anyhow::anyhow!("file is not being recorded"));
    };

    let streaming_file = ReOpenableFile::open(&path).with_context(|| format!("failed to open file: {path:?}"))?;

    let upgrade_result = ws.on_upgrade(move |socket| async move {
        let websocket_stream = websocket_compat(socket);

        // Spawn blocking because webm_stream is blocking.
        let streaming_result = tokio::task::spawn_blocking(move || {
            webm_stream(websocket_stream, streaming_file, shutdown_signal, move || {
                let (tx, rx) = tokio::sync::oneshot::channel();
                recordings
                    .add_new_chunk_listener(recording_id, tx)
                    .expect("failed to send on_appended message"); // early development
                rx
            })
            .context("webm_stream failed")?;
            Ok::<_, anyhow::Error>(())
        })
        .await;

        match streaming_result {
            Err(e) => {
                error!(?e, "streaming file task join failed");
            }
            Ok(Err(e)) => {
                error!(?e, "streaming file failed");
            }
            _ => {}
        };
    });

    Ok(upgrade_result)
}
