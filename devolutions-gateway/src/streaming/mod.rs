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
    // 1.identify the file type
    if path.extension() != Some(RecordingFileType::WebM.extension()) {
        return Err(anyhow::anyhow!("Invalid file type"));
    }
    // 2.if the file is actively being recorded, then proceed
    let Ok(Some(OnGoingRecordingState::Connected)) = recordings.get_state(recording_id).await else {
        return Err(anyhow::anyhow!("File is not being recorded"));
    };

    let streaming_file = ReOpenableFile::open(&path).with_context(|| format!("failed to open file: {path:?}"))?;

    let upgrade_result = ws.on_upgrade(move |socket| async move {
        let websocket_stream = websocket_compat(socket);
        // Spawn blocking because webm_stream is blocking
        let streaming_result = tokio::task::spawn_blocking(move || {
            webm_stream(websocket_stream, streaming_file, shutdown_signal, move || {
                let (tx, rx) = tokio::sync::oneshot::channel();
                recordings
                    .on_new_chunk_appended(recording_id, tx)
                    .expect("Failed to send on_appended message"); // early development
                rx
            })
            .context("webm_stream failed")?;
            Ok::<_, anyhow::Error>(())
        })
        .await;

        let res = match streaming_result {
            Ok(res) => res,
            Err(e) => {
                error!("Error while streaming file on join: {:?}", e);
                return;
            }
        };

        if let Err(e) = res {
            error!("Error while streaming file: {:?}", e);
        }
    });

    Ok(upgrade_result)
}
