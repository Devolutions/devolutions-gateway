use std::sync::Arc;

use anyhow::Context;
use axum::{body::Body, response::Response};
use streamer::{config::CpuCount, webm_stream, ReOpenableFile};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::{
    recording::OnGoingRecordingState,
    token::RecordingFileType,
    ws::websocket_compat,
};

struct ShutdownSignal(Arc<Notify>);

impl streamer::Signal for ShutdownSignal {
    fn wait(&mut self) -> impl std::future::Future<Output = ()> + Send {
        self.0.notified()
    }
}

pub(crate) async fn stream_file(
    recording_folder_path: camino::Utf8PathBuf,
    ws: axum::extract::WebSocketUpgrade,
    shutdown_notify: Arc<Notify>,
    recordings: crate::recording::RecordingMessageSender,
    recording_id: Uuid,
) -> anyhow::Result<Response<Body>> {
    let recording_file_path = get_recording_file_path(recording_folder_path)?;
    // 1.identify the file type
    if recording_file_path.extension() != Some(RecordingFileType::WebM.extension()) {
        anyhow::bail!("invalid file type");
    }
    // 2.if the file is actively being recorded, then proceed
    let Ok(Some(OnGoingRecordingState::Connected)) = recordings.get_state(recording_id).await else {
        anyhow::bail!("file is not being recorded");
    };

    let streaming_file = ReOpenableFile::open(&recording_file_path)?;

    let streamer_config = streamer::StreamingConfig {
        encoder_threads: CpuCount::default(),
    };

    let shutdown_signal = ShutdownSignal(shutdown_notify);

    let when_new_chunk_appended = move || {
        let (tx, rx) = tokio::sync::oneshot::channel();
        recordings.add_new_chunk_listener(recording_id, tx);
        rx
    };

    let upgrade_result = ws.on_upgrade(move |socket| async move {
        let websocket_stream = websocket_compat(socket);
        // Spawn blocking because webm_stream is blocking
        let streaming_result = tokio::task::spawn_blocking(move || {
            webm_stream(
                websocket_stream,
                streaming_file,
                shutdown_signal,
                streamer_config,
                when_new_chunk_appended,
            )
            .context("webm_stream failed")?;
            Ok::<_, anyhow::Error>(())
        })
        .await;

        match streaming_result {
            Err(e) => {
                error!(error=?e, "Streaming file task join failed");
            }
            Ok(Err(e)) => {
                error!(error = format!("{e:#}"), "Streaming file failed");
            }
            _ => {}
        };
    });

    return Ok(upgrade_result);

    fn get_recording_file_path(recording_folder_path: camino::Utf8PathBuf) -> anyhow::Result<camino::Utf8PathBuf> {
        use serde_json::Value;
        let json = std::fs::read(recording_folder_path.join("recording.json"))?;
        let json: Value = serde_json::from_slice(&json)?;
        let Value::Array(files) = &json["files"] else {
            anyhow::bail!("no files or files are not array in recording.json");
        };

        let file = files.last().context("no files in manifest")?;
        let Value::Object(file) = file else {
            anyhow::bail!("file is not an object");
        };

        let Value::String(file_name) = &file["fileName"] else {
            anyhow::bail!("file_name is not a string");
        };

        Ok(recording_folder_path.join(file_name))
    }
}
