use anyhow::Context;
use axum::{body::Body, response::Response};
use streamer::{config::CpuCount, webm_stream, ReOpenableFile};
use uuid::Uuid;

use crate::{recording::OnGoingRecordingState, token::RecordingFileType, ws::websocket_compat};

struct ShutdownSignal(devolutions_gateway_task::ShutdownSignal);

impl streamer::Signal for ShutdownSignal {
    fn wait(&mut self) -> impl std::future::Future<Output = ()> + Send {
        self.0.wait()
    }
}

pub(crate) async fn stream_file(
    path: camino::Utf8PathBuf,
    ws: axum::extract::WebSocketUpgrade,
    shutdown_signal: devolutions_gateway_task::ShutdownSignal,
    recordings: crate::recording::RecordingMessageSender,
    recording_id: Uuid,
) -> anyhow::Result<Response<Body>> {
    // 1.identify the file type
    if path.extension() != Some(RecordingFileType::WebM.extension()) {
        anyhow::bail!("invalid file type");
    }
    // 2.if the file is actively being recorded, then proceed
    let Ok(Some(OnGoingRecordingState::Connected)) = recordings.get_state(recording_id).await else {
        anyhow::bail!("file is not being recorded");
    };

    let streaming_file = ReOpenableFile::open(&path).with_context(|| format!("failed to open file: {path:?}"))?;

    let upgrade_result = ws.on_upgrade(move |socket| async move {
        let websocket_stream = websocket_compat(socket);
        // Spawn blocking because webm_stream is blocking
        let streaming_result = tokio::task::spawn_blocking(move || {
            webm_stream(
                websocket_stream,
                streaming_file,
                ShutdownSignal(shutdown_signal),
                streamer::StreamingConfig {
                    encoder_threads: CpuCount::default(),
                },
                move || {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    recordings.add_new_chunk_listener(recording_id, tx);
                    rx
                },
            )
            .context("webm_stream failed")?;
            Ok::<_, anyhow::Error>(())
        })
        .await;

        match streaming_result {
            Err(e) => {
                error!(?e, "Streaming file task join failed");
            }
            Ok(Err(e)) => {
                error!(?e, "Streaming file failed");
            }
            _ => {}
        };
    });

    Ok(upgrade_result)
}
