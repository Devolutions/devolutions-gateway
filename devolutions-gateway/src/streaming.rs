use anyhow::Context;
use axum::{body::Body, response::Response};
use streamer::{config::CpuCount, webm_stream, ReOpenableFile};
use uuid::Uuid;

use crate::{
    recording::{OnGoingRecordingState, RecordingEvent},
    token::RecordingFileType,
    ws::websocket_compat,
};

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
    mut recording_event_receiver: tokio::sync::mpsc::Receiver<RecordingEvent>,
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

    // prepare the streaming task
    let recording_event_receiver = {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            while let Some(event) = recording_event_receiver.recv().await {
                let event = match event {
                    RecordingEvent::Disconnected { sender } => streamer::RecordingEvent::Disconnected { sender },
                };
                if let Err(e) = sender.send(event).await {
                    warn!(error=?e, "Failed to send recording event");
                }
            }
        });
        receiver
    };

    let streamer_config = streamer::StreamingConfig {
        encoder_threads: CpuCount::default(),
    };

    let shutdown_signal = ShutdownSignal(shutdown_signal);

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
                recording_event_receiver,
                when_new_chunk_appended,
            )
            .context("webm_stream failed")?;
            Ok::<_, anyhow::Error>(())
        })
        .await;

        match streaming_result {
            Err(e) => {
                error!(error=?e, "streaming file task join failed");
            }
            Ok(Err(e)) => {
                error!(error = format!("{e:#}"), "streaming file failed");
            }
            _ => {}
        };
    });

    Ok(upgrade_result)
}
