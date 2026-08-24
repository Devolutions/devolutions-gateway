use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::body::Body;
use axum::extract::ws::{CloseFrame, Utf8Bytes, WebSocket};
use axum::response::Response;
use futures::SinkExt;
use terminal_streamer::terminal_stream;
use tokio::fs::OpenOptions;
use tokio::sync::Notify;
use uuid::Uuid;
use video_streamer::config::CpuCount;
use video_streamer::{ReOpenableFile, webm_stream};

use crate::token::RecordingFileType;

pub(crate) async fn stream_file(
    path: &camino::Utf8Path,
    ws: axum::extract::WebSocketUpgrade,
    shutdown_notify: Arc<Notify>,
    recordings: crate::recording::RecordingMessageSender,
    recording_id: Uuid,
) -> anyhow::Result<Response<Body>> {
    let streaming_type = validate_streaming_file(path).await?;

    let when_new_chunk_appended = move || {
        let (tx, rx) = tokio::sync::oneshot::channel();
        recordings.add_new_chunk_listener(recording_id, tx);
        rx
    };

    let path = Arc::new(path.to_owned());
    let upgrade_result = match streaming_type {
        StreamingType::Terminal(input_type) => {
            let shutdown_notify = Arc::clone(&shutdown_notify);
            ws.on_upgrade(move |socket| async move {
                if let Err(e) =
                    setup_terminal_streaming(&path, input_type, socket, shutdown_notify, when_new_chunk_appended).await
                {
                    error!(error = ?e, "Terminal streaming failed");
                }
            })
        }
        StreamingType::WebM => {
            let shutdown_notify = Arc::clone(&shutdown_notify);
            ws.on_upgrade(move |socket| async move {
                if let Err(e) = setup_webm_streaming(&path, socket, shutdown_notify, when_new_chunk_appended).await {
                    error!(error = ?e, "WebM streaming failed");
                }
            })
        }
    };

    Ok(upgrade_result)
}

struct TerminalStreamSocketImpl(WebSocket);

impl terminal_streamer::TerminalStreamSocket for TerminalStreamSocketImpl {
    async fn send(&mut self, value: String) -> Result<(), anyhow::Error> {
        self.0
            .send(axum::extract::ws::Message::Text(Utf8Bytes::from(value)))
            .await?;
        Ok(())
    }

    async fn close(&mut self) {
        let _ = self
            .0
            .send(axum::extract::ws::Message::Close(Some(CloseFrame {
                code: 1000,
                reason: Utf8Bytes::from_static("EOF"),
            })))
            .await;
        let _ = self.0.flush().await;
    }
}

enum StreamingType {
    Terminal(terminal_streamer::InputStreamType),
    WebM,
}

async fn validate_streaming_file(path: &camino::Utf8Path) -> anyhow::Result<StreamingType> {
    let path_extension = path
        .extension()
        .context("no extension found in the recording file path")?;

    info!(?path, extension = ?path_extension, "Streaming file");
    let file_type =
        RecordingFileType::from_extension(path_extension).ok_or_else(|| anyhow::anyhow!("invalid file type"))?;
    streaming_type_for_file_type(file_type)
}

fn streaming_type_for_file_type(file_type: RecordingFileType) -> anyhow::Result<StreamingType> {
    match file_type {
        RecordingFileType::Asciicast => Ok(StreamingType::Terminal(terminal_streamer::InputStreamType::Asciinema)),
        RecordingFileType::TRP => Ok(StreamingType::Terminal(terminal_streamer::InputStreamType::Trp)),
        RecordingFileType::WebM => Ok(StreamingType::WebM),
        RecordingFileType::SessionRecordingLog => anyhow::bail!("invalid file type"),
    }
}

async fn setup_terminal_streaming(
    path: &camino::Utf8Path,
    input_type: terminal_streamer::InputStreamType,
    socket: WebSocket,
    shutdown_notify: Arc<Notify>,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()> + Send + 'static,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    const FILE_SHARE_READ: u32 = 0x00000001;

    #[cfg(windows)]
    let streaming_file = OpenOptions::new()
        .read(true)
        .access_mode(FILE_SHARE_READ)
        .open(path)
        .await
        .with_context(|| format!("failed to open file: {path:?}"))?;

    #[cfg(not(windows))]
    let streaming_file = OpenOptions::new()
        .read(true)
        .open(path)
        .await
        .with_context(|| format!("failed to open file: {path:?}"))?;

    terminal_stream(
        TerminalStreamSocketImpl(socket),
        streaming_file,
        shutdown_notify,
        input_type,
        when_new_chunk_appended,
    )
    .await
    .inspect_err(|e| error!(error = format!("{e:#}"), "Streaming file failed"))?;

    Ok(())
}

async fn setup_webm_streaming(
    path: &camino::Utf8Path,
    socket: WebSocket,
    shutdown_notify: Arc<Notify>,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()> + Send + 'static,
) -> anyhow::Result<()> {
    let streaming_file = ReOpenableFile::open(path).with_context(|| format!("failed to open file: {path:?}"))?;
    let streamer_config = video_streamer::StreamingConfig {
        encoder_threads: CpuCount::default(),
        adaptive_frame_skip: true,
    };

    let (websocket_stream, close_handle) =
        crate::ws::handle(socket, Arc::clone(&shutdown_notify), Duration::from_secs(45));
    let streaming_result = tokio::task::spawn_blocking(move || {
        webm_stream(
            websocket_stream,
            streaming_file,
            shutdown_notify,
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
            Err(anyhow::anyhow!("Streaming task failed"))
        }
        Ok(Err(e)) => {
            close_handle.server_error("webm streaming failure".to_owned()).await;
            error!(error = format!("{e:#}"), "Streaming file failed");
            Err(e)
        }
        Ok(Ok(())) => {
            close_handle.normal_close().await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_recording_file_type_to_streaming_type() {
        let asciicast_type =
            streaming_type_for_file_type(RecordingFileType::Asciicast).expect("asciicast should stream in terminal");
        assert!(matches!(
            asciicast_type,
            StreamingType::Terminal(terminal_streamer::InputStreamType::Asciinema)
        ));

        let trp_type = streaming_type_for_file_type(RecordingFileType::TRP).expect("trp should stream in terminal");
        assert!(matches!(
            trp_type,
            StreamingType::Terminal(terminal_streamer::InputStreamType::Trp)
        ));

        let webm_type = streaming_type_for_file_type(RecordingFileType::WebM).expect("webm should stream as video");
        assert!(matches!(webm_type, StreamingType::WebM));
        assert!(streaming_type_for_file_type(RecordingFileType::SessionRecordingLog).is_err());
    }
}
