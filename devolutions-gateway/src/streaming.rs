use std::{borrow::Cow, sync::Arc};

use anyhow::Context;
use axum::{
    body::Body,
    extract::ws::{CloseFrame, WebSocket},
    response::Response,
};
use futures::SinkExt;
use terminal_streamer::terminal_stream;
use tokio::{fs::OpenOptions, sync::Notify};
use uuid::Uuid;
use video_streamer::{config::CpuCount, webm_stream, ReOpenableFile};

use crate::{token::RecordingFileType, ws::websocket_compat};

pub(crate) async fn stream_file(
    path: &camino::Utf8Path,
    ws: axum::extract::WebSocketUpgrade,
    shutdown_notify: Arc<Notify>,
    recordings: crate::recording::RecordingMessageSender,
    recording_id: Uuid,
) -> anyhow::Result<Response<Body>> {
    let streaming_type = validate_streaming_file(path, recording_id, &recordings).await?;

    let when_new_chunk_appended = move || {
        let (tx, rx) = tokio::sync::oneshot::channel();
        recordings.add_new_chunk_listener(recording_id, tx);
        rx
    };

    let path = Arc::new(path.to_owned());
    let upgrade_result = match streaming_type {
        StreamingType::Terminal => {
            let shutdown_notify = shutdown_notify.clone();
            ws.on_upgrade(move |socket| async move {
                if let Err(e) = setup_terminal_streaming(&path, socket, shutdown_notify, when_new_chunk_appended).await
                {
                    error!(error = ?e, "Terminal streaming failed");
                }
            })
        }
        StreamingType::WebM => {
            let shutdown_notify = shutdown_notify.clone();
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
        self.0.send(axum::extract::ws::Message::Text(value)).await?;
        Ok(())
    }

    async fn close(&mut self) {
        let _ = self
            .0
            .send(axum::extract::ws::Message::Close(Some(CloseFrame {
                code: 1000,
                reason: Cow::Borrowed("EOF"),
            })))
            .await;
        let _ = self.0.flush().await;
    }
}

enum StreamingType {
    Terminal,
    WebM,
}

async fn validate_streaming_file(
    path: &camino::Utf8Path,
    recording_id: Uuid,
    recordings: &crate::recording::RecordingMessageSender,
) -> anyhow::Result<StreamingType> {
    let path_extension = path
        .extension()
        .context("no extension found in the recording file path")?;

    info!(?path, extension = ?path_extension, "Streaming file");
    if !(path_extension == RecordingFileType::WebM.extension()
        || path_extension == RecordingFileType::Asciicast.extension()
        || path_extension == RecordingFileType::TRP.extension())
    {
        anyhow::bail!("invalid file type");
    }

    if path_extension == RecordingFileType::Asciicast.extension()
        || path_extension == RecordingFileType::TRP.extension()
    {
        Ok(StreamingType::Terminal)
    } else {
        Ok(StreamingType::WebM)
    }
}

async fn setup_terminal_streaming(
    path: &camino::Utf8Path,
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

    let path_extension = path.extension().unwrap();
    let input_type = if path_extension == RecordingFileType::Asciicast.extension() {
        terminal_streamer::InputStreamType::Asciinema
    } else {
        terminal_streamer::InputStreamType::Trp
    };

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
    };

    let websocket_stream = websocket_compat(socket);
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
            error!(error = format!("{e:#}"), "Streaming file failed");
            Err(e)
        }
        Ok(Ok(())) => Ok(()),
    }
}
