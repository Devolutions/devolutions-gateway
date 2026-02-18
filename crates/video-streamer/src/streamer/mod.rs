use std::sync::Arc;

use channel_writer::{ChannelWriter, ChannelWriterError, ChannelWriterReceiver};
use ebml_iterable::error::CorruptedFileError;
use futures_util::SinkExt;
use iter::{IteratorError, WebmPositionedIterator};
use protocol::{ProtocolCodeC, UserFriendlyError};
use tag_writers::{EncodeWriterConfig, HeaderWriter, WriterResult};
use tokio::sync::oneshot::error::RecvError;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio_util::codec::Framed;
use tracing::Instrument;
use webm_iterable::WebmIterator;
use webm_iterable::errors::{TagIteratorError, TagWriterError};
use webm_iterable::matroska_spec::{Master, MatroskaSpec};

pub(crate) mod block_tag;
pub(crate) mod channel_writer;
pub(crate) mod iter;
pub(crate) mod protocol;
pub(crate) mod reopenable_file;
pub(crate) mod signal_writer;
pub(crate) mod tag_writers;

use tokio::io::AsyncWriteExt;

use crate::StreamingConfig;
use crate::reopenable::Reopenable;

#[instrument(skip_all)]
pub fn webm_stream(
    output_stream: impl tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static, // A websocket usually
    input_stream: impl std::io::Read + Reopenable,                                             // A file usually
    shutdown_signal: Arc<Notify>,
    config: StreamingConfig,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let mut webm_itr = WebmPositionedIterator::new(WebmIterator::new(
        input_stream,
        &[MatroskaSpec::BlockGroup(Master::Start)],
    ));
    let mut headers = vec![];

    // we extract all the headers before the first cluster
    while let Some(tag) = webm_itr.next() {
        let tag = tag?;
        if matches!(tag, MatroskaSpec::Cluster(Master::Start)) {
            break;
        }

        headers.push(tag);
    }
    let encode_writer_config = EncodeWriterConfig::try_from((headers.as_slice(), &config))?;

    // we run to the last cluster, skipping everything that has been played
    while let Some(tag) = webm_itr.next() {
        if let Err(IteratorError::InnerError(TagIteratorError::UnexpectedEOF { .. })) = tag {
            break;
        }
    }

    let cut_block_position = webm_itr.previous_emitted_tag_postion();

    let ws_frame = Framed::new(output_stream, ProtocolCodeC);

    // ChannelWriter is a writer that writes to a channel
    let (chunk_writer, chunk_receiver) = ChannelWriter::new();
    let (error_sender, error_receiver) = mpsc::channel(1);
    let stop_notifier = Arc::new(Notify::new());
    spawn_sending_task(
        ws_frame,
        chunk_receiver,
        match encode_writer_config.codec {
            cadeau::xmf::vpx::VpxCodec::VP8 => Some("vp8".to_owned()),
            cadeau::xmf::vpx::VpxCodec::VP9 => Some("vp9".to_owned()),
        },
        shutdown_signal,
        error_receiver,
        Arc::clone(&stop_notifier),
    );

    let mut header_writer = HeaderWriter::new(chunk_writer);
    perf_debug!(?headers);
    for header in &headers {
        header_writer.write(header)?;
    }

    let (mut encode_writer, cut_block_hit_marker) = header_writer.into_encoded_writer(encode_writer_config)?;
    let mut cut_block_hit_marker = Some(cut_block_hit_marker);
    // Start muxing from the last key frame.
    // The WebM project requires the muxer to ensure the first Block/SimpleBlock is a keyframe.
    // However, the WebM file emitted by the CaptureStream API in Chrome does not adhere to this requirement.
    match webm_itr.rollback_to_last_key_frame()? {
        iter::LastKeyFrameInfo::NotMet { .. } => {
            anyhow::bail!("no key frame found in the last cluster");
        }
        iter::LastKeyFrameInfo::Met { cluster_timestamp, .. } => {
            encode_writer.write(MatroskaSpec::Timestamp(cluster_timestamp))?;
        }
    }

    // With a 3-second timeout per EOF wait, 25 retries gives a 75-second maximum stall
    // before giving up. The counter resets to 0 on every successful tag read, so this
    // only triggers on continuous EOF with zero progress.
    const MAX_RETRY_COUNT: usize = 25;
    let mut retry_count = 0;

    let result = loop {
        match webm_itr.next() {
            Some(Err(IteratorError::InnerError(TagIteratorError::ReadError { source }))) => {
                return Err(source.into());
            }
            Some(Err(IteratorError::InnerError(TagIteratorError::UnexpectedEOF { .. })))
            // Sometimes the file is not corrupted, it's just that specific tag is still on the fly
            | Some(Err(IteratorError::InnerError(TagIteratorError::CorruptedFileData(
                CorruptedFileError::InvalidTagData { .. },
            ))))
            | None => {
                perf_trace!("End of file reached or invalid tag data hit, retrying");
                if retry_count >= MAX_RETRY_COUNT {
                    anyhow::bail!("reached max retry count, the webm iterator cannot proceed with the current streaming file");
                }

                retry_count += 1;
                match when_eof(&when_new_chunk_appended, Arc::clone(&stop_notifier)) {
                    Ok(WhenEofControlFlow::Continue) => {
                        webm_itr.rollback_to_last_successful_tag()?;
                        webm_itr.skip(1)?;
                    }
                    Ok(WhenEofControlFlow::Break) => {
                        break Ok(());
                    }
                    Err(e) => {
                        error_sender.blocking_send(UserFriendlyError::UnexpectedEOF)?;
                        anyhow::bail!(e);
                    }
                }
            }
            Some(Ok(tag)) => {
                retry_count = 0;
                if webm_itr.previous_emitted_tag_postion() == cut_block_position {
                    if let Some(cut_block_hit_marker) = cut_block_hit_marker.take() {
                        encode_writer.mark_cut_block_hit(cut_block_hit_marker);
                    } else {
                        error_sender.blocking_send(UserFriendlyError::UnexpectedError)?;
                        anyhow::bail!("cut block hit twice");
                    }
                }

                match encode_writer.write(tag) {
                    Ok(WriterResult::Continue) => continue,
                    Err(e) => {
                        let Some(TagWriterError::WriteError { source }) = e.downcast_ref::<TagWriterError>() else {
                            break Err(e);
                        };

                        if source.kind() != std::io::ErrorKind::Other {
                            break Err(e);
                        }
                        let Some(ChannelWriterError::ChannelClosed) =
                            source.get_ref().and_then(|e| e.downcast_ref::<ChannelWriterError>())
                        else {
                            break Err(e);
                        };
                        // Channel is closed, we can break
                        break Ok(());
                    }
                }
            }
            Some(Err(e)) => {
                error_sender.blocking_send(UserFriendlyError::UnexpectedError)?;
                break Err(e.into());
            }
        }
    };

    info!(?result, "WebM streaming finished");

    return result;

    fn when_eof(
        when_new_chunk_appended: &impl Fn() -> tokio::sync::oneshot::Receiver<()>,
        stop_notifier: Arc<Notify>,
    ) -> Result<WhenEofControlFlow, RecvError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let when_new_chunk_appended_receiver = when_new_chunk_appended();
        tokio::spawn(async move {
            tokio::select! {
                _ = when_new_chunk_appended_receiver => {
                    let _ = tx.send(WhenEofControlFlow::Continue);
                },
                _ = stop_notifier.notified() => {
                    let _ = tx.send(WhenEofControlFlow::Break);
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    trace!("EOF wait timed out, retrying");
                    let _ = tx.send(WhenEofControlFlow::Continue);
                }
            }
        });
        rx.blocking_recv()
    }
}

fn spawn_sending_task<W>(
    ws_frame: Framed<W, ProtocolCodeC>,
    mut chunk_receiver: ChannelWriterReceiver,
    codec: Option<String>,
    shutdown_signal: Arc<Notify>,
    mut error_receiver: mpsc::Receiver<UserFriendlyError>,
    stop_notifier: Arc<Notify>,
) where
    W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static,
{
    use futures_util::stream::StreamExt;
    let ws_frame = Arc::new(Mutex::new(ws_frame));
    let ws_frame_clone = Arc::clone(&ws_frame);
    // Spawn a dedicated task to handle incoming messages from the client
    // Reasoning: tokio::select! will stuck on `chunk_receiver.recv()` when there's no more data to receive
    // This will disable the ability to receive shutdown signal
    let handle = tokio::task::spawn(async move {
        loop {
            let client_message = {
                let mut ws_frame = ws_frame.lock().await;
                ws_frame.next().await
            };

            match client_message {
                None => {
                    break;
                }
                Some(Err(e)) => {
                    warn!(error = %e, "Error while receiving message from client");
                    break;
                }
                Some(Ok(protocol::ClientMessage::Start)) => {
                    ws_send(
                        &ws_frame,
                        protocol::ServerMessage::MetaData {
                            codec: codec
                                .as_ref()
                                .and_then(|c| c.as_str().try_into().ok())
                                .unwrap_or(protocol::Codec::Vp8),
                        },
                    )
                    .await;
                }
                Some(Ok(protocol::ClientMessage::Pull)) => match chunk_receiver.recv().await {
                    Some(data) => {
                        ws_send(&ws_frame, protocol::ServerMessage::Chunk(&data)).await;
                    }
                    _ => {
                        break;
                    }
                },
            }
        }
        let _ = ws_frame.lock().await.get_mut().shutdown().await;
        Ok::<_, anyhow::Error>(())
    });

    let control_task = async move {
        info!("Starting streaming task");
        loop {
            tokio::select! {
                err = error_receiver.recv() => {
                    if let Some(err) = err {
                        ws_send(&ws_frame_clone, protocol::ServerMessage::Error(err)).await;
                        break;
                    } else {
                        continue;
                    }
                },
                _ = shutdown_signal.notified() => {
                    info!("Received shutdown signal");
                    ws_send(&ws_frame_clone, protocol::ServerMessage::End).await;
                    break;
                },
            }
        }
        info!("Stopping streaming task");
        let _ = ws_frame_clone.lock().await.get_mut().shutdown().await;
        handle.abort();
        stop_notifier.notify_waiters();
        Ok::<_, anyhow::Error>(())
    }
    .instrument(tracing::span!(tracing::Level::INFO, "Streaming WebM task"));

    tokio::spawn(async move {
        let task_result = control_task.await;
        if let Err(e) = task_result {
            tracing::warn!(error = format!("{e:#}"));
        }
    });

    async fn ws_send<W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static>(
        ws_frame: &Arc<Mutex<Framed<W, ProtocolCodeC>>>,
        message: protocol::ServerMessage<'_>,
    ) {
        let _ = ws_frame.lock().await.send(message).await.inspect_err(|e| {
            warn!(error = %e, "Failed to send message to client");
        });
    }
}

enum WhenEofControlFlow {
    Continue,
    Break,
}
