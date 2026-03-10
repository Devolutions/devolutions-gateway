use std::sync::Arc;

use channel_writer::{ChannelWriter, ChannelWriterError, ChannelWriterReceiver};
use ebml_iterable::error::CorruptedFileError;
use futures_util::SinkExt;
use iter::{IteratorError, WebmPositionedIterator};
use protocol::{ProtocolCodeC, UserFriendlyError};
use tag_writers::{EncodeWriterConfig, HeaderWriter, WriterResult};
use tokio::sync::{Mutex, Notify, watch};
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
    let mut raw_itr = WebmIterator::new(input_stream, &[MatroskaSpec::BlockGroup(Master::Start)]);
    let mut headers = vec![];

    // we extract all the headers before the first cluster
    for tag in raw_itr.by_ref() {
        let tag = tag?;
        if matches!(tag, MatroskaSpec::Cluster(Master::Start)) {
            break;
        }

        headers.push(tag);
    }
    let encode_writer_config = EncodeWriterConfig::try_from((headers.as_slice(), &config))?;
    let cluster_start_position = raw_itr.last_emitted_tag_offset();
    let mut webm_itr = WebmPositionedIterator::new(raw_itr, encode_writer_config.codec, cluster_start_position);

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
    let (shutdown_tx, shutdown_rx) = watch::channel(StreamShutdown::Running);

    // Bridge the external shutdown signal into the watch channel (single source of truth).
    // Wrapped in AbortOnDrop so that early returns/bails from webm_stream always abort the
    // bridge task, dropping its shutdown_tx clone and allowing control_task to resolve.
    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _bridge_guard = AbortOnDrop({
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal.notified().await;
            let _ = shutdown_tx.send(StreamShutdown::ExternalShutdown);
        })
    });

    spawn_sending_task(
        ws_frame,
        chunk_receiver,
        match encode_writer_config.codec {
            cadeau::xmf::vpx::VpxCodec::VP8 => Some("vp8".to_owned()),
            cadeau::xmf::vpx::VpxCodec::VP9 => Some("vp9".to_owned()),
        },
        shutdown_tx.clone(),
        shutdown_rx.clone(),
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

    // NOTE: MAX_RETRY_COUNT is intentionally set to 25. With the 3-second delay
    // between retries, this yields a worst-case wait of 75 seconds before we
    // give up on the current stream. This is acceptable in our live-streaming
    // context because downstream components already enforce a stricter overall
    // timeout, and tolerating longer temporary input stalls here reduces
    // unnecessary reconnect churn on brief network or encoder hiccups.
    // The counter resets to 0 on every successful tag read, so this only
    // triggers on continuous EOF with zero progress.
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
                // INVARIANT: `shutdown_rx` must NEVER be consumed (.changed()/.borrow_and_update())
                // in this scope. Clones inherit the "last seen" version from the source, so keeping
                // the source unconsumed guarantees every clone will detect any pending shutdown.
                match when_eof(&when_new_chunk_appended, shutdown_rx.clone()) {
                    WhenEofControlFlow::Continue => {
                        webm_itr.rollback_to_last_successful_tag()?;
                        webm_itr.skip(1)?;
                    }
                    WhenEofControlFlow::Break => {
                        break Ok(());
                    }
                }
            }
            Some(Ok(tag)) => {
                retry_count = 0;
                if webm_itr.previous_emitted_tag_postion() == cut_block_position {
                    if let Some(cut_block_hit_marker) = cut_block_hit_marker.take() {
                        encode_writer.mark_cut_block_hit(cut_block_hit_marker);
                    } else {
                        let _ = shutdown_tx.send(StreamShutdown::Error(UserFriendlyError::UnexpectedError));
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
                let _ = shutdown_tx.send(StreamShutdown::Error(UserFriendlyError::UnexpectedError));
                break Err(e.into());
            }
        }
    };

    info!(?result, "WebM streaming finished");

    // _bridge_guard (AbortOnDrop) is dropped here, aborting the bridge task so its
    // shutdown_tx clone is dropped. This ensures control_task's shutdown_rx.changed()
    // will resolve (Err) instead of hanging forever when webm_stream exits without
    // an explicit shutdown signal.
    return result;

    fn when_eof(
        when_new_chunk_appended: &impl Fn() -> tokio::sync::oneshot::Receiver<()>,
        mut shutdown_rx: watch::Receiver<StreamShutdown>,
    ) -> WhenEofControlFlow {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let when_new_chunk_appended_receiver = when_new_chunk_appended();
        tokio::spawn(async move {
            tokio::select! {
                _ = when_new_chunk_appended_receiver => {
                    let _ = tx.send(WhenEofControlFlow::Continue);
                },
                _ = shutdown_rx.changed() => {
                    let _ = tx.send(WhenEofControlFlow::Break);
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    trace!("EOF wait timed out, retrying");
                    let _ = tx.send(WhenEofControlFlow::Continue);
                }
            }
        });
        // If the oneshot sender is dropped (task panicked), treat as Break
        rx.blocking_recv().unwrap_or(WhenEofControlFlow::Break)
    }

    enum WhenEofControlFlow {
        Continue,
        Break,
    }
}

fn spawn_sending_task<W>(
    ws_frame: Framed<W, ProtocolCodeC>,
    mut chunk_receiver: ChannelWriterReceiver,
    codec: Option<String>,
    shutdown_tx: watch::Sender<StreamShutdown>,
    mut shutdown_rx: watch::Receiver<StreamShutdown>,
) where
    W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static,
{
    use futures_util::stream::StreamExt;
    let ws_frame = Arc::new(Mutex::new(ws_frame));
    let ws_frame_clone = Arc::clone(&ws_frame);
    let mut handle_shutdown_rx = shutdown_rx.clone();

    // Spawn a dedicated task to handle incoming messages from the client
    // Reasoning: tokio::select! will stuck on `chunk_receiver.recv()` when there's no more data to receive
    // This will disable the ability to receive shutdown signal
    let handle = tokio::task::spawn(async move {
        loop {
            // Select on both the next client message and shutdown, so we don't
            // get stuck waiting for a silent client when shutdown is requested.
            let client_message = tokio::select! {
                msg = async {
                    let mut ws_frame = ws_frame.lock().await;
                    ws_frame.next().await
                } => msg,
                _ = handle_shutdown_rx.changed() => {
                    break;
                }
            };

            match client_message {
                None => {
                    let _ = shutdown_tx.send(StreamShutdown::ClientDisconnected);
                    break;
                }
                Some(Err(e)) => {
                    warn!(error = %e, "Error while receiving message from client");
                    let _ = shutdown_tx.send(StreamShutdown::ClientDisconnected);
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
                Some(Ok(protocol::ClientMessage::Pull)) => {
                    tokio::select! {
                        chunk = chunk_receiver.recv() => {
                            match chunk {
                                Some(data) => {
                                    ws_send(&ws_frame, protocol::ServerMessage::Chunk(&data)).await;
                                }
                                None => {
                                    // Channel closed, producer is done
                                    break;
                                }
                            }
                        }
                        _ = handle_shutdown_rx.changed() => {
                            break;
                        }
                    }
                }
            }
        }
        // Best-effort: deliver a final message to client before closing the socket.
        // Read the shutdown reason to decide whether to send End or Error.
        let shutdown_reason = handle_shutdown_rx.borrow().clone();
        match shutdown_reason {
            StreamShutdown::Error(err) => {
                ws_send(&ws_frame, protocol::ServerMessage::Error(err)).await;
            }
            _ => {
                ws_send(&ws_frame, protocol::ServerMessage::End).await;
            }
        }
        let _ = ws_frame.lock().await.get_mut().shutdown().await;
        Ok::<_, anyhow::Error>(())
    });

    let control_task = async move {
        info!("Starting streaming task");
        let result = shutdown_rx.changed().await;
        if result.is_ok() {
            let reason = shutdown_rx.borrow().clone();
            match reason {
                StreamShutdown::Error(err) => {
                    ws_send(&ws_frame_clone, protocol::ServerMessage::Error(err)).await;
                }
                StreamShutdown::ExternalShutdown => {
                    info!("Received shutdown signal");
                    ws_send(&ws_frame_clone, protocol::ServerMessage::End).await;
                }
                StreamShutdown::ClientDisconnected => {
                    ws_send(&ws_frame_clone, protocol::ServerMessage::End).await;
                }
                StreamShutdown::Running => {
                    // Spurious wake, shouldn't happen since we only send non-Running values
                    warn!("Received shutdown signal with Running state, ignoring");
                }
            }
        }
        // If result is Err, the sender was dropped — stream is done
        info!("Stopping streaming task");
        let _ = ws_frame_clone.lock().await.get_mut().shutdown().await;
        // Wait briefly for handle to finish gracefully instead of aborting
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
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

#[derive(Clone, Debug, PartialEq)]
enum StreamShutdown {
    Running,
    ClientDisconnected,
    ExternalShutdown,
    Error(UserFriendlyError),
}
