use std::sync::Arc;

use channel_writer::{ChannelWriter, ChannelWriterError};
use futures_util::SinkExt;
use iter::{IteratorError, WebmPositionedIterator};
use protocol::{ProtocolCodeC, UserFriendlyError};
use tag_writers::{EncodeWriterConfig, HeaderWriter, WriterResult};
use tokio::sync::{mpsc, Mutex};
use tokio_util::codec::Framed;
use tracing::{debug, info, instrument, trace, warn, Instrument};
use webm_iterable::{
    errors::{TagIteratorError, TagWriterError},
    matroska_spec::{Master, MatroskaSpec},
    WebmIterator,
};

pub(crate) mod block_tag;
pub(crate) mod channel_writer;
pub(crate) mod iter;
pub(crate) mod protocol;
pub(crate) mod reopenable_file;
pub(crate) mod signal_writer;
pub(crate) mod tag_writers;

use crate::{debug::mastroka_spec_name, reopenable::Reopenable, StreamingConfig};

pub trait Signal: Send + 'static {
    fn wait(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

#[derive(Debug)]
pub enum RecordingEvent {
    Disconnected { sender: tokio::sync::oneshot::Sender<()> },
}

#[instrument(skip_all)]
pub fn webm_stream(
    output_stream: impl tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static, // A websocket usually
    input_stream: impl std::io::Read + Reopenable,                                             // A file usually
    shutdown_signal: impl Signal,
    config: StreamingConfig,
    recording_event_receiver: mpsc::Receiver<RecordingEvent>,
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

    let cut_block_position = webm_itr.last_tag_position();

    let ws_frame = Framed::new(output_stream, ProtocolCodeC);

    // ChannelWriter is a writer that writes to a channel
    let (chunk_writer, chunk_receiver) = ChannelWriter::new();
    let (error_sender, error_receiver) = mpsc::channel(1);
    let (file_droped_sender, file_droped_receiver) = tokio::sync::oneshot::channel();
    spawn_sending_task(
        ws_frame,
        chunk_receiver,
        match encode_writer_config.codec {
            cadeau::xmf::vpx::VpxCodec::VP8 => Some("vp8".to_owned()),
            cadeau::xmf::vpx::VpxCodec::VP9 => Some("vp9".to_owned()),
        },
        shutdown_signal,
        error_receiver,
        recording_event_receiver,
        file_droped_receiver,
    );

    let mut header_writer = HeaderWriter::new(chunk_writer);
    debug!(?headers);
    for header in &headers {
        header_writer.write(header)?;
    }

    let mut encode_writer = header_writer.into_encoded_writer(encode_writer_config)?;

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

    let result = loop {
        match webm_itr.next() {
            Some(Err(IteratorError::InnerError(TagIteratorError::ReadError { source }))) => {
                return Err(source.into());
            }
            Some(Err(IteratorError::InnerError(TagIteratorError::UnexpectedEOF {
                tag_start,
                tag_id,
                tag_size,
                ..
            }))) => {
                trace!(tag_start, tag_id, tag_size, "End of file reached, retrying");
                when_new_chunk_appended().blocking_recv()?;
                webm_itr.rollback_to_last_successful_tag()?;
                webm_itr.skip(1)?;
            }
            Some(Ok(tag)) => {
                if webm_itr.last_tag_position() == cut_block_position {
                    encode_writer.mark_cut_block_hit();
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
                        info!("Stopping streaming task");
                        // Channel is closed, we can break
                        break Ok(());
                    }
                }
            }
            None => {
                error_sender.blocking_send(UserFriendlyError::UnexpectedEOF)?;
                anyhow::bail!("unexpected None");
            }
            Some(Err(e)) => {
                error_sender.blocking_send(UserFriendlyError::UnexpectedError)?;
                break Err(e.into());
            }
        }
    };
    drop(webm_itr);

    let _ = file_droped_sender.send(());

    result
}

fn spawn_sending_task<W>(
    ws_frame: Framed<W, ProtocolCodeC>,
    mut chunk_receiver: mpsc::Receiver<Vec<u8>>,
    codec: Option<String>,
    mut shutdown_signal: impl Signal,
    mut error_receiver: mpsc::Receiver<UserFriendlyError>,
    mut recording_event_receiver: mpsc::Receiver<RecordingEvent>,
    file_droped_receiver: tokio::sync::oneshot::Receiver<()>,
) where
    W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static,
{
    use futures_util::stream::StreamExt;

    let ws_frame = Arc::new(Mutex::new(ws_frame));
    let ws_frame_clone = ws_frame.clone();
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
                    warn!(?e, "error while receiving message from client");
                    break;
                }
                Some(Ok(protocol::ClientMessage::Start)) => {
                    let _ = ws_frame
                        .lock()
                        .await
                        .send(protocol::ServerMessage::MetaData {
                            codec: codec
                                .as_ref()
                                .and_then(|c| c.as_str().try_into().ok())
                                .unwrap_or(protocol::Codec::Vp8),
                        })
                        .await?;
                }
                Some(Ok(protocol::ClientMessage::Pull)) => match chunk_receiver.recv().await {
                    Some(data) => {
                        ws_frame
                            .lock()
                            .await
                            .send(protocol::ServerMessage::Chunk(&data))
                            .await?;
                    }
                    None => {
                        break;
                    }
                },
            }
        }

        Ok::<_, anyhow::Error>(())
    });

    let task = async move {
        info!("Starting streaming task");
        loop {
            tokio::select! {
                err = error_receiver.recv() => {
                    if let Some(err) = err {
                        let _ = ws_frame_clone.lock().await.send(protocol::ServerMessage::Error(err)).await.inspect_err(|e| {
                            warn!(?e, "failed to send error message");
                        });
                        break;
                    } else {
                        continue;
                    }
                },
                event = recording_event_receiver.recv() => {
                     match event {
                        Some(RecordingEvent::Disconnected {
                            sender,
                        }) => {
                            let _ = ws_frame_clone.lock().await.send(protocol::ServerMessage::End).await.inspect_err(|e| {
                                warn!(?e, "failed to send end message");
                            });

                            tokio::spawn(async move {
                                let _ = file_droped_receiver.await;
                                let _ = sender.send(()).inspect_err(|e| {
                                    warn!(?e, "failed to send recording event");
                                });
                            });

                            break;
                        },
                        None => {
                            break;
                        }
                    }
                },
                _ = shutdown_signal.wait() => {
                    break;
                },
            }
        }

        handle.abort();
        Ok::<_, anyhow::Error>(())
    }
    .instrument(tracing::span!(tracing::Level::INFO, "Streaming WebM task"));

    tokio::spawn(async move {
        let task_result = task.await;

        if let Err(e) = task_result {
            tracing::warn!(error=?e);
        }
    });
}
