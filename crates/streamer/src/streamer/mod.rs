use channel_writer::ChannelWriter;
use futures_util::SinkExt;
use protocol::ProtocolCodeC;
use tag_writers::{EncodeWriterConfig, EncodedWriteResult, HeaderWriter};
use tokio_util::codec::Framed;
use tracing::{debug, info, trace, warn, Instrument};
use webm::WebmPostionedIterator;
use webm_iterable::{
    errors::TagIteratorError,
    matroska_spec::{Master, MatroskaSpec},
    WebmIterator,
};

pub mod block_tag;
pub mod channel_writer;
pub mod protocol;
pub mod reopenable_file;
pub mod signal_when_flush;
pub mod tag_writers;
pub mod webm;

use crate::reopenable::Reopenable;

pub trait Signal: Send + 'static {
    fn wait(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

pub fn webm_stream(
    output_stream: impl tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static, // A websocket usually
    input_stream: impl std::io::Read + Reopenable,                                             // A file usually
    shutdown_signal: impl Signal,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    warn!("Starting webm_stream");
    let mut webm_itr = WebmPostionedIterator::new(WebmIterator::new(input_stream, &[]));
    let mut headers = vec![];

    // we extract all the headers before the first cluster
    while let Some(tag) = webm_itr.next() {
        let tag = tag?;
        if matches!(tag, MatroskaSpec::Cluster(Master::Start)) {
            break;
        }

        headers.push(tag);
    }

    let mut codec: Option<String> = None;
    // we run to the last cluster, skipping everything that has been played
    while let Some(tag) = webm_itr.next() {
        if let Err(TagIteratorError::UnexpectedEOF { .. }) = tag {
            break;
        }

        let tag = tag?;

        if let MatroskaSpec::CodecID(codec_string) = &tag {
            codec = Some(codec_string.to_owned());
        }
    }

    let framed = Framed::new(output_stream, ProtocolCodeC);

    // ChannelWriter is a writer that writes to a channel
    let (writer, receiver) = ChannelWriter::new();

    spawn_sending_task(framed, receiver, codec, shutdown_signal);

    // ControlledTagWriter will not write to underlying writer unless the data is valid
    let mut header_writer = HeaderWriter::new(writer);
    info!(?headers, "Headers sent");
    for header in &headers {
        header_writer.write(header)?;
    }

    // We startint muxing the last cluster
    webm_itr.rollback_to_last_cluster_start()?;
    let encode_writer_config = EncodeWriterConfig::try_from(headers.as_slice())?;
    let mut encode_writer = header_writer.into_encoded_writer(encode_writer_config)?;

    loop {
        match webm_itr.next() {
            Some(Err(TagIteratorError::ReadError { source })) => {
                // if source.kind() == std::io::ErrorKind::UnexpectedEof {
                //     when_new_chunk_appended().blocking_recv()?;
                //     webm_itr.rollback_to_last_successful_tag()?;
                //     webm_itr.skip(1)?;
                // } else {
                    return Err(source.into());
                // }
            }
            None | Some(Err(_)) => {
                when_new_chunk_appended().blocking_recv()?;
                webm_itr.rollback_to_last_successful_tag()?;
                webm_itr.skip(1)?;
            }
            Some(Ok(tag)) => {
                if let EncodedWriteResult::Finished = encode_writer.write(tag)? {
                    break;
                }
            }
        }
    }

    let mut timed_writer = encode_writer.into_timed_tag_writer();
    debug!("Start timed writing");

    loop {
        match webm_itr.next() {
            Some(Err(TagIteratorError::ReadError { source })) => {
                // if source.kind() == std::io::ErrorKind::UnexpectedEof {
                //     when_new_chunk_appended().blocking_recv()?;
                //     webm_itr.rollback_to_last_successful_tag()?;
                //     webm_itr.skip(1)?;
                // } else {
                    return Err(source.into());
                // }
            }
            None | Some(Err(_)) => {
                when_new_chunk_appended().blocking_recv()?;
                webm_itr.rollback_to_last_successful_tag()?;
                webm_itr.skip(1)?;
            }
            Some(Ok(tag)) => {
                timed_writer.write(tag)?;
            }
        }
    }

    Ok(())
}

fn spawn_sending_task<W>(
    mut ws_frame: Framed<W, ProtocolCodeC>,
    mut chunk_receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    codec: Option<String>,
    mut shutdown_signal: impl Signal,
) where
    W: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static,
{
    use futures_util::stream::StreamExt;
    let task = async move {
        info!("Starting streaming task");

        loop {
            tokio::select! {
                _ = shutdown_signal.wait() => {
                    break;
                },
                client_message = ws_frame.next() => {
                    match client_message {
                        None => {
                            break;
                        },
                        Some(Err(e)) => {
                            warn!("Error while receiving data: {:?}", e);
                            break;
                        },
                        Some(Ok(protocol::ClientMessage::Start)) => {
                            info!("Start message received");
                            ws_frame.send(protocol::ServerMessage::MetaData {
                                codec: codec.as_ref().and_then(|c| c.as_str().try_into().ok()).unwrap_or(protocol::Codec::Vp8)
                            }).await?;
                        },
                        Some(Ok(protocol::ClientMessage::Pull)) => {
                            info!("Pull message received");
                            match chunk_receiver.recv().await {
                                Some(data) => {
                                  ws_frame.send(protocol::ServerMessage::Chunk(&data)).await?;
                                },
                                None => {
                                    break ;
                                },
                            }
                        }
                    }
                }
            }
        }

        Ok::<_, anyhow::Error>(())
    }
    .instrument(tracing::span!(tracing::Level::INFO, "Streaming WebM task"));

    tokio::spawn(async move {
        let task_result = task.await;

        if let Err(e) = task_result {
            tracing::error!("Error while sending data: {:?}", e);
        }
    });
}

fn reseek<R: std::io::Read + Reopenable>(
    webm_itr: WebmIterator<R>,
    last_cluster_postion: usize,
) -> anyhow::Result<WebmIterator<R>> {
    let mut inner = webm_itr.into_inner();
    inner.reopen()?;
    inner.seek(std::io::SeekFrom::Start(last_cluster_postion as u64))?;
    Ok(WebmIterator::new(inner, &[MatroskaSpec::BlockGroup(Master::Start)]))
}

enum NextTagResult {
    Tag(MatroskaSpec),
    TryAgain,
    End,
}

fn next_tag(webm_itr: &mut WebmIterator<impl std::io::Read + Reopenable>) -> anyhow::Result<NextTagResult> {
    let Some(tag) = webm_itr.next() else {
        return Ok(NextTagResult::TryAgain);
    };

    let tag = match tag {
        Ok(tag) => tag,
        Err(TagIteratorError::ReadError { source }) => match source.kind() {
            std::io::ErrorKind::UnexpectedEof => {
                return Ok(NextTagResult::End);
            }
            _ => {
                return Err(source.into());
            }
        },
        Err(_) => {
            return Ok(NextTagResult::TryAgain);
        }
    };
    Ok(NextTagResult::Tag(tag))
}
