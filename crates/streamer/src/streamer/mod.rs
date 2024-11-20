use channel_writer::ChannelWriter;
use futures_util::SinkExt;
use protocol::ProtocolCodeC;
use tag_writers::{EncodeWriterConfig, EncodedWriteResult, HeaderWriter};
use tokio_util::codec::Framed;
use tracing::{info, warn, Instrument};
use webm_iterable::{
    errors::TagIteratorError,
    matroska_spec::{Master, MatroskaSpec},
};

pub mod block_tag;
pub mod channel_writer;
pub mod protocol;
pub mod reopenable_file;
pub mod signal_when_flush;
pub mod tag_writers;

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
    let mut webm_itr = webm_iterable::WebmIterator::new(input_stream, &[]);
    let mut headers = vec![];
    let mut first_cluster_position = None;

    // we extract all the headers before the first cluster
    while let Some(tag) = webm_itr.next() {
        let tag = tag?;
        if matches!(tag, MatroskaSpec::Cluster(Master::Start)) {
            first_cluster_position = Some(webm_itr.last_emitted_tag_offset());
            break;
        }

        headers.push(tag);
    }

    let Some(mut last_cluster_postion) = first_cluster_position else {
        // Think Twice, is this senario possible?
        return Err(anyhow::anyhow!("No cluster found"));
    };

    warn!(last_cluster_postion, "First cluster position");

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

        if matches!(tag, MatroskaSpec::Cluster(Master::End)) {
            last_cluster_postion = webm_itr.last_emitted_tag_offset();
        }
    }

    warn!(last_cluster_postion, "Last cluster position");

    let framed = Framed::new(output_stream, ProtocolCodeC);

    // ChannelWriter is a writer that writes to a channel
    let (writer, receiver) = ChannelWriter::new();

    spawn_sending_task(framed, receiver, codec, shutdown_signal);

    // ControlledTagWriter will not write to underlying writer unless the data is valid
    let mut header_writer = HeaderWriter::new(writer);
    warn!(?headers, "Headers sent");
    for header in &headers {
        header_writer.write(header)?;
    }

    // We startint muxing the last cluster
    reseek(&mut webm_itr, last_cluster_postion)?;
    let encode_writer_config = EncodeWriterConfig::try_from(headers.as_slice())?;
    let mut encode_writer = header_writer.into_encoded_writer(encode_writer_config)?;

    let mut last_tag_position = last_cluster_postion;
    loop {
        match next_tag(&mut webm_itr, &mut last_tag_position)? {
            NextTagResult::Tag(matroska_spec) => {
                if let EncodedWriteResult::Finished = encode_writer.write(matroska_spec)? {
                    break;
                }
            }
            NextTagResult::TryAgain => {
                reseek(&mut webm_itr, last_cluster_postion)?;
                when_new_chunk_appended().blocking_recv()?;
            }
            NextTagResult::End => {
                anyhow::bail!("Unexpected end of file");
            }
        };
    }

    let mut timed_writer = encode_writer.into_timed_tag_writer();

    loop {
        match next_tag(&mut webm_itr, &mut last_tag_position)? {
            NextTagResult::Tag(matroska_spec) => {
                timed_writer.write(matroska_spec)?;
            }
            NextTagResult::TryAgain => {
                reseek(&mut webm_itr, last_cluster_postion)?;
                when_new_chunk_appended().blocking_recv()?;
            }
            NextTagResult::End => {
                break;
            }
        };
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

fn reseek(
    webm_itr: &mut webm_iterable::WebmIterator<impl std::io::Read + Reopenable>,
    last_cluster_postion: usize,
) -> anyhow::Result<()> {
    webm_itr.get_mut().reopen()?;
    webm_itr
        .get_mut()
        .seek(std::io::SeekFrom::Start(last_cluster_postion as u64))?;
    Ok(())
}

enum NextTagResult {
    Tag(MatroskaSpec),
    TryAgain,
    End,
}

fn next_tag(
    webm_itr: &mut webm_iterable::WebmIterator<impl std::io::Read + Reopenable>,
    last_cluster_postion: &mut usize,
) -> anyhow::Result<NextTagResult> {
    let Some(tag) = webm_itr.next() else {
        return Ok(NextTagResult::End);
    };

    let tag = match tag {
        Ok(tag) => tag,
        Err(TagIteratorError::ReadError { .. }) => anyhow::bail!("Read error"),
        Err(_) => {
            return Ok(NextTagResult::TryAgain);
        }
    };

    *last_cluster_postion += webm_itr.last_emitted_tag_offset();
    Ok(NextTagResult::Tag(tag))
}
