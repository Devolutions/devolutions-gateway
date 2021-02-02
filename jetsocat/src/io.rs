use anyhow::Result;
use async_tungstenite::tungstenite::{Error as TungsteniteError, Message};
use futures_channel::mpsc;
use slog::{debug, trace};

pub async fn read_and_write<R, W>(mut reader: R, mut writer: W, logger: slog::Logger) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let mut buf = vec![0; 1024];

        let bytes_read = reader.read(&mut buf).await?;
        if bytes_read == 0 {
            break;
        }

        buf.truncate(bytes_read);
        trace!(logger, r#""{}""#, String::from_utf8_lossy(&buf));

        writer.write_all(&buf).await?;
    }
    Ok(())
}

pub async fn read_and_send<R>(mut reader: R, tx: mpsc::UnboundedSender<Message>, logger: slog::Logger) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    loop {
        let mut buf = vec![0; 1024];

        let bytes_read = reader.read(&mut buf).await?;
        if bytes_read == 0 {
            break;
        }

        buf.truncate(bytes_read);
        trace!(logger, r#""{}""#, String::from_utf8_lossy(&buf));
        tx.unbounded_send(Message::binary(buf))?;
    }

    Ok(())
}

pub async fn ws_stream_to_writer<S, W>(mut stream: S, mut writer: W, logger: slog::Logger) -> Result<()>
where
    S: futures_util::stream::Stream<Item = Result<Message, TungsteniteError>> + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;

    while let Some(msg) = stream.next().await {
        let data = msg?.into_data();

        if data.is_empty() {
            debug!(logger, "Empty message");
        } else {
            trace!(logger, r#""{}""#, String::from_utf8_lossy(&data));
        }

        writer.write_all(&data).await?;
    }

    Ok(())
}
