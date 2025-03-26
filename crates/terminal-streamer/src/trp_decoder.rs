use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use crate::asciinema::{AsciinemaEvent, AsciinemaHeader};

pub fn decode_stream(
    input_stream: impl AsyncRead + Unpin + Send + 'static,
) -> anyhow::Result<(tokio::task::JoinHandle<()>, impl AsyncRead + Unpin + Send + 'static)> {
    let (tx, rx) = tokio::sync::mpsc::channel(10);

    let task = tokio::spawn(async move {
        let final_tx = tx.clone();
        if let Err(e) = parse_trp_stream(input_stream, tx).await {
            final_tx.send(Err(e)).await.ok();
        }
        info!("TRP decoder task finished");
    });

    Ok((task, AsyncReadChannel::new(rx)))
}

struct AsyncReadChannel {
    receiver: tokio::sync::mpsc::Receiver<anyhow::Result<String>>,
}

impl AsyncReadChannel {
    fn new(receiver: tokio::sync::mpsc::Receiver<anyhow::Result<String>>) -> Self {
        Self { receiver }
    }
}

impl AsyncRead for AsyncReadChannel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let res = Pin::new(&mut self.receiver).poll_recv(cx);
        match res {
            Poll::Ready(Some(Ok(data))) => {
                buf.put_slice(data.as_bytes());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
            Poll::Ready(None) => {
                // Channel is closed - only then we signal EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                // No data available yet, but channel is still open
                Poll::Pending
            }
        }
    }
}

async fn parse_trp_stream(
    mut input_stream: impl AsyncRead + Unpin + Send + 'static,
    mut tx: tokio::sync::mpsc::Sender<anyhow::Result<String>>,
) -> anyhow::Result<()> {
    let mut time = 0.0;
    let mut before_setup_cache = Some(Vec::new());
    let mut header = AsciinemaHeader::default();

    loop {
        let mut packet_head_buffer = [0u8; 8];
        if let Err(e) = input_stream.read_exact(&mut packet_head_buffer).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
            anyhow::bail!(e);
        }

        let time_delta = u32::from_le_bytes(packet_head_buffer[0..4].try_into()?);
        let event_type = u16::from_le_bytes(packet_head_buffer[4..6].try_into()?);
        let size = u16::from_le_bytes(packet_head_buffer[6..8].try_into()?);

        time += f64::from(time_delta) / 1000.0;

        let mut event_payload = vec![0u8; size as usize];
        if let Err(e) = input_stream.read_exact(&mut event_payload).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
            anyhow::bail!(e);
        }

        match event_type {
            0 => {
                // Terminal output
                let event_payload = String::from_utf8_lossy(&event_payload).into_owned();
                let event = AsciinemaEvent::TerminalOutput {
                    payload: event_payload,
                    time,
                };
                match before_setup_cache {
                    Some(ref mut cache) => {
                        cache.push(event);
                    }
                    None => {
                        send(&mut tx, event.to_json()).await?;
                    }
                }
            }
            1 => {
                let event_payload = String::from_utf8_lossy(&event_payload).into_owned();
                let event = AsciinemaEvent::UserInput {
                    payload: event_payload,
                    time,
                };
                match before_setup_cache {
                    Some(ref mut cache) => {
                        cache.push(event);
                    }
                    None => {
                        send(&mut tx, event.to_json()).await?;
                    }
                }
            }
            2 => {
                // Terminal size change
                if before_setup_cache.is_some() {
                    header.row = u16::from_le_bytes(event_payload[0..2].try_into()?);
                    header.col = u16::from_le_bytes(event_payload[2..4].try_into()?);
                } else {
                    let event = AsciinemaEvent::Resize {
                        width: header.col,
                        height: header.row,
                        time,
                    };
                    send(&mut tx, event.to_json()).await?;
                }
            }
            4 => {
                // Terminal setup
                if before_setup_cache.is_some() {
                    let header_json = header.to_json();
                    send(&mut tx, header_json).await?;
                    if let Some(ref mut cache) = before_setup_cache {
                        for event in cache.drain(..) {
                            send(&mut tx, event.to_json()).await?;
                        }
                    }
                    before_setup_cache = None;
                } else {
                    warn!("Received terminal setup event but cache is empty");
                }
            }
            _ => {}
        }
    }
}

async fn send(sender: &mut tokio::sync::mpsc::Sender<anyhow::Result<String>>, mut json: String) -> anyhow::Result<()> {
    json.push('\n');
    sender.send(Ok(json)).await?;
    Ok(())
}
