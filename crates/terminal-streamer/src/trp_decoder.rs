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
    // A single decoded message can be larger than the caller's read buffer (e.g. a full-screen
    // redraw becomes one big cast line). Hold the unread remainder across poll_read calls.
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl AsyncReadChannel {
    fn new(receiver: tokio::sync::mpsc::Receiver<anyhow::Result<String>>) -> Self {
        Self {
            receiver,
            leftover: Vec::new(),
            leftover_pos: 0,
        }
    }
}

impl AsyncRead for AsyncReadChannel {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Drain any leftover from a previous oversized message before pulling a new one.
        if this.leftover_pos < this.leftover.len() {
            let n = std::cmp::min(buf.remaining(), this.leftover.len() - this.leftover_pos);
            buf.put_slice(&this.leftover[this.leftover_pos..this.leftover_pos + n]);
            this.leftover_pos += n;
            if this.leftover_pos >= this.leftover.len() {
                this.leftover.clear();
                this.leftover_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut this.receiver).poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // Only copy what fits; buffer the rest so we never overflow the read buffer.
                let bytes = data.as_bytes();
                let n = std::cmp::min(buf.remaining(), bytes.len());
                buf.put_slice(&bytes[..n]);
                if n < bytes.len() {
                    this.leftover = bytes[n..].to_vec();
                    this.leftover_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
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
                // Terminal size change. Payload is little-endian [columns, rows].
                if event_payload.len() < 4 {
                    anyhow::bail!(
                        "invalid terminal size change payload length (len={})",
                        event_payload.len()
                    );
                }
                header.col = u16::from_le_bytes(event_payload[0..2].try_into()?);
                header.row = u16::from_le_bytes(event_payload[2..4].try_into()?);
                if before_setup_cache.is_none() {
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
