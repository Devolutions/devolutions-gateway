use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

#[derive(Debug)]
struct AsciinemaHeader {
    version: u16,
    row: u16,
    col: u16,
}

impl Default for AsciinemaHeader {
    fn default() -> Self {
        Self {
            version: 2,
            row: 24,
            col: 80,
        }
    }
}

#[derive(Debug)]
enum AsciinemaEvent {
    TerminalOutput { payload: String, time: f64 },
    UserInput { payload: String, time: f64 },
    Resize { width: u16, height: u16, time: f64 },
}

impl AsciinemaHeader {
    fn to_json(&self) -> String {
        format!(
            r#"{{"version": {}, "row": {}, "col": {}}}"#,
            self.version, self.row, self.col
        )
    }
}

impl AsciinemaEvent {
    fn to_json(&self) -> String {
        match self {
            AsciinemaEvent::TerminalOutput { payload, time } => {
                let escaped_payload = Self::sanitize_payload(payload);
                format!(r#"[{},"o","{}"]"#, time, escaped_payload)
            }
            AsciinemaEvent::UserInput { payload, time } => {
                let escaped_payload = Self::sanitize_payload(payload);
                format!(r#"[{},"i","{}"]"#, time, escaped_payload)
            }
            AsciinemaEvent::Resize { width, height, time } => {
                format!(r#"[{},"r","{}x{}"]"#, time, width, height)
            }
        }
    }

    fn sanitize_payload(payload: &str) -> String {
        payload
            .chars()
            .map(|c| {
                if c.is_ascii_control() {
                    format!("\\u{:04x}", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect::<String>()
    }
}

pub fn decode_stream(
    mut input_stream: impl AsyncRead + Unpin + Send + 'static,
) -> anyhow::Result<(tokio::task::JoinHandle<()>, impl AsyncRead + Unpin + Send + 'static)> {
    let (mut tx, rx) = tokio::sync::mpsc::channel(10);

    let mut time = 0.0;
    // Store everything until we have a terminal setup
    let mut before_setup_cache = Some(Vec::new());
    let mut header = AsciinemaHeader::default();
    let task = tokio::spawn(async move {
        let final_tx = tx.clone();
        let task = async move {
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
                            warn!("Termianl setup event cache is empty and we got a setup event");
                        }
                    }
                    _ => {}
                }
            }
        };

        info!("TRP decoder task finished");
        set_return_type::<anyhow::Result<()>, _>(&task);
        if let Err(e) = task.await {
            final_tx.send(Err(e)).await.ok();
        }
    });

    return Ok((task, AsyncReadChannel::new(rx)));

    fn set_return_type<T, F: Future<Output = T>>(_arg: &F) {}
    async fn send(
        sender: &mut tokio::sync::mpsc::Sender<anyhow::Result<String>>,
        mut json: String,
    ) -> anyhow::Result<()> {
        json.push('\n');
        sender.send(Ok(json)).await?;
        Ok(())
    }
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
