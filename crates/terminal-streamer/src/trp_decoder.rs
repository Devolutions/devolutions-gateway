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

/// Terminal output written at `time`, in seconds since the start of the recording.
#[derive(Debug, Clone, PartialEq)]
pub struct TerminalOutput {
    pub time: f64,
    pub text: String,
}

/// Reads the terminal output of a finished TRP recording one packet at a time.
///
/// A truncated last packet, as left by an interrupted recording, ends the output.
pub struct TrpOutputReader<R> {
    reader: R,
    time: f64,
}

impl<R: std::io::Read> TrpOutputReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader, time: 0.0 }
    }

    fn read_packet(&mut self) -> std::io::Result<Option<(u16, Vec<u8>)>> {
        let mut header = [0u8; 8];

        if let Err(error) = self.reader.read_exact(&mut header) {
            return eof_as_end(error);
        }

        let time_delta = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let event_type = u16::from_le_bytes([header[4], header[5]]);
        let size = u16::from_le_bytes([header[6], header[7]]);

        let mut payload = vec![0u8; usize::from(size)];

        if let Err(error) = self.reader.read_exact(&mut payload) {
            return eof_as_end(error);
        }

        self.time += f64::from(time_delta) / 1000.0;

        Ok(Some((event_type, payload)))
    }
}

fn eof_as_end<T>(error: std::io::Error) -> std::io::Result<Option<T>> {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        Ok(None)
    } else {
        Err(error)
    }
}

impl<R: std::io::Read> Iterator for TrpOutputReader<R> {
    type Item = std::io::Result<TerminalOutput>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read_packet() {
                Ok(Some((0, payload))) => {
                    return Some(Ok(TerminalOutput {
                        time: self.time,
                        text: String::from_utf8_lossy(&payload).into_owned(),
                    }));
                }
                Ok(Some(_)) => {}
                Ok(None) => return None,
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(time_delta: u32, event_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&time_delta.to_le_bytes());
        packet.extend_from_slice(&event_type.to_le_bytes());
        packet.extend_from_slice(&u16::try_from(payload.len()).expect("small payload").to_le_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn reads_the_timed_output_and_ignores_a_truncated_tail() {
        let mut trp = Vec::new();
        trp.extend(packet(0, 2, &[100, 0, 30, 0]));
        trp.extend(packet(500, 0, b"$ "));
        trp.extend(packet(0, 4, &[]));
        trp.extend(packet(1000, 1, b"l"));
        trp.extend(packet(250, 0, b"ls\r\n"));
        trp.extend(&packet(10, 0, b"lost")[..9]);

        let output = TrpOutputReader::new(trp.as_slice())
            .collect::<std::io::Result<Vec<_>>>()
            .expect("valid recording");

        assert_eq!(
            output,
            [
                TerminalOutput {
                    time: 0.5,
                    text: "$ ".to_owned()
                },
                TerminalOutput {
                    time: 1.75,
                    text: "ls\r\n".to_owned()
                },
            ]
        );
    }

    #[test]
    fn reads_one_packet_at_a_time() {
        struct CountingReader<'a> {
            data: &'a [u8],
            read: std::rc::Rc<std::cell::Cell<usize>>,
        }

        impl std::io::Read for CountingReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = std::io::Read::read(&mut self.data, buf)?;
                self.read.set(self.read.get() + n);
                Ok(n)
            }
        }

        let trp = (0..1000).flat_map(|_| packet(1, 0, b"x")).collect::<Vec<_>>();
        let read = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut reader = TrpOutputReader::new(CountingReader {
            data: &trp,
            read: std::rc::Rc::clone(&read),
        });

        reader.next().expect("one packet").expect("valid packet");

        assert_eq!(read.get(), 9);
    }
}
