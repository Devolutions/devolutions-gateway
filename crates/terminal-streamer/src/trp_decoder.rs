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

/// Decodes a complete TRP recording into asciicast v2 lines, each ending with a newline.
///
/// A truncated last packet, as left by an interrupted recording, is ignored.
pub fn decode_to_asciicast(mut input: &[u8]) -> anyhow::Result<String> {
    let mut decoder = TrpDecoder::default();
    let mut output = String::new();

    while input.len() >= PACKET_HEADER_SIZE {
        let (header, rest) = input.split_at(PACKET_HEADER_SIZE);
        let header = PacketHeader::parse(header.try_into()?);

        let Some((payload, rest)) = rest.split_at_checked(usize::from(header.size)) else {
            break;
        };
        input = rest;

        for line in decoder.push(&header, payload)? {
            output.push_str(&line);
            output.push('\n');
        }
    }

    for line in decoder.finish() {
        output.push_str(&line);
        output.push('\n');
    }

    Ok(output)
}

const PACKET_HEADER_SIZE: usize = 8;

struct PacketHeader {
    time_delta: u32,
    event_type: u16,
    size: u16,
}

impl PacketHeader {
    fn parse(buffer: &[u8; PACKET_HEADER_SIZE]) -> Self {
        Self {
            time_delta: u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
            event_type: u16::from_le_bytes([buffer[4], buffer[5]]),
            size: u16::from_le_bytes([buffer[6], buffer[7]]),
        }
    }
}

/// Turns TRP packets into asciicast lines, holding the events that come before the terminal setup.
struct TrpDecoder {
    time: f64,
    before_setup_cache: Option<Vec<AsciinemaEvent>>,
    header: AsciinemaHeader,
}

impl Default for TrpDecoder {
    fn default() -> Self {
        Self {
            time: 0.0,
            before_setup_cache: Some(Vec::new()),
            header: AsciinemaHeader::default(),
        }
    }
}

impl TrpDecoder {
    fn push(&mut self, packet: &PacketHeader, payload: &[u8]) -> anyhow::Result<Vec<String>> {
        self.time += f64::from(packet.time_delta) / 1000.0;
        let time = self.time;

        let mut lines = Vec::new();

        match packet.event_type {
            0 | 1 => {
                let payload = String::from_utf8_lossy(payload).into_owned();
                let event = if packet.event_type == 0 {
                    AsciinemaEvent::TerminalOutput { payload, time }
                } else {
                    AsciinemaEvent::UserInput { payload, time }
                };
                match self.before_setup_cache {
                    Some(ref mut cache) => cache.push(event),
                    None => lines.push(event.to_json()),
                }
            }
            2 => {
                // Terminal size change. Payload is little-endian [columns, rows].
                if payload.len() < 4 {
                    anyhow::bail!("invalid terminal size change payload length (len={})", payload.len());
                }
                self.header.col = u16::from_le_bytes([payload[0], payload[1]]);
                self.header.row = u16::from_le_bytes([payload[2], payload[3]]);
                if self.before_setup_cache.is_none() {
                    let event = AsciinemaEvent::Resize {
                        width: self.header.col,
                        height: self.header.row,
                        time,
                    };
                    lines.push(event.to_json());
                }
            }
            4 => {
                // Terminal setup
                if let Some(cache) = self.before_setup_cache.take() {
                    lines.push(self.header.to_json());
                    lines.extend(cache.iter().map(AsciinemaEvent::to_json));
                } else {
                    warn!("Received terminal setup event but cache is empty");
                }
            }
            _ => {}
        }

        Ok(lines)
    }

    /// Flushes the cached events of a recording that never sent its terminal setup.
    fn finish(self) -> Vec<String> {
        match self.before_setup_cache {
            Some(cache) => core::iter::once(self.header.to_json())
                .chain(cache.iter().map(AsciinemaEvent::to_json))
                .collect(),
            None => Vec::new(),
        }
    }
}

async fn parse_trp_stream(
    mut input_stream: impl AsyncRead + Unpin + Send + 'static,
    mut tx: tokio::sync::mpsc::Sender<anyhow::Result<String>>,
) -> anyhow::Result<()> {
    let mut decoder = TrpDecoder::default();

    loop {
        let mut packet_head_buffer = [0u8; PACKET_HEADER_SIZE];
        if let Err(e) = input_stream.read_exact(&mut packet_head_buffer).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
            anyhow::bail!(e);
        }

        let packet = PacketHeader::parse(&packet_head_buffer);

        let mut event_payload = vec![0u8; usize::from(packet.size)];
        if let Err(e) = input_stream.read_exact(&mut event_payload).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
            anyhow::bail!(e);
        }

        for line in decoder.push(&packet, &event_payload)? {
            send(&mut tx, line).await?;
        }
    }
}

async fn send(sender: &mut tokio::sync::mpsc::Sender<anyhow::Result<String>>, mut json: String) -> anyhow::Result<()> {
    json.push('\n');
    sender.send(Ok(json)).await?;
    Ok(())
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
    fn decodes_a_complete_recording_and_ignores_a_truncated_tail() {
        let mut trp = Vec::new();
        trp.extend(packet(0, 2, &[100, 0, 30, 0]));
        trp.extend(packet(500, 0, b"$ "));
        trp.extend(packet(0, 4, &[]));
        trp.extend(packet(1000, 1, b"l"));
        trp.extend(packet(250, 0, b"ls\r\n"));
        trp.extend(&packet(10, 0, b"lost")[..9]);

        let cast = decode_to_asciicast(&trp).expect("valid recording");

        assert_eq!(
            cast,
            concat!(
                "{\"version\": 2, \"width\": 100, \"height\": 30}\n",
                "[0.5,\"o\",\"$ \"]\n",
                "[1.5,\"i\",\"l\"]\n",
                r#"[1.75,"o","ls\u000d\u000a"]"#,
                "\n",
            )
        );
    }

    #[test]
    fn events_of_a_recording_without_setup_are_kept() {
        let cast = decode_to_asciicast(&packet(2000, 0, b"x")).expect("valid recording");

        assert_eq!(
            cast,
            "{\"version\": 2, \"width\": 80, \"height\": 24}\n[2,\"o\",\"x\"]\n"
        );
    }
}
