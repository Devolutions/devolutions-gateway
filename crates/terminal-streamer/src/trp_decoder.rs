use std::collections::VecDeque;
use std::io::Read;
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

/// Decodes a complete TRP recording into asciicast v2 lines, without their line ending.
///
/// The recording is read one packet at a time, so memory use does not grow with its size.
/// A truncated last packet, as left by an interrupted recording, is ignored.
/// The lines end after the first error.
pub struct AsciicastLines<R> {
    input: R,
    decoder: Option<TrpDecoder>,
    pending: VecDeque<String>,
    payload: Vec<u8>,
}

impl<R: Read> AsciicastLines<R> {
    pub fn new(input: R) -> Self {
        Self {
            input,
            decoder: Some(TrpDecoder::default()),
            pending: VecDeque::new(),
            payload: Vec::new(),
        }
    }

    /// Decodes the next packet into `pending`; at the end of the input, flushes the decoder.
    fn decode_next_packet(&mut self) -> anyhow::Result<()> {
        let Some(decoder) = self.decoder.as_mut() else {
            return Ok(());
        };

        let mut header = [0u8; PACKET_HEADER_SIZE];
        if read_complete(&mut self.input, &mut header)? {
            let header = PacketHeader::parse(&header);
            self.payload.resize(usize::from(header.size), 0);

            if read_complete(&mut self.input, &mut self.payload)? {
                self.pending.extend(decoder.push(&header, &self.payload)?);
                return Ok(());
            }
        }

        if let Some(decoder) = self.decoder.take() {
            self.pending.extend(decoder.finish());
        }

        Ok(())
    }
}

impl<R: Read> Iterator for AsciicastLines<R> {
    type Item = anyhow::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(line) = self.pending.pop_front() {
                return Some(Ok(line));
            }

            self.decoder.as_ref()?;

            if let Err(error) = self.decode_next_packet() {
                self.decoder = None;
                return Some(Err(error));
            }
        }
    }
}

/// Fills `buffer`, or returns `false` if the input ends first.
fn read_complete(input: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<bool> {
    match input.read_exact(buffer) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
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

/// Most payload bytes held while waiting for the terminal setup; past it, the header is sent with the size known so far.
const MAX_BEFORE_SETUP_LEN: usize = 1024 * 1024;

/// Turns TRP packets into asciicast lines, holding the events that come before the terminal setup.
struct TrpDecoder {
    time: f64,
    before_setup_cache: Option<Vec<AsciinemaEvent>>,
    before_setup_len: usize,
    header: AsciinemaHeader,
}

impl Default for TrpDecoder {
    fn default() -> Self {
        Self {
            time: 0.0,
            before_setup_cache: Some(Vec::new()),
            before_setup_len: 0,
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
                let packet_len = payload.len();
                let payload = String::from_utf8_lossy(payload).into_owned();
                let event = if packet.event_type == 0 {
                    AsciinemaEvent::TerminalOutput { payload, time }
                } else {
                    AsciinemaEvent::UserInput { payload, time }
                };
                match self.before_setup_cache {
                    Some(ref mut cache) => {
                        cache.push(event);
                        self.before_setup_len += packet_len;

                        // A recording that never sends its terminal setup must not be held whole in memory.
                        if self.before_setup_len > MAX_BEFORE_SETUP_LEN {
                            lines.extend(self.flush_before_setup());
                        }
                    }
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
                if self.before_setup_cache.is_some() {
                    lines.extend(self.flush_before_setup());
                } else {
                    warn!("Received terminal setup event but cache is empty");
                }
            }
            _ => {}
        }

        Ok(lines)
    }

    /// Returns the header and the cached events, once; the events that follow are not cached anymore.
    fn flush_before_setup(&mut self) -> Vec<String> {
        match self.before_setup_cache.take() {
            Some(cache) => core::iter::once(self.header.to_json())
                .chain(cache.iter().map(AsciinemaEvent::to_json))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Flushes the cached events of a recording that never sent its terminal setup.
    fn finish(mut self) -> Vec<String> {
        self.flush_before_setup()
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

    fn decode(trp: &[u8]) -> anyhow::Result<String> {
        AsciicastLines::new(trp)
            .map(|line| Ok(format!("{}\n", line?)))
            .collect()
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

        let cast = decode(&trp).expect("valid recording");

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

    #[tokio::test]
    async fn complete_recording_matches_the_live_stream_decoder() {
        use tokio::io::AsyncBufReadExt as _;

        let mut trp = Vec::new();
        trp.extend(packet(0, 2, &[120, 0, 40, 0]));
        trp.extend(packet(100, 0, b"before setup"));
        trp.extend(packet(0, 4, &[]));
        trp.extend(packet(300, 1, b"x"));
        trp.extend(packet(0, 2, &[80, 0, 24, 0]));
        trp.extend(packet(42, 0, "é\u{1b}[0m".as_bytes()));

        let complete = decode(&trp).expect("valid recording");

        let (task, live_reader) = decode_stream(std::io::Cursor::new(trp)).expect("start the live decoder");
        let mut live_lines = tokio::io::BufReader::new(live_reader).lines();
        let mut streamed = String::new();
        for _ in complete.lines() {
            let line = live_lines
                .next_line()
                .await
                .expect("read a live line")
                .expect("a live line");
            streamed.push_str(&line);
            streamed.push('\n');
        }
        task.abort();

        assert_eq!(complete, streamed);
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk failure"))
        }
    }

    #[test]
    fn lines_come_out_before_the_rest_of_the_recording_is_read() {
        let mut trp = Vec::new();
        trp.extend(packet(0, 4, &[]));
        trp.extend(packet(1000, 0, b"first"));

        let mut lines = AsciicastLines::new(Read::chain(trp.as_slice(), FailingReader));

        assert_eq!(
            lines.next().expect("header").expect("valid header"),
            "{\"version\": 2, \"width\": 80, \"height\": 24}"
        );
        assert_eq!(
            lines.next().expect("event").expect("valid event"),
            "[1,\"o\",\"first\"]"
        );
        let error = lines.next().expect("read error").expect_err("the rest fails");
        assert!(error.to_string().contains("disk failure"), "{error:#}");
        assert!(lines.next().is_none(), "nothing comes after an error");
    }

    #[test]
    fn events_waiting_for_the_terminal_setup_are_bounded() {
        let payload = vec![b'x'; 60_000];
        let packets = MAX_BEFORE_SETUP_LEN / payload.len() + 1;
        let mut trp = Vec::new();
        for _ in 0..packets {
            trp.extend(packet(0, 0, &payload));
        }

        // The setup never comes: the rest of the recording fails to read.
        let lines = AsciicastLines::new(Read::chain(trp.as_slice(), FailingReader)).collect::<Vec<_>>();

        assert_eq!(lines.len(), 1 + packets + 1, "header, every event, then the read error");
        assert_eq!(
            lines[0].as_ref().expect("valid header"),
            "{\"version\": 2, \"width\": 80, \"height\": 24}"
        );
        assert!(lines[1..=packets].iter().all(Result::is_ok));
        assert!(lines[packets + 1].is_err());
    }

    #[test]
    fn malformed_input_fails_cleanly() {
        let error = decode(&packet(0, 2, &[1, 2])).expect_err("short resize payload");
        assert!(
            error
                .to_string()
                .contains("invalid terminal size change payload length")
        );

        let cast = decode(&[0xFF; 5]).expect("input shorter than a packet header");
        assert_eq!(cast, "{\"version\": 2, \"width\": 80, \"height\": 24}\n");
    }

    #[test]
    fn events_of_a_recording_without_setup_are_kept() {
        let cast = decode(&packet(2000, 0, b"x")).expect("valid recording");

        assert_eq!(
            cast,
            "{\"version\": 2, \"width\": 80, \"height\": 24}\n[2,\"o\",\"x\"]\n"
        );
    }
}
