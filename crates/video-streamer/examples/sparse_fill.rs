//! Experiment: replays a WebM recording into `stream_session` at its real cadence, as a live clip, and reports when
//! output frames reach a client that pulls continuously.
//!
//! Usage: sparse_fill <xmf-lib> <input.webm> <seconds> <fill-ms (0 = off)> <report.json> [fill-delay-ms] [jitter-ms]
//!
//! `jitter-ms` delays each source frame by a pseudo-random 0..jitter-ms (order kept), like a congested push link.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "experiment statistics"
)]

use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::sync::mpsc;
use video_streamer::{RecordingClip, RecordingEvent, SessionConfig, ShadowProtocolVersion, StartAt, stream_session};
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};
use webm_iterable::{WebmIterator, WebmWriter, WriteOptions};

struct SourceFrame {
    timestamp_ms: u64,
    data: Vec<u8>,
    key_frame: bool,
}

fn read_input(path: &PathBuf, limit_ms: u64) -> anyhow::Result<(String, u64, u64, Vec<SourceFrame>)> {
    let file = std::fs::File::open(path)?;
    let mut tags = WebmIterator::new(io::BufReader::new(file), &[MatroskaSpec::BlockGroup(Master::Start)]);
    tags.emit_master_end_when_eof(false);
    let (mut codec, mut width, mut height, mut cluster) = (None, None, None, None);
    let mut frames = Vec::new();
    for tag in &mut tags {
        let tag = match tag {
            Ok(tag) => tag,
            Err(TagIteratorError::UnexpectedEOF { .. }) => break,
            Err(error) => return Err(error.into()),
        };
        let (relative, data, key_frame) = match tag {
            MatroskaSpec::CodecID(id) => {
                codec = Some(id);
                continue;
            }
            MatroskaSpec::PixelWidth(value) => {
                width = Some(value);
                continue;
            }
            MatroskaSpec::PixelHeight(value) => {
                height = Some(value);
                continue;
            }
            MatroskaSpec::Timestamp(value) => {
                cluster = Some(value);
                continue;
            }
            ref simple @ MatroskaSpec::SimpleBlock(_) => {
                let block = SimpleBlock::try_from(simple)?;
                let data = block.read_frame_data()?.remove(0).data.to_vec();
                (block.timestamp, data, block.keyframe)
            }
            MatroskaSpec::BlockGroup(Master::Full(children)) => {
                let Some(raw @ MatroskaSpec::Block(_)) =
                    children.iter().find(|tag| matches!(tag, MatroskaSpec::Block(_)))
                else {
                    continue;
                };
                let block = Block::try_from(raw)?;
                let data = block.read_frame_data()?.remove(0).data.to_vec();
                let key_frame = data.first().is_some_and(|byte| byte & 1 == 0);
                (block.timestamp, data, key_frame)
            }
            _ => continue,
        };
        let timestamp_ms =
            u64::try_from(i64::try_from(cluster.context("block before cluster")?)? + i64::from(relative))?;
        if frames
            .first()
            .is_some_and(|first: &SourceFrame| timestamp_ms - first.timestamp_ms > limit_ms)
        {
            break;
        }
        frames.push(SourceFrame {
            timestamp_ms,
            data,
            key_frame,
        });
    }
    Ok((
        codec.context("codec")?,
        width.context("width")?,
        height.context("height")?,
        frames,
    ))
}

/// Header bytes, then one cluster per frame.
#[derive(Clone, Default)]
struct SharedBuffer(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

impl io::Write for SharedBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn build_feed(codec: &str, width: u64, height: u64, frames: &[SourceFrame]) -> anyhow::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let buffer = SharedBuffer::default();
    let take = |buffer: &SharedBuffer| core::mem::take(&mut *buffer.0.borrow_mut());
    let mut header = WebmWriter::new(buffer.clone());
    header.write(&MatroskaSpec::Ebml(Master::Full(vec![
        MatroskaSpec::EbmlVersion(1),
        MatroskaSpec::EbmlReadVersion(1),
        MatroskaSpec::EbmlMaxIdLength(4),
        MatroskaSpec::EbmlMaxSizeLength(8),
        MatroskaSpec::DocType("webm".to_owned()),
        MatroskaSpec::DocTypeVersion(4),
        MatroskaSpec::DocTypeReadVersion(2),
    ])))?;
    header.write_advanced(
        &MatroskaSpec::Segment(Master::Start),
        WriteOptions::is_unknown_sized_element(),
    )?;
    header.write(&MatroskaSpec::Info(Master::Full(vec![MatroskaSpec::TimestampScale(
        1_000_000,
    )])))?;
    header.write(&MatroskaSpec::Tracks(Master::Full(vec![MatroskaSpec::TrackEntry(
        Master::Full(vec![
            MatroskaSpec::TrackNumber(1),
            MatroskaSpec::TrackUID(1),
            MatroskaSpec::TrackType(1),
            MatroskaSpec::CodecID(codec.to_owned()),
            MatroskaSpec::Video(Master::Full(vec![
                MatroskaSpec::PixelWidth(width),
                MatroskaSpec::PixelHeight(height),
            ])),
        ]),
    )])))?;
    let header_bytes = take(&buffer);

    let clusters = frames
        .iter()
        .map(|frame| {
            header.write(&MatroskaSpec::Cluster(Master::Full(vec![
                MatroskaSpec::Timestamp(frame.timestamp_ms),
                MatroskaSpec::from(SimpleBlock::new_uncheked(
                    &frame.data,
                    1,
                    0,
                    false,
                    None,
                    false,
                    frame.key_frame,
                )),
            ])))?;
            Ok(take(&buffer))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok((header_bytes, clusters))
}

/// A growing in-memory file.
#[derive(Clone, Default)]
struct LiveFile(Arc<Mutex<Vec<u8>>>);

struct LiveReader {
    file: LiveFile,
    position: u64,
}

impl Read for LiveReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let data = self.file.0.lock().expect("poisoned");
        let mut cursor = Cursor::new(data.as_slice());
        cursor.set_position(self.position);
        let read = cursor.read(buffer)?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for LiveReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let length = self.file.0.lock().expect("poisoned").len() as u64;
        self.position = match position {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => length.saturating_add_signed(offset),
            SeekFrom::Current(offset) => self.position.saturating_add_signed(offset),
        };
        Ok(self.position)
    }
}

struct ChannelTransport {
    incoming: mpsc::UnboundedReceiver<Result<Bytes, io::Error>>,
    outgoing: mpsc::UnboundedSender<(Instant, Bytes)>,
}

impl Stream for ChannelTransport {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().incoming.poll_recv(cx)
    }
}

impl Sink<Bytes> for ChannelTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.outgoing
            .send((Instant::now(), item))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct OutputFrame {
    arrival_ms: f64,
    timestamp_ms: u64,
    bytes: usize,
}

fn read_vint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let length = first.leading_zeros() as usize + 1;
    if length > 8 || data.len() < length {
        return None;
    }
    let mut value = u64::from(first) & ((1u64 << (8 - length)) - 1);
    for byte in &data[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

/// Finds Cluster Timestamp and SimpleBlock elements in a chunk of server output.
fn scan_output(chunk: &[u8], cluster: &mut u64, arrival_ms: f64, out: &mut Vec<OutputFrame>) {
    let mut at = 0;
    while at < chunk.len() {
        let rest = &chunk[at..];
        if rest.starts_with(&[0x1F, 0x43, 0xB6, 0x75]) {
            // Cluster of unknown size: step inside.
            at += 4 + read_vint(&rest[4..]).map_or(1, |(_, length)| length);
            continue;
        }
        let Some(id_length) = rest.first().map(|byte| byte.leading_zeros() as usize + 1) else {
            break;
        };
        let Some((size, size_length)) = read_vint(&rest[id_length..]) else {
            break;
        };
        let body = id_length + size_length;
        let Ok(size) = usize::try_from(size) else { break };
        if rest.len() < body + size {
            break;
        }
        let payload = &rest[body..body + size];
        match rest[0] {
            0xE7 if id_length == 1 => {
                *cluster = payload.iter().fold(0, |value, byte| (value << 8) | u64::from(*byte));
            }
            0xA3 if id_length == 1 => {
                let relative = i16::from_be_bytes([payload[1], payload[2]]);
                out.push(OutputFrame {
                    arrival_ms,
                    timestamp_ms: cluster.saturating_add_signed(i64::from(relative)),
                    bytes: size,
                });
            }
            _ => {}
        }
        at += body + size;
    }
}

fn percentile(values: &mut [f64], p: f64) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    values.sort_by(f64::total_cmp);
    values[((values.len() - 1) as f64 * p).round() as usize]
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
#[expect(clippy::print_stdout, reason = "example output")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        (6..=8).contains(&args.len()),
        "usage: sparse_fill <xmf-lib> <input.webm> <seconds> <fill-ms> <report.json> [fill-delay-ms] [jitter-ms]"
    );
    // SAFETY: XMF has no initialization precondition beyond a valid library path.
    unsafe { cadeau::xmf::init(&args[1]) }.context("load XMF")?;
    let input = PathBuf::from(&args[2]);
    let limit_ms = args[3].parse::<u64>()? * 1000;
    let fill_ms = args[4].parse::<u64>()?;
    let report = PathBuf::from(&args[5]);
    let fill_delay_ms = args.get(6).map_or(Ok(0), |value| value.parse::<u64>())?;
    let jitter_ms = args.get(7).map_or(Ok(0), |value| value.parse::<u64>())?;

    let (codec, width, height, frames) = read_input(&input, limit_ms)?;
    anyhow::ensure!(!frames.is_empty(), "no frames");
    let (header, clusters) = build_feed(&codec, width, height, &frames)?;
    let first_ms = frames[0].timestamp_ms;
    let source_ms: Vec<u64> = frames.iter().map(|frame| frame.timestamp_ms - first_ms).collect();
    let last_ms = *source_ms.last().expect("not empty");

    let file = LiveFile::default();
    file.0.lock().expect("poisoned").extend_from_slice(&header);
    file.0.lock().expect("poisoned").extend_from_slice(&clusters[0]);

    let (event_sender, mut event_receiver) = mpsc::unbounded_channel::<anyhow::Result<RecordingEvent>>();
    let start = Instant::now();
    let feeder = {
        let file = file.clone();
        let source_ms = source_ms.clone();
        tokio::spawn(async move {
            let mut state = 0x2545_f491_4f6c_dd1du64;
            let mut not_before = 0;
            for (offset, cluster) in source_ms.iter().zip(&clusters).skip(1) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let jitter = if jitter_ms == 0 { 0 } else { state % (jitter_ms + 1) };
                let due = (offset + jitter).max(not_before);
                not_before = due;
                tokio::time::sleep_until((start + Duration::from_millis(due)).into()).await;
                file.0.lock().expect("poisoned").extend_from_slice(cluster);
                let _ = event_sender.send(Ok(RecordingEvent::DataAvailable));
            }
            // Keep the clip open past the last frame, like a producer that is still connected.
            tokio::time::sleep(Duration::from_secs(10)).await;
            let _ = event_sender.send(Ok(RecordingEvent::ClipEnded));
            let _ = event_sender.send(Ok(RecordingEvent::SessionEnded));
        })
    };

    let source_file = file.clone();
    let start_source = move || async move {
        let clip = RecordingClip::new(LiveReader {
            file: source_file,
            position: 0,
        });
        let head = futures_util::stream::iter([
            Ok(RecordingEvent::ClipStarted {
                sequence: 0,
                start_at: StartAt::LiveEdge,
                clip,
            }),
            Ok(RecordingEvent::DataAvailable),
            Ok(RecordingEvent::CaughtUp),
        ]);
        let tail = futures_util::stream::poll_fn(move |cx| event_receiver.poll_recv(cx));
        Ok(futures_util::StreamExt::chain(head, tail))
    };

    let (client_sender, client_receiver) = mpsc::unbounded_channel();
    let (server_sender, mut server_receiver) = mpsc::unbounded_channel();
    let transport = ChannelTransport {
        incoming: client_receiver,
        outgoing: server_sender,
    };
    client_sender.send(Ok(Bytes::from_static(&[0])))?;
    for _ in 0..4 {
        client_sender.send(Ok(Bytes::from_static(&[1])))?;
    }

    let config = SessionConfig {
        encoder_threads: 1,
        adaptive_frame_skip: false,
        fill_interval: (fill_ms > 0).then(|| Duration::from_millis(fill_ms)),
        fill_delay: Duration::from_millis(fill_delay_ms),
    };
    let server = tokio::spawn(stream_session(
        move || async move { start_source().await },
        transport,
        config,
        ShadowProtocolVersion::V2,
    ));

    let mut output = Vec::new();
    let mut cluster = 0;
    let mut total_bytes = 0;
    while let Some((at, message)) = server_receiver.recv().await {
        let _ = client_sender.send(Ok(Bytes::from_static(&[1])));
        let Some((&kind, payload)) = message.split_first() else {
            continue;
        };
        match kind {
            0x00 => {
                total_bytes += payload.len();
                scan_output(payload, &mut cluster, (at - start).as_secs_f64() * 1000.0, &mut output);
            }
            0x03 | 0x02 => break,
            _ => {}
        }
    }
    drop(client_sender);
    server.await??;
    feeder.await?;

    // Output timestamps restart at 0 per segment; the first output frame is the first source frame.
    let mut wall_gaps: Vec<f64> = output
        .windows(2)
        .map(|pair| pair[1].arrival_ms - pair[0].arrival_ms)
        .collect();
    let mut media_gaps: Vec<f64> = output
        .windows(2)
        .map(|pair| pair[1].timestamp_ms.saturating_sub(pair[0].timestamp_ms) as f64)
        .collect();
    // Delay between when the source made a picture available and when the client got the frame showing it.
    let mut delays: Vec<f64> = output
        .iter()
        .map(|frame| frame.arrival_ms - frame.timestamp_ms as f64)
        .collect();
    let source_frames = frames.len();
    let output_frames = output.len();
    let wall_gap_max = percentile(&mut wall_gaps.clone(), 1.0);
    let wall_gap_p95 = percentile(&mut wall_gaps, 0.95);
    let media_gap_max = percentile(&mut media_gaps, 1.0);
    let delay_p50 = percentile(&mut delays.clone(), 0.5);
    let delay_max = percentile(&mut delays, 1.0);
    let frame_bytes: usize = output.iter().map(|frame| frame.bytes).sum();
    let span_s = last_ms as f64 / 1000.0 + 10.0;
    let json = format!(
        "{{\"input\":\"{}\",\"fill_ms\":{fill_ms},\"fill_delay_ms\":{fill_delay_ms},\"jitter_ms\":{jitter_ms},\"late_frames_moved\":{},\"span_s\":{span_s:.1},\"source_frames\":{source_frames},\"output_frames\":{output_frames},\"output_bytes\":{total_bytes},\"frame_bytes\":{frame_bytes},\"kbps\":{:.2},\"wall_gap_p95_ms\":{wall_gap_p95:.0},\"wall_gap_max_ms\":{wall_gap_max:.0},\"media_gap_max_ms\":{media_gap_max:.0},\"delay_p50_ms\":{delay_p50:.0},\"delay_max_ms\":{delay_max:.0},\"source_ms\":{source_ms:?},\"frames\":[{}]}}",
        input.display().to_string().replace('\\', "/"),
        video_streamer::late_frames_moved(),
        total_bytes as f64 * 8.0 / span_s / 1000.0,
        output
            .iter()
            .map(|frame| format!("[{:.0},{},{}]", frame.arrival_ms, frame.timestamp_ms, frame.bytes))
            .collect::<Vec<_>>()
            .join(","),
    );
    std::fs::write(&report, &json)?;
    println!("{}", json.split(",\"source_ms\"").next().unwrap_or_default());
    Ok(())
}
