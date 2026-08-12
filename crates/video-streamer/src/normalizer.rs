use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use cadeau::xmf::vpx::{VpxCodec, VpxEncoder, VpxEncoderPreset, VpxImage};
use ebml_iterable::TagDecoder;
use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use webm_iterable::matroska_spec::{Master, MatroskaSpec, SimpleBlock};
use webm_iterable::{WebmWriter, WriteOptions};

use crate::decoder::{Dimensions, InputDecoder};
use crate::session::{RecordingEvent, SessionConfig, StartAt};
use crate::streamer::block_tag::{VideoBlock, is_vpx_key_frame};

const OUTPUT_CHANNEL_CAPACITY: usize = 1;
const INPUT_CHANNEL_CAPACITY: usize = 1;
const INPUT_CHUNK_SIZE: usize = 64 * 1024;
const MAX_BUFFERED_TAG_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_GOP_BYTES: usize = 64 * 1024 * 1024;
const OUTPUT_BITRATE: u32 = 256 * 1024;
const VPX_EFLAG_FORCE_KF: u32 = 0x0000_0001;
const WEBM_TIMESTAMP_SCALE_NS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentInfo {
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SegmentEvent {
    Begin(SegmentInfo),
    Data(Bytes),
    End,
}

pub(crate) struct NormalizedSession {
    receiver: mpsc::Receiver<anyhow::Result<SegmentEvent>>,
    supervisor: Option<tokio::task::JoinHandle<()>>,
}

impl Stream for NormalizedSession {
    type Item = anyhow::Result<SegmentEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

impl NormalizedSession {
    pub(crate) async fn shutdown(mut self) -> anyhow::Result<()> {
        self.receiver.close();
        let supervisor = self.supervisor.take().context("normalizer supervisor is missing")?;
        supervisor.await.context("normalizer supervisor failed")
    }
}

impl Drop for NormalizedSession {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.abort();
        }
    }
}

pub(crate) fn normalize<S>(source: S, config: SessionConfig) -> NormalizedSession
where
    S: Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static,
{
    let (output_sender, output_receiver) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
    let (input_sender, input_receiver) = mpsc::channel(INPUT_CHANNEL_CAPACITY);

    let supervisor = tokio::spawn(async move {
        let worker_sender = output_sender.clone();
        let mut worker = tokio::task::spawn_blocking(move || normalize_events(input_receiver, worker_sender, config));
        let mut forward = Box::pin(async move {
            tokio::pin!(source);
            while let Some(event) = source.next().await {
                if input_sender.send(event).await.is_err() {
                    break;
                }
            }
        });

        tokio::select! {
            result = &mut worker => publish_worker_result(result, &output_sender).await,
            () = output_sender.closed() => {
                drop(forward);
                let _ = worker.await;
            }
            () = &mut forward => {
                drop(forward);
                publish_worker_result(worker.await, &output_sender).await;
            }
        };
    });

    NormalizedSession {
        receiver: output_receiver,
        supervisor: Some(supervisor),
    }
}

async fn publish_worker_result(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    sender: &mpsc::Sender<anyhow::Result<SegmentEvent>>,
) {
    let error = match result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => error.context("session normalization failed"),
        Err(error) => anyhow::Error::new(error).context("normalizer worker failed"),
    };
    let _ = sender.send(Err(error)).await;
}

fn normalize_events(
    mut receiver: mpsc::Receiver<anyhow::Result<RecordingEvent>>,
    sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
    config: SessionConfig,
) -> anyhow::Result<()> {
    let mut phase = SessionPhase::AwaitClip;
    let mut next_segment_sequence = 0;

    while let Some(event) = receiver.blocking_recv() {
        match event.context("recording source failed")? {
            RecordingEvent::ClipStarted { sequence, start_at } => {
                anyhow::ensure!(
                    matches!(phase, SessionPhase::AwaitClip),
                    "clip {sequence} started before the previous clip ended"
                );
                phase = SessionPhase::InClip(Box::new(ClipNormalizer::new(
                    sequence,
                    start_at,
                    sender.clone(),
                    config,
                    next_segment_sequence,
                )));
            }
            RecordingEvent::Bytes(bytes) => {
                let SessionPhase::InClip(clip) = &mut phase else {
                    anyhow::bail!("recording bytes arrived outside a clip");
                };
                clip.push(&bytes)?;
            }
            RecordingEvent::CaughtUp => {
                let SessionPhase::InClip(clip) = &mut phase else {
                    anyhow::bail!("caught-up arrived outside a clip");
                };
                clip.caught_up()?;
            }
            RecordingEvent::ClipEnded => {
                let SessionPhase::InClip(current) = std::mem::replace(&mut phase, SessionPhase::AwaitClip) else {
                    anyhow::bail!("clip end arrived outside a clip");
                };
                next_segment_sequence = (*current).finish()?;
            }
            RecordingEvent::SessionEnded => {
                anyhow::ensure!(
                    matches!(phase, SessionPhase::AwaitClip),
                    "session ended before the active clip ended"
                );
                phase = SessionPhase::Ended;
                break;
            }
        }
    }

    anyhow::ensure!(
        matches!(phase, SessionPhase::Ended),
        "recording source ended before the session end event"
    );
    Ok(())
}

enum SessionPhase {
    AwaitClip,
    InClip(Box<ClipNormalizer>),
    Ended,
}

#[derive(Clone, Copy)]
struct SourceVideo {
    track: u64,
    codec: VpxCodec,
}

struct PendingFrame {
    data: Vec<u8>,
    timestamp: u64,
    codec: VpxCodec,
    key_frame: bool,
}

enum ClipPhase {
    History(HistoryPolicy),
    Live,
}

enum HistoryPolicy {
    EmitAll,
    KeepLatestGop(PendingGop),
}

#[derive(Default)]
struct PendingGop {
    frames: Vec<PendingFrame>,
    bytes: usize,
}

impl PendingGop {
    fn push(&mut self, frame: PendingFrame) -> anyhow::Result<()> {
        if frame.key_frame {
            self.frames.clear();
            self.bytes = 0;
        } else if self.frames.is_empty() {
            return Ok(());
        }

        let bytes = self
            .bytes
            .checked_add(frame.data.len())
            .context("pending GOP size overflow")?;
        anyhow::ensure!(bytes <= MAX_PENDING_GOP_BYTES, "pending GOP exceeds the resource limit");
        self.frames.push(frame);
        self.bytes = bytes;
        Ok(())
    }
}

struct ClipNormalizer {
    clip_sequence: u64,
    decoder: TagDecoder<MatroskaSpec>,
    input: BytesMut,
    source_video: Option<SourceVideo>,
    cluster_timestamp: Option<u64>,
    timestamp_scale_ns: u64,
    phase: ClipPhase,
    input_decoder: Option<InputDecoder>,
    output_segment: Option<OutputSegment>,
    next_segment_sequence: u64,
    sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
    config: SessionConfig,
}

impl ClipNormalizer {
    fn new(
        clip_sequence: u64,
        start_at: StartAt,
        sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
        config: SessionConfig,
        next_segment_sequence: u64,
    ) -> Self {
        let targets = [
            MatroskaSpec::TrackEntry(Master::Start),
            MatroskaSpec::BlockGroup(Master::Start),
        ];
        let mut decoder = TagDecoder::new(&targets);
        decoder.set_max_allowable_tag_size(Some(MAX_BUFFERED_TAG_BYTES));
        let phase = match start_at {
            StartAt::Beginning => ClipPhase::History(HistoryPolicy::EmitAll),
            StartAt::LiveEdge => ClipPhase::History(HistoryPolicy::KeepLatestGop(PendingGop::default())),
        };
        Self {
            clip_sequence,
            decoder,
            input: BytesMut::new(),
            source_video: None,
            cluster_timestamp: None,
            timestamp_scale_ns: WEBM_TIMESTAMP_SCALE_NS,
            phase,
            input_decoder: None,
            output_segment: None,
            next_segment_sequence,
            sender,
            config,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        for chunk in bytes.chunks(INPUT_CHUNK_SIZE) {
            self.input.extend_from_slice(chunk);
            while let Some(positioned) = self.decoder.decode(&mut self.input)? {
                self.handle_tag(positioned.tag)?;
            }
        }
        Ok(())
    }

    fn caught_up(&mut self) -> anyhow::Result<()> {
        let history = match std::mem::replace(&mut self.phase, ClipPhase::Live) {
            ClipPhase::History(history) => history,
            ClipPhase::Live => anyhow::bail!("clip {} sent caught-up twice", self.clip_sequence),
        };
        if let HistoryPolicy::KeepLatestGop(pending) = history {
            for frame in pending.frames {
                self.process_frame(frame)?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<u64> {
        anyhow::ensure!(
            matches!(self.phase, ClipPhase::Live),
            "clip {} ended before caught-up",
            self.clip_sequence
        );
        loop {
            match self.decoder.decode_eof(&mut self.input)? {
                Some(positioned) => self.handle_tag(positioned.tag)?,
                None if self.decoder.is_finished() => break,
                None => continue,
            }
        }

        if let Some(segment) = self.output_segment.take() {
            segment.finish()?;
        }
        Ok(self.next_segment_sequence)
    }

    fn handle_tag(&mut self, tag: MatroskaSpec) -> anyhow::Result<()> {
        match tag {
            MatroskaSpec::TrackEntry(Master::Full(children)) => {
                if let Some(video) = parse_video_track(&children)? {
                    anyhow::ensure!(self.source_video.is_none(), "multiple video tracks are not supported");
                    self.source_video = Some(video);
                }
            }
            MatroskaSpec::TimestampScale(value) => self.timestamp_scale_ns = value,
            MatroskaSpec::Cluster(Master::Start) => self.cluster_timestamp = None,
            MatroskaSpec::Timestamp(value) => self.cluster_timestamp = Some(value),
            tag @ (MatroskaSpec::SimpleBlock(_) | MatroskaSpec::BlockGroup(Master::Full(_))) => {
                self.handle_block(tag)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_block(&mut self, tag: MatroskaSpec) -> anyhow::Result<()> {
        let video = self
            .source_video
            .context("video track header not found before video data")?;
        let block = VideoBlock::new(tag, self.cluster_timestamp, video.codec)?;
        if block.track != video.track {
            return Ok(());
        }

        let data = block.get_frame()?;
        let key_frame = is_vpx_key_frame(&data, video.codec);
        let timestamp = scale_timestamp(block.absolute_timestamp()?, self.timestamp_scale_ns)?;
        let frame = PendingFrame {
            data,
            timestamp,
            codec: video.codec,
            key_frame,
        };

        match &mut self.phase {
            ClipPhase::History(HistoryPolicy::KeepLatestGop(pending)) => pending.push(frame),
            ClipPhase::History(HistoryPolicy::EmitAll) | ClipPhase::Live => self.process_frame(frame),
        }
    }

    fn process_frame(&mut self, frame: PendingFrame) -> anyhow::Result<()> {
        let input_decoder = self
            .input_decoder
            .get_or_insert_with(|| InputDecoder::new(frame.codec, self.config.encoder_threads));
        let decoded = input_decoder.decode(&frame.data)?;
        let dimensions = decoded.dimensions;
        let size_changed = self
            .output_segment
            .as_ref()
            .is_some_and(|current| current.dimensions != dimensions);
        if size_changed {
            self.output_segment
                .take()
                .context("missing active output segment")?
                .finish()?;
        }

        let new_segment = if self.output_segment.is_none() {
            Some(SegmentInfo {
                sequence: self.next_segment_sequence,
                width: dimensions.width,
                height: dimensions.height,
            })
        } else {
            None
        };

        if let Some(info) = new_segment {
            self.output_segment = Some(OutputSegment::new(self.sender.clone(), info, self.config)?);
            self.next_segment_sequence = self
                .next_segment_sequence
                .checked_add(1)
                .context("segment sequence overflow")?;
        }
        self.output_segment
            .as_mut()
            .context("output segment is missing")?
            .encode(&decoded.image, frame.timestamp)?;
        Ok(())
    }
}

fn parse_video_track(children: &[MatroskaSpec]) -> anyhow::Result<Option<SourceVideo>> {
    let is_video = children
        .iter()
        .find_map(|tag| match tag {
            MatroskaSpec::TrackType(value) => Some(*value == 1),
            _ => None,
        })
        .unwrap_or(false);

    if !is_video {
        return Ok(None);
    }

    let track = children
        .iter()
        .find_map(|tag| match tag {
            MatroskaSpec::TrackNumber(value) => Some(*value),
            _ => None,
        })
        .context("video track number is missing")?;
    let codec_id = children
        .iter()
        .find_map(|tag| match tag {
            MatroskaSpec::CodecID(value) => Some(value.as_str()),
            _ => None,
        })
        .context("video codec ID is missing")?;
    let codec = match codec_id {
        "V_VP8" | "vp8" => VpxCodec::VP8,
        "V_VP9" | "vp9" => VpxCodec::VP9,
        _ => anyhow::bail!("unsupported video codec: {codec_id}"),
    };

    Ok(Some(SourceVideo { track, codec }))
}

fn scale_timestamp(value: u64, timestamp_scale_ns: u64) -> anyhow::Result<u64> {
    let nanoseconds = u128::from(value)
        .checked_mul(u128::from(timestamp_scale_ns))
        .context("video timestamp overflow")?;
    u64::try_from(nanoseconds / u128::from(WEBM_TIMESTAMP_SCALE_NS)).context("video timestamp is too large")
}

struct OutputSegment {
    info: SegmentInfo,
    dimensions: Dimensions,
    origin_timestamp: Option<u64>,
    previous_timestamp: Option<u64>,
    encoder: VpxEncoder,
    writer: WebmWriter<EventWriter>,
}

impl OutputSegment {
    fn new(
        sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
        info: SegmentInfo,
        config: SessionConfig,
    ) -> anyhow::Result<Self> {
        send_event(&sender, SegmentEvent::Begin(info))?;

        let encoder = VpxEncoder::builder()
            .timebase_num(1)
            .timebase_den(1000)
            .codec(VpxCodec::VP8)
            .width(info.width)
            .height(info.height)
            .threads(config.encoder_threads)
            .bitrate(OUTPUT_BITRATE)
            .preset(VpxEncoderPreset::BestPerformance)
            .build()?;
        let mut writer = WebmWriter::new(EventWriter { sender });
        write_header(&mut writer, info.width, info.height)?;

        Ok(Self {
            info,
            dimensions: Dimensions {
                width: info.width,
                height: info.height,
            },
            origin_timestamp: None,
            previous_timestamp: None,
            encoder,
            writer,
        })
    }

    fn encode(&mut self, image: &VpxImage<'_>, timestamp: u64) -> anyhow::Result<()> {
        let origin = *self.origin_timestamp.get_or_insert(timestamp);
        let relative_timestamp = timestamp.saturating_sub(origin);
        let duration = self
            .previous_timestamp
            .map_or(30, |previous| timestamp.saturating_sub(previous).max(1));
        self.previous_timestamp = Some(timestamp);

        let flags = if relative_timestamp == 0 { VPX_EFLAG_FORCE_KF } else { 0 };
        self.encoder.encode_frame(
            image,
            i64::try_from(relative_timestamp).context("relative timestamp is too large")?,
            usize::try_from(duration).unwrap_or(usize::MAX),
            flags,
        )?;
        self.write_encoded_frames()
    }

    fn write_encoded_frames(&mut self) -> anyhow::Result<()> {
        let frames = self
            .encoder
            .packet_iterator()
            .filter_map(|packet| packet.frame())
            .map(|frame| {
                let timestamp = u64::try_from(frame.pts()).context("encoder returned a negative timestamp")?;
                let data = frame.buffer().context("encoder returned a frame without data")?;
                Ok((timestamp, data))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        for (timestamp, data) in frames {
            write_frame(&mut self.writer, timestamp, &data)?;
        }

        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<()> {
        self.encoder.flush()?;
        self.write_encoded_frames()?;
        let event_writer = self.writer.into_inner()?;
        send_event(&event_writer.sender, SegmentEvent::End)
            .with_context(|| format!("failed to finish segment {}", self.info.sequence))
    }
}

fn write_header(writer: &mut WebmWriter<EventWriter>, width: u32, height: u32) -> anyhow::Result<()> {
    writer.write(&MatroskaSpec::Ebml(Master::Full(vec![
        MatroskaSpec::EbmlVersion(1),
        MatroskaSpec::EbmlReadVersion(1),
        MatroskaSpec::EbmlMaxIdLength(4),
        MatroskaSpec::EbmlMaxSizeLength(8),
        MatroskaSpec::DocType("webm".to_owned()),
        MatroskaSpec::DocTypeVersion(4),
        MatroskaSpec::DocTypeReadVersion(2),
    ])))?;
    writer.write_advanced(
        &MatroskaSpec::Segment(Master::Start),
        WriteOptions::is_unknown_sized_element(),
    )?;
    writer.write(&MatroskaSpec::Info(Master::Full(vec![
        MatroskaSpec::TimestampScale(WEBM_TIMESTAMP_SCALE_NS),
        MatroskaSpec::MuxingApp("Devolutions Gateway".to_owned()),
        MatroskaSpec::WritingApp("Devolutions Gateway".to_owned()),
    ])))?;
    writer.write(&MatroskaSpec::Tracks(Master::Full(vec![MatroskaSpec::TrackEntry(
        Master::Full(vec![
            MatroskaSpec::TrackNumber(1),
            MatroskaSpec::TrackUID(1),
            MatroskaSpec::TrackType(1),
            MatroskaSpec::FlagEnabled(1),
            MatroskaSpec::FlagDefault(1),
            MatroskaSpec::FlagLacing(0),
            MatroskaSpec::CodecID("V_VP8".to_owned()),
            MatroskaSpec::Video(Master::Full(vec![
                MatroskaSpec::PixelWidth(u64::from(width)),
                MatroskaSpec::PixelHeight(u64::from(height)),
            ])),
        ]),
    )])))?;
    Ok(())
}

fn write_frame(writer: &mut WebmWriter<EventWriter>, timestamp: u64, data: &[u8]) -> anyhow::Result<()> {
    writer.write_advanced(
        &MatroskaSpec::Cluster(Master::Start),
        WriteOptions::is_unknown_sized_element(),
    )?;
    writer.write(&MatroskaSpec::Timestamp(timestamp))?;
    let block = SimpleBlock::new_uncheked(data, 1, 0, false, None, false, data[0] & 1 == 0);
    writer.write(&MatroskaSpec::from(block))?;
    writer.write(&MatroskaSpec::Cluster(Master::End))?;
    Ok(())
}

fn send_event(sender: &mpsc::Sender<anyhow::Result<SegmentEvent>>, event: SegmentEvent) -> anyhow::Result<()> {
    sender
        .blocking_send(Ok(event))
        .map_err(|_| anyhow::anyhow!("segment event receiver closed"))
}

struct EventWriter {
    sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
}

impl Write for EventWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.sender
            .blocking_send(Ok(SegmentEvent::Data(Bytes::copy_from_slice(buffer))))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "segment event receiver closed"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
