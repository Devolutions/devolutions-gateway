use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use cadeau::xmf::vpx::{VpxCodec, VpxDecoder, VpxEncoder, VpxEncoderPreset};
use ebml_iterable::TagDecoder;
use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use webm_iterable::matroska_spec::{Master, MatroskaSpec, SimpleBlock};
use webm_iterable::{WebmWriter, WriteOptions};

use crate::session::{RecordingEvent, SessionConfig, StartAt};
use crate::streamer::block_tag::{VideoBlock, is_vpx_key_frame};

const OUTPUT_CHANNEL_CAPACITY: usize = 32;
const INPUT_CHANNEL_CAPACITY: usize = 32;
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
}

impl Stream for NormalizedSession {
    type Item = anyhow::Result<SegmentEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

pub(crate) fn normalize<S>(source: S, config: SessionConfig) -> NormalizedSession
where
    S: Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static,
{
    let (output_sender, output_receiver) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
    let (input_sender, input_receiver) = mpsc::channel(INPUT_CHANNEL_CAPACITY);

    tokio::spawn(async move {
        tokio::pin!(source);
        let worker_sender = output_sender.clone();
        let worker = tokio::task::spawn_blocking(move || normalize_events(input_receiver, worker_sender, config));

        while let Some(event) = source.next().await {
            if input_sender.send(event).await.is_err() {
                break;
            }
        }
        drop(input_sender);

        match worker.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = output_sender
                    .send(Err(error.context("session normalization failed")))
                    .await;
            }
            Err(error) => {
                let _ = output_sender
                    .send(Err(anyhow::Error::new(error).context("normalizer worker failed")))
                    .await;
            }
        }
    });

    NormalizedSession {
        receiver: output_receiver,
    }
}

fn normalize_events(
    mut receiver: mpsc::Receiver<anyhow::Result<RecordingEvent>>,
    sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
    config: SessionConfig,
) -> anyhow::Result<()> {
    let mut clip = None;
    let mut next_segment_sequence = 0;
    let mut session_ended = false;

    while let Some(event) = receiver.blocking_recv() {
        match event.context("recording source failed")? {
            RecordingEvent::ClipStarted { sequence, start_at } => {
                anyhow::ensure!(clip.is_none(), "clip {sequence} started before the previous clip ended");
                clip = Some(ClipNormalizer::new(
                    sequence,
                    start_at,
                    sender.clone(),
                    config,
                    next_segment_sequence,
                ));
            }
            RecordingEvent::Bytes(bytes) => {
                clip.as_mut()
                    .context("recording bytes arrived outside a clip")?
                    .push(&bytes)?;
            }
            RecordingEvent::CaughtUp => {
                clip.as_mut().context("caught-up arrived outside a clip")?.caught_up()?;
            }
            RecordingEvent::ClipEnded => {
                let current = clip.take().context("clip end arrived outside a clip")?;
                next_segment_sequence = current.finish()?;
            }
            RecordingEvent::SessionEnded => {
                anyhow::ensure!(clip.is_none(), "session ended before the active clip ended");
                session_ended = true;
                break;
            }
        }
    }

    anyhow::ensure!(session_ended, "recording source ended before the session end event");
    Ok(())
}

#[derive(Clone, Copy)]
struct SourceVideo {
    track: u64,
    codec: VpxCodec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Dimensions {
    width: u32,
    height: u32,
}

struct PendingFrame {
    data: Vec<u8>,
    timestamp: u64,
    codec: VpxCodec,
    key_frame: bool,
}

struct ClipNormalizer {
    clip_sequence: u64,
    decoder: TagDecoder<MatroskaSpec>,
    input: BytesMut,
    source_video: Option<SourceVideo>,
    cluster_timestamp: Option<u64>,
    timestamp_scale_ns: u64,
    live: bool,
    caught_up_seen: bool,
    pending_gop: Vec<PendingFrame>,
    epoch: Option<Epoch>,
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
        Self {
            clip_sequence,
            decoder: TagDecoder::new(&targets),
            input: BytesMut::new(),
            source_video: None,
            cluster_timestamp: None,
            timestamp_scale_ns: WEBM_TIMESTAMP_SCALE_NS,
            live: start_at == StartAt::Beginning,
            caught_up_seen: false,
            pending_gop: Vec::new(),
            epoch: None,
            next_segment_sequence,
            sender,
            config,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.input.extend_from_slice(bytes);
        while let Some(positioned) = self.decoder.decode(&mut self.input)? {
            self.handle_tag(positioned.tag)?;
        }
        Ok(())
    }

    fn caught_up(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.caught_up_seen, "clip {} sent caught-up twice", self.clip_sequence);
        self.caught_up_seen = true;
        if self.live {
            return Ok(());
        }

        self.live = true;
        for frame in std::mem::take(&mut self.pending_gop) {
            self.process_frame(frame)?;
        }
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<u64> {
        loop {
            match self.decoder.decode_eof(&mut self.input)? {
                Some(positioned) => self.handle_tag(positioned.tag)?,
                None if self.decoder.is_finished() => break,
                None => continue,
            }
        }

        anyhow::ensure!(
            self.live,
            "live-edge clip {} ended before caught-up",
            self.clip_sequence
        );
        if let Some(epoch) = self.epoch.take() {
            epoch.finish()?;
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

        if self.live {
            self.process_frame(frame)
        } else {
            if key_frame {
                self.pending_gop.clear();
            }
            if key_frame || !self.pending_gop.is_empty() {
                self.pending_gop.push(frame);
            }
            Ok(())
        }
    }

    fn process_frame(&mut self, frame: PendingFrame) -> anyhow::Result<()> {
        if frame.key_frame {
            let dimensions = frame_dimensions(&frame.data, frame.codec)?;
            let size_changed = self
                .epoch
                .as_ref()
                .is_some_and(|current| current.dimensions != dimensions);

            if size_changed {
                self.epoch.take().context("missing active epoch")?.finish()?;
            }

            if self.epoch.is_none() {
                self.epoch = Some(Epoch::new(
                    self.sender.clone(),
                    SegmentInfo {
                        sequence: self.next_segment_sequence,
                        width: dimensions.width,
                        height: dimensions.height,
                    },
                    frame.codec,
                    self.config,
                )?);
                self.next_segment_sequence = self
                    .next_segment_sequence
                    .checked_add(1)
                    .context("segment sequence overflow")?;
            }
        }

        if let Some(epoch) = self.epoch.as_mut() {
            epoch.encode(&frame.data, frame.timestamp)?;
        }
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

fn frame_dimensions(frame: &[u8], codec: VpxCodec) -> anyhow::Result<Dimensions> {
    match codec {
        VpxCodec::VP8 => vp8_dimensions(frame),
        VpxCodec::VP9 => vp9_dimensions(frame),
    }
}

fn vp8_dimensions(frame: &[u8]) -> anyhow::Result<Dimensions> {
    anyhow::ensure!(frame.len() >= 10, "VP8 key frame is too short");
    anyhow::ensure!(frame[0] & 1 == 0, "VP8 frame is not a key frame");
    anyhow::ensure!(frame[3..6] == [0x9d, 0x01, 0x2a], "VP8 key frame sync code is invalid");

    let width = u16::from_le_bytes([frame[6], frame[7]]) & 0x3fff;
    let height = u16::from_le_bytes([frame[8], frame[9]]) & 0x3fff;
    anyhow::ensure!(width > 0 && height > 0, "VP8 key frame dimensions are invalid");

    Ok(Dimensions {
        width: u32::from(width),
        height: u32::from(height),
    })
}

fn vp9_dimensions(frame: &[u8]) -> anyhow::Result<Dimensions> {
    let mut bits = BitReader::new(frame);
    anyhow::ensure!(bits.read(2)? == 0b10, "VP9 frame marker is invalid");

    let profile_low = bits.read(1)?;
    let profile_high = bits.read(1)?;
    let profile = profile_low | (profile_high << 1);
    if profile == 3 {
        anyhow::ensure!(bits.read(1)? == 0, "VP9 reserved profile bit is invalid");
    }

    anyhow::ensure!(bits.read(1)? == 0, "VP9 frame references an existing frame");
    anyhow::ensure!(bits.read(1)? == 0, "VP9 frame is not a key frame");
    bits.skip(2)?;
    anyhow::ensure!(bits.read(24)? == 0x49_83_42, "VP9 key frame sync code is invalid");

    if profile >= 2 {
        bits.skip(1)?;
    }
    let color_space = bits.read(3)?;
    if color_space != 7 {
        bits.skip(1)?;
        if profile == 1 || profile == 3 {
            bits.skip(3)?;
        }
    } else if profile == 1 || profile == 3 {
        bits.skip(1)?;
    }

    let width = bits.read(16)?.checked_add(1).context("VP9 width overflow")?;
    let height = bits.read(16)?.checked_add(1).context("VP9 height overflow")?;

    Ok(Dimensions { width, height })
}

struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, count: usize) -> anyhow::Result<u32> {
        anyhow::ensure!(count <= 32, "bit read is too wide");
        let end = self.position.checked_add(count).context("bit position overflow")?;
        anyhow::ensure!(end <= self.bytes.len() * 8, "VP9 key frame header is truncated");

        let mut value = 0;
        while self.position < end {
            let byte = self.bytes[self.position / 8];
            let shift = 7 - (self.position % 8);
            value = (value << 1) | u32::from((byte >> shift) & 1);
            self.position += 1;
        }
        Ok(value)
    }

    fn skip(&mut self, count: usize) -> anyhow::Result<()> {
        self.read(count).map(|_| ())
    }
}

struct Epoch {
    info: SegmentInfo,
    dimensions: Dimensions,
    origin_timestamp: Option<u64>,
    previous_timestamp: Option<u64>,
    decoder: VpxDecoder,
    encoder: VpxEncoder,
    writer: WebmWriter<EventWriter>,
}

impl Epoch {
    fn new(
        sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
        info: SegmentInfo,
        input_codec: VpxCodec,
        config: SessionConfig,
    ) -> anyhow::Result<Self> {
        send_event(&sender, SegmentEvent::Begin(info))?;

        let decoder = VpxDecoder::builder()
            .threads(config.encoder_threads)
            .width(info.width)
            .height(info.height)
            .codec(input_codec)
            .build()?;
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
            decoder,
            encoder,
            writer,
        })
    }

    fn encode(&mut self, frame: &[u8], timestamp: u64) -> anyhow::Result<()> {
        let origin = *self.origin_timestamp.get_or_insert(timestamp);
        let relative_timestamp = timestamp.saturating_sub(origin);
        let duration = self
            .previous_timestamp
            .map_or(30, |previous| timestamp.saturating_sub(previous).max(1));
        self.previous_timestamp = Some(timestamp);

        self.decoder.decode(frame)?;
        let image = self.decoder.next_frame()?;
        let flags = if relative_timestamp == 0 { VPX_EFLAG_FORCE_KF } else { 0 };
        self.encoder.encode_frame(
            &image,
            i64::try_from(relative_timestamp).context("relative timestamp is too large")?,
            usize::try_from(duration).unwrap_or(usize::MAX),
            flags,
        )?;
        drop(image);
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
