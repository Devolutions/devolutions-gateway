use std::io::{self, SeekFrom, Write};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use cadeau::xmf::vpx::{VpxCodec, VpxEncoder, VpxEncoderPreset, VpxImage};
use ebml_iterable::error::TagIteratorError;
use ebml_iterable::{PositionedTag, TagDecoder};
use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use webm_iterable::matroska_spec::{Master, MatroskaSpec, SimpleBlock};
use webm_iterable::{WebmWriter, WriteOptions};

use crate::decoder::{Dimensions, InputDecoder};
use crate::session::{RecordingClip, RecordingEvent, SessionConfig, StartAt};
use crate::streamer::block_tag::{VideoBlock, is_vpx_key_frame};

const OUTPUT_CHANNEL_CAPACITY: usize = 4;
const OUTPUT_CHUNK_SIZE: usize = 64 * 1024;
const INPUT_CHANNEL_CAPACITY: usize = 1;
const INPUT_CHUNK_SIZE: usize = 64 * 1024;
const MAX_TAG_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const MAX_INPUT_BUFFER_BYTES: usize = MAX_TAG_PAYLOAD_BYTES + 16;
const OUTPUT_BITRATE: u32 = 256 * 1024;
const VPX_EFLAG_FORCE_KF: u32 = 0x0000_0001;
const WEBM_TIMESTAMP_SCALE_NS: u64 = 1_000_000;
const MAX_WEBM_BLOCK_TIMESTAMP: u64 = 32_767;

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

#[cfg(test)]
pub(crate) fn test_session<S>(stream: S) -> NormalizedSession
where
    S: Stream<Item = anyhow::Result<SegmentEvent>> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
    let supervisor = tokio::spawn(async move {
        tokio::pin!(stream);
        loop {
            tokio::select! {
                event = stream.next() => {
                    let Some(event) = event else { break };
                    if sender.send(event).await.is_err() {
                        break;
                    }
                }
                () = sender.closed() => break,
            }
        }
    });
    NormalizedSession {
        receiver,
        supervisor: Some(supervisor),
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
            RecordingEvent::ClipStarted {
                sequence,
                start_at,
                clip,
            } => {
                anyhow::ensure!(
                    matches!(phase, SessionPhase::AwaitClip),
                    "clip {sequence} started before the previous clip ended"
                );
                let mut clip_normalizer =
                    ClipNormalizer::new(sequence, start_at, clip, sender.clone(), config, next_segment_sequence)?;
                clip_normalizer.scan_available()?;
                phase = SessionPhase::InClip(Box::new(clip_normalizer));
            }
            RecordingEvent::DataAvailable => {
                let SessionPhase::InClip(clip) = &mut phase else {
                    anyhow::bail!("data availability arrived outside a clip");
                };
                clip.scan_available()?;
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

#[derive(Default)]
struct TrackEntryState {
    track: Option<u64>,
    track_type: Option<u64>,
    codec_id: Option<String>,
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
    KeepLatestGop,
}

#[derive(Clone, Copy)]
struct ReplayPoint {
    block_offset: u64,
    cluster_timestamp: u64,
}

struct PendingBlockGroup {
    offset: u64,
    block: Option<Vec<u8>>,
}

struct ClipNormalizer {
    clip_sequence: u64,
    clip: RecordingClip,
    reader_head: u64,
    decoder: TagDecoder<MatroskaSpec>,
    input: BytesMut,
    source_video: Option<SourceVideo>,
    track_entry: Option<TrackEntryState>,
    pending_block_group: Option<PendingBlockGroup>,
    cluster_timestamp: Option<u64>,
    timestamp_scale_ns: u64,
    phase: ClipPhase,
    replay_point: Option<ReplayPoint>,
    complete_boundary: u64,
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
        mut clip: RecordingClip,
        sender: mpsc::Sender<anyhow::Result<SegmentEvent>>,
        config: SessionConfig,
        next_segment_sequence: u64,
    ) -> anyhow::Result<Self> {
        let reader_head = clip.seek(SeekFrom::Start(0))?;
        anyhow::ensure!(reader_head == 0, "recording clip did not seek to its beginning");
        let phase = match start_at {
            StartAt::Beginning => ClipPhase::History(HistoryPolicy::EmitAll),
            StartAt::LiveEdge => ClipPhase::History(HistoryPolicy::KeepLatestGop),
        };
        Ok(Self {
            clip_sequence,
            clip,
            reader_head,
            decoder: new_decoder(),
            input: BytesMut::new(),
            source_video: None,
            track_entry: None,
            pending_block_group: None,
            cluster_timestamp: None,
            timestamp_scale_ns: WEBM_TIMESTAMP_SCALE_NS,
            phase,
            replay_point: None,
            complete_boundary: reader_head,
            input_decoder: None,
            output_segment: None,
            next_segment_sequence,
            sender,
            config,
        })
    }

    fn scan_available(&mut self) -> anyhow::Result<()> {
        let mut process_frame = Self::process_frame;
        self.scan_available_with(&mut process_frame)
    }

    fn scan_available_with<F>(&mut self, process_frame: &mut F) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        loop {
            if self.sender.is_closed() {
                return Ok(());
            }

            while let Some(positioned) = self.decoder.decode(&mut self.input)? {
                if self.sender.is_closed() {
                    return Ok(());
                }
                self.handle_tag_with(positioned, process_frame)?;
            }

            if self.sender.is_closed() {
                return Ok(());
            }
            if self.input.len() >= MAX_INPUT_BUFFER_BYTES {
                anyhow::bail!("recording input exceeds the resource limit");
            }

            let read_limit = (MAX_INPUT_BUFFER_BYTES - self.input.len()).min(INPUT_CHUNK_SIZE);
            anyhow::ensure!(read_limit > 0, "recording input cannot make progress");
            let mut buffer = vec![0; read_limit];
            let read = self.clip.read(&mut buffer)?;
            if read == 0 {
                return Ok(());
            }
            self.reader_head = self
                .reader_head
                .checked_add(u64::try_from(read).context("recording reader position overflow")?)
                .context("recording reader position overflow")?;
            self.input.extend_from_slice(&buffer[..read]);
        }
    }

    fn caught_up(&mut self) -> anyhow::Result<()> {
        let mut process_frame = Self::process_frame;
        self.caught_up_with(&mut process_frame)
    }

    fn caught_up_with<F>(&mut self, process_frame: &mut F) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        let history = match std::mem::replace(&mut self.phase, ClipPhase::Live) {
            ClipPhase::History(history) => history,
            ClipPhase::Live => anyhow::bail!("clip {} sent caught-up twice", self.clip_sequence),
        };
        if matches!(history, HistoryPolicy::KeepLatestGop)
            && let Some(replay_point) = self.replay_point
        {
            self.replay_latest_gop_with(replay_point, process_frame)?;
        }
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<u64> {
        anyhow::ensure!(
            matches!(self.phase, ClipPhase::Live),
            "clip {} ended before caught-up",
            self.clip_sequence
        );
        self.scan_available()?;
        if self.sender.is_closed() {
            return Ok(self.next_segment_sequence);
        }
        loop {
            if self.sender.is_closed() {
                return Ok(self.next_segment_sequence);
            }
            match self.decoder.decode_eof(&mut self.input) {
                Ok(Some(positioned)) => self.handle_tag(positioned)?,
                Ok(None) if self.decoder.is_finished() => break,
                Ok(None) => continue,
                Err(TagIteratorError::UnexpectedEOF { .. }) => {
                    debug!(
                        clip_sequence = self.clip_sequence,
                        bytes = self.input.len(),
                        "Discard incomplete trailing EBML element"
                    );
                    self.input.clear();
                    self.pending_block_group = None;
                    self.track_entry = None;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        if let Some(segment) = self.output_segment.take() {
            segment.finish()?;
        }
        Ok(self.next_segment_sequence)
    }

    fn handle_tag(&mut self, positioned: PositionedTag<MatroskaSpec>) -> anyhow::Result<()> {
        let mut process_frame = Self::process_frame;
        self.handle_tag_with(positioned, &mut process_frame)
    }

    fn handle_tag_with<F>(
        &mut self,
        positioned: PositionedTag<MatroskaSpec>,
        process_frame: &mut F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        let offset = u64::try_from(positioned.offset).context("recording tag offset overflow")?;
        match positioned.tag {
            MatroskaSpec::TrackEntry(Master::Start) => {
                anyhow::ensure!(self.track_entry.is_none(), "nested video track entry");
                self.track_entry = Some(TrackEntryState::default());
            }
            MatroskaSpec::TrackEntry(Master::End) => {
                let track_entry = self
                    .track_entry
                    .take()
                    .context("track entry end arrived without a start")?;
                self.finish_track_entry(track_entry)?;
            }
            MatroskaSpec::TrackNumber(value) => {
                if let Some(track_entry) = &mut self.track_entry {
                    track_entry.track = Some(value);
                }
            }
            MatroskaSpec::TrackType(value) => {
                if let Some(track_entry) = &mut self.track_entry {
                    track_entry.track_type = Some(value);
                }
            }
            MatroskaSpec::CodecID(value) => {
                if let Some(track_entry) = &mut self.track_entry {
                    track_entry.codec_id = Some(value);
                }
            }
            MatroskaSpec::TimestampScale(value) => {
                self.timestamp_scale_ns = value;
            }
            MatroskaSpec::Cluster(Master::Start) => self.cluster_timestamp = None,
            MatroskaSpec::Timestamp(value) => self.cluster_timestamp = Some(value),
            MatroskaSpec::BlockGroup(Master::Start) => {
                anyhow::ensure!(self.pending_block_group.is_none(), "nested block group");
                self.pending_block_group = Some(PendingBlockGroup { offset, block: None });
            }
            MatroskaSpec::Block(data) => {
                let group = self
                    .pending_block_group
                    .as_mut()
                    .context("block arrived outside a block group")?;
                anyhow::ensure!(
                    group.block.replace(data).is_none(),
                    "block group contains multiple blocks"
                );
            }
            MatroskaSpec::BlockGroup(Master::End) => {
                let group = self
                    .pending_block_group
                    .take()
                    .context("block group end arrived without a start")?;
                let data = group.block.context("block group does not contain a block")?;
                self.handle_block_with(
                    MatroskaSpec::BlockGroup(Master::Full(vec![MatroskaSpec::Block(data)])),
                    group.offset,
                    process_frame,
                )?;
                self.complete_boundary = decoder_position(&self.decoder)?;
            }
            MatroskaSpec::SimpleBlock(data) => {
                self.handle_block_with(MatroskaSpec::SimpleBlock(data), offset, process_frame)?;
                self.complete_boundary = decoder_position(&self.decoder)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_track_entry(&mut self, track_entry: TrackEntryState) -> anyhow::Result<()> {
        if track_entry.track_type != Some(1) {
            return Ok(());
        }
        anyhow::ensure!(self.source_video.is_none(), "multiple video tracks are not supported");
        let track = track_entry.track.context("video track number is missing")?;
        let codec_id = track_entry.codec_id.context("video codec ID is missing")?;
        let codec = match codec_id.as_str() {
            "V_VP8" | "vp8" => VpxCodec::VP8,
            "V_VP9" | "vp9" => VpxCodec::VP9,
            _ => anyhow::bail!("unsupported video codec: {codec_id}"),
        };
        self.source_video = Some(SourceVideo { track, codec });
        Ok(())
    }

    fn handle_block_with<F>(
        &mut self,
        tag: MatroskaSpec,
        block_offset: u64,
        process_frame: &mut F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        let cluster_timestamp = self.cluster_timestamp;
        let Some(frame) = self.frame_from_block(tag, cluster_timestamp)? else {
            return Ok(());
        };

        if matches!(&self.phase, ClipPhase::History(HistoryPolicy::KeepLatestGop)) {
            if frame.key_frame {
                self.replay_point = Some(ReplayPoint {
                    block_offset,
                    cluster_timestamp: cluster_timestamp.context("cluster timestamp is missing")?,
                });
            }
            return Ok(());
        }

        process_frame(self, frame)
    }

    fn frame_from_block(
        &self,
        tag: MatroskaSpec,
        cluster_timestamp: Option<u64>,
    ) -> anyhow::Result<Option<PendingFrame>> {
        let video = self
            .source_video
            .context("video track header not found before video data")?;
        let block = VideoBlock::new(tag, cluster_timestamp, video.codec)?;
        if block.track != video.track {
            return Ok(None);
        }

        let data = block.get_frame()?;
        let key_frame = is_vpx_key_frame(&data, video.codec);
        let timestamp = scale_timestamp(block.absolute_timestamp()?, self.timestamp_scale_ns)?;
        Ok(Some(PendingFrame {
            data,
            timestamp,
            codec: video.codec,
            key_frame,
        }))
    }

    fn process_frame(&mut self, frame: PendingFrame) -> anyhow::Result<()> {
        let input_decoder = self
            .input_decoder
            .get_or_insert_with(|| InputDecoder::new(frame.codec, self.config.encoder_threads));
        let decoded = input_decoder.decode(&frame.data)?;
        let dimensions = decoded.dimensions;
        let new_segment = next_segment_info(
            self.output_segment.as_ref().map(|segment| segment.dimensions),
            dimensions,
            self.next_segment_sequence,
        );
        if self.output_segment.is_some() && new_segment.is_some() {
            self.output_segment
                .take()
                .context("missing active output segment")?
                .finish()?;
        }

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

    fn replay_latest_gop_with<F>(&mut self, replay_point: ReplayPoint, process_frame: &mut F) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        if self.sender.is_closed() {
            return Ok(());
        }

        let replay_end = self.complete_boundary;
        anyhow::ensure!(
            replay_point.block_offset <= replay_end,
            "replay point is after the complete scan boundary"
        );
        if replay_point.block_offset == replay_end {
            return Ok(());
        }

        let original_decoder = std::mem::replace(&mut self.decoder, new_decoder());
        let original_input = std::mem::take(&mut self.input);
        let original_reader_head = self.reader_head;
        let replay_result = (|| {
            self.seek_reader(replay_point.block_offset)?;
            self.replay_window(replay_point, replay_end, process_frame)
        })();

        self.decoder = original_decoder;
        self.input = original_input;
        let restore_result = self.seek_reader(original_reader_head);
        if let Err(restore_error) = restore_result {
            return Err(match replay_result {
                Ok(()) => restore_error.context("failed to restore recording reader"),
                Err(replay_error) => {
                    replay_error.context(format!("failed to restore recording reader: {restore_error:#}"))
                }
            });
        }
        replay_result
    }

    fn replay_window<F>(
        &mut self,
        replay_point: ReplayPoint,
        replay_end: u64,
        process_frame: &mut F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        let mut cluster_timestamp = Some(replay_point.cluster_timestamp);
        let mut block_group: Option<PendingBlockGroup> = None;

        loop {
            if self.sender.is_closed() {
                return Ok(());
            }

            while let Some(positioned) = self.decoder.decode(&mut self.input)? {
                if self.sender.is_closed() {
                    return Ok(());
                }
                self.handle_replay_tag(
                    positioned,
                    replay_point.block_offset,
                    &mut cluster_timestamp,
                    &mut block_group,
                    process_frame,
                )?;
            }

            if self.reader_head >= replay_end {
                anyhow::ensure!(self.input.is_empty(), "replay endpoint is inside an incomplete element");
                if let Some(group) = block_group.take() {
                    anyhow::ensure!(
                        group.offset < replay_end,
                        "replay endpoint is inside an incomplete block group"
                    );
                    self.process_replay_block_group(group, cluster_timestamp, process_frame)?;
                }
                return Ok(());
            }

            if self.input.len() >= MAX_INPUT_BUFFER_BYTES {
                anyhow::bail!("replay input exceeds the resource limit");
            }
            let read_limit = usize::try_from(replay_end - self.reader_head)
                .context("replay window is too large")?
                .min(INPUT_CHUNK_SIZE)
                .min(MAX_INPUT_BUFFER_BYTES - self.input.len());
            anyhow::ensure!(read_limit > 0, "replay input cannot make progress");
            let mut buffer = vec![0; read_limit];
            let read = self.clip.read(&mut buffer)?;
            anyhow::ensure!(read > 0, "recording ended before replay boundary");
            self.reader_head = self
                .reader_head
                .checked_add(u64::try_from(read).context("replay reader position overflow")?)
                .context("replay reader position overflow")?;
            self.input.extend_from_slice(&buffer[..read]);
        }
    }

    fn process_replay_block_group<F>(
        &mut self,
        group: PendingBlockGroup,
        cluster_timestamp: Option<u64>,
        process_frame: &mut F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        let data = group.block.context("replay block group does not contain a block")?;
        if let Some(frame) = self.frame_from_block(
            MatroskaSpec::BlockGroup(Master::Full(vec![MatroskaSpec::Block(data)])),
            cluster_timestamp,
        )? {
            process_frame(self, frame)?;
        }
        Ok(())
    }

    fn handle_replay_tag<F>(
        &mut self,
        positioned: PositionedTag<MatroskaSpec>,
        replay_offset: u64,
        cluster_timestamp: &mut Option<u64>,
        block_group: &mut Option<PendingBlockGroup>,
        process_frame: &mut F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&mut Self, PendingFrame) -> anyhow::Result<()>,
    {
        let offset = u64::try_from(positioned.offset)
            .context("replay tag offset overflow")?
            .checked_add(replay_offset)
            .context("replay tag offset overflow")?;
        match positioned.tag {
            MatroskaSpec::Cluster(Master::Start) => *cluster_timestamp = None,
            MatroskaSpec::Timestamp(value) => *cluster_timestamp = Some(value),
            MatroskaSpec::BlockGroup(Master::Start) => {
                anyhow::ensure!(block_group.is_none(), "nested replay block group");
                *block_group = Some(PendingBlockGroup { offset, block: None });
            }
            MatroskaSpec::Block(data) => {
                let group = block_group
                    .as_mut()
                    .context("replay block arrived outside a block group")?;
                anyhow::ensure!(
                    group.block.replace(data).is_none(),
                    "replay block group contains multiple blocks"
                );
            }
            MatroskaSpec::BlockGroup(Master::End) => {
                let group = block_group.take().context("replay block group end without a start")?;
                self.process_replay_block_group(group, *cluster_timestamp, process_frame)?;
            }
            MatroskaSpec::SimpleBlock(data) => {
                if let Some(frame) = self.frame_from_block(MatroskaSpec::SimpleBlock(data), *cluster_timestamp)? {
                    process_frame(self, frame)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn seek_reader(&mut self, position: u64) -> anyhow::Result<()> {
        self.clip.seek(SeekFrom::Start(position))?;
        self.reader_head = position;
        Ok(())
    }
}

fn new_decoder() -> TagDecoder<MatroskaSpec> {
    let mut decoder = TagDecoder::new(&[]);
    decoder.set_max_allowable_tag_size(Some(MAX_TAG_PAYLOAD_BYTES));
    decoder
}

fn decoder_position(decoder: &TagDecoder<MatroskaSpec>) -> anyhow::Result<u64> {
    u64::try_from(decoder.position()).context("decoder position overflow")
}

fn next_segment_info(
    current_dimensions: Option<Dimensions>,
    frame_dimensions: Dimensions,
    next_sequence: u64,
) -> Option<SegmentInfo> {
    (current_dimensions != Some(frame_dimensions)).then_some(SegmentInfo {
        sequence: next_sequence,
        width: frame_dimensions.width,
        height: frame_dimensions.height,
    })
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
    cluster_timestamp: Option<u64>,
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
            cluster_timestamp: None,
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

        let cluster_timestamp_expired = self.cluster_timestamp.is_some_and(|cluster_timestamp| {
            relative_timestamp.saturating_sub(cluster_timestamp) > MAX_WEBM_BLOCK_TIMESTAMP
        });
        let flags = if relative_timestamp == 0 || cluster_timestamp_expired {
            VPX_EFLAG_FORCE_KF
        } else {
            0
        };
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
            let is_key_frame = is_vpx_key_frame(&data, VpxCodec::VP8);
            anyhow::ensure!(
                self.cluster_timestamp.is_some() || is_key_frame,
                "output segment does not begin with a key frame"
            );
            if self.cluster_timestamp.is_none() || is_key_frame {
                if self.cluster_timestamp.is_some() {
                    self.writer.write(&MatroskaSpec::Cluster(Master::End))?;
                }
                self.writer.write_advanced(
                    &MatroskaSpec::Cluster(Master::Start),
                    WriteOptions::is_unknown_sized_element(),
                )?;
                self.writer.write(&MatroskaSpec::Timestamp(timestamp))?;
                self.cluster_timestamp = Some(timestamp);
            }

            let cluster_timestamp = self.cluster_timestamp.context("output cluster timestamp is missing")?;
            let block_timestamp = timestamp
                .checked_sub(cluster_timestamp)
                .context("output frame timestamp precedes its cluster")?;
            let block_timestamp =
                i16::try_from(block_timestamp).context("output cluster exceeds block timestamp range")?;
            let block = SimpleBlock::new_uncheked(&data, 1, block_timestamp, false, None, false, is_key_frame);
            self.writer.write(&MatroskaSpec::from(block))?;
        }

        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<()> {
        self.encoder.flush()?;
        self.write_encoded_frames()?;
        if self.cluster_timestamp.is_some() {
            self.writer.write(&MatroskaSpec::Cluster(Master::End))?;
        }
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
        for chunk in buffer.chunks(OUTPUT_CHUNK_SIZE) {
            self.sender
                .blocking_send(Ok(SegmentEvent::Data(Bytes::copy_from_slice(chunk))))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "segment event receiver closed"))?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
