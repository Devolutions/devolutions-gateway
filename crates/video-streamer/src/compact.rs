//! Post-recording compaction of WebM recordings.
//!
//! Recorders that capture on a fixed tick (e.g. web pages at 1 fps) keep spending bytes on a picture that did not
//! change, because the encoder keeps refining it. Compaction decodes the recording, keeps only the frames whose
//! picture changed, and re-encodes them at their original timestamps with a quantizer ceiling so that text stays
//! legible. The first and last frames are always kept, so the duration is unchanged.
//!
//! Damage-driven recordings (e.g. RDP) already contain only changed frames and usually grow when re-encoded with a
//! quality ceiling. Compaction gives up as soon as its output outgrows the input it has consumed so far.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write as _};
use std::path::Path;

use anyhow::Context as _;
use cadeau::xmf::vpx::{VpxCodec, VpxDecoder, VpxEncoder, VpxImage};
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Master, MatroskaSpec, SimpleBlock};
use webm_iterable::{WebmIterator, WebmWriter, WriteOptions};

use crate::streamer::block_tag::{VideoBlock, is_vpx_key_frame};

/// A block counts as changed when its mean absolute luma difference exceeds this value.
const CHANGE_THRESHOLD: u32 = 12;
const BLOCK_SIZE: usize = 8;
/// Quantizer ceiling for the re-encode; 63 (the libvpx default) makes small text unreadable on sparse frames.
const MAX_QUANTIZER: u8 = 30;
const KEY_FRAME_INTERVAL_MS: u64 = 30_000;
/// Media time after which the output must stay smaller than the input consumed so far.
const SIZE_CHECK_GRACE_MS: u64 = 60_000;
const MAX_CLUSTER_SPAN_MS: u64 = 30_000;
const WEBM_TIMESTAMP_SCALE_NS: u64 = 1_000_000;
const VPX_EFLAG_FORCE_KF: u32 = 0x0000_0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactStats {
    pub input_frames: u64,
    pub kept_frames: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactOutcome {
    /// The compacted recording was written to the output path. It still needs a remux to get cues and a duration.
    Written(CompactStats),
    /// Compaction was abandoned; the output path may contain a partial file.
    Skipped(SkipReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    NoFrames,
    Unsupported(String),
    /// The output grew larger than the input it replaces.
    NotSmaller,
}

/// Writes a compacted copy of the WebM recording at `input_path` to `output_path`.
///
/// Requires XMF to be initialized. CPU-intensive: call it from a blocking context.
pub fn compact_webm(input_path: &Path, output_path: &Path) -> anyhow::Result<CompactOutcome> {
    let input_size = std::fs::metadata(input_path)
        .with_context(|| format!("read metadata of {}", input_path.display()))?
        .len();

    let probe = match probe(input_path)? {
        Ok(probe) => probe,
        Err(reason) => return Ok(CompactOutcome::Skipped(reason)),
    };

    let mut frames = FrameReader::open(input_path)?;
    let mut compactor = Compactor::new(&probe, input_size, output_path)?;

    let mut next = frames.next_frame()?;
    while let Some(frame) = next {
        next = frames.next_frame()?;
        let is_last = next.is_none();
        if let Some(reason) = compactor.push(frame, is_last)? {
            return Ok(CompactOutcome::Skipped(reason));
        }
    }

    compactor.finish()
}

struct Probe {
    codec: VpxCodec,
    width: u32,
    height: u32,
    first_ms: u64,
    last_ms: u64,
}

fn probe(path: &Path) -> anyhow::Result<Result<Probe, SkipReason>> {
    let mut frames = FrameReader::open(path)?;
    let mut first_ms = None;
    let mut last_ms = 0;
    while let Some(frame) = frames.next_frame()? {
        first_ms.get_or_insert(frame.timestamp_ms);
        last_ms = frame.timestamp_ms;
    }

    if let Some(reason) = frames.unsupported.take() {
        return Ok(Err(SkipReason::Unsupported(reason)));
    }
    let Some(first_ms) = first_ms else {
        return Ok(Err(SkipReason::NoFrames));
    };
    let video = frames.video.context("video track is missing")?;
    let (Some(width), Some(height)) = (video.width, video.height) else {
        return Ok(Err(SkipReason::Unsupported("video dimensions are missing".to_owned())));
    };

    Ok(Ok(Probe {
        codec: video.codec,
        width,
        height,
        first_ms,
        last_ms,
    }))
}

struct Frame {
    timestamp_ms: u64,
    data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct VideoTrack {
    number: u64,
    codec: VpxCodec,
    width: Option<u32>,
    height: Option<u32>,
}

#[derive(Default)]
struct TrackEntry {
    number: Option<u64>,
    track_type: Option<u64>,
    codec_id: Option<String>,
    width: Option<u64>,
    height: Option<u64>,
}

/// Reads video frames from a single-track VP8/VP9 WebM file.
///
/// Anything else stops the iteration and records the reason in `unsupported`.
struct FrameReader {
    tags: WebmIterator<BufReader<File>>,
    track_entries: usize,
    track_entry: Option<TrackEntry>,
    video: Option<VideoTrack>,
    cluster_timestamp: Option<u64>,
    unsupported: Option<String>,
}

impl FrameReader {
    fn open(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut tags = WebmIterator::new(BufReader::new(file), &[MatroskaSpec::BlockGroup(Master::Start)]);
        tags.emit_master_end_when_eof(false);
        Ok(Self {
            tags,
            track_entries: 0,
            track_entry: None,
            video: None,
            cluster_timestamp: None,
            unsupported: None,
        })
    }

    fn next_frame(&mut self) -> anyhow::Result<Option<Frame>> {
        if self.unsupported.is_some() {
            return Ok(None);
        }

        loop {
            let tag = match self.tags.next() {
                None | Some(Err(TagIteratorError::UnexpectedEOF { .. })) => return Ok(None),
                Some(Err(error)) => return Err(error).context("read WebM tag"),
                Some(Ok(tag)) => tag,
            };

            match tag {
                MatroskaSpec::TimestampScale(scale) if scale != WEBM_TIMESTAMP_SCALE_NS => {
                    return Ok(self.stop(format!("timestamp scale {scale} is not supported")));
                }
                MatroskaSpec::TrackEntry(Master::Start) => {
                    self.track_entries += 1;
                    if self.track_entries > 1 {
                        return Ok(self.stop("multiple tracks are not supported".to_owned()));
                    }
                    self.track_entry = Some(TrackEntry::default());
                }
                MatroskaSpec::TrackNumber(value) => {
                    if let Some(entry) = &mut self.track_entry {
                        entry.number = Some(value);
                    }
                }
                MatroskaSpec::TrackType(value) => {
                    if let Some(entry) = &mut self.track_entry {
                        entry.track_type = Some(value);
                    }
                }
                MatroskaSpec::CodecID(value) => {
                    if let Some(entry) = &mut self.track_entry {
                        entry.codec_id = Some(value);
                    }
                }
                MatroskaSpec::PixelWidth(value) => {
                    if let Some(entry) = &mut self.track_entry {
                        entry.width = Some(value);
                    }
                }
                MatroskaSpec::PixelHeight(value) => {
                    if let Some(entry) = &mut self.track_entry {
                        entry.height = Some(value);
                    }
                }
                MatroskaSpec::TrackEntry(Master::End) => {
                    let entry = self.track_entry.take().context("track entry end without a start")?;
                    if let Err(reason) = self.finish_track_entry(entry) {
                        return Ok(self.stop(reason));
                    }
                }
                MatroskaSpec::Cluster(Master::Start) => self.cluster_timestamp = None,
                MatroskaSpec::Timestamp(value) => self.cluster_timestamp = Some(value),
                tag @ (MatroskaSpec::SimpleBlock(_) | MatroskaSpec::BlockGroup(Master::Full(_))) => {
                    let Some(video) = self.video else {
                        return Ok(self.stop("block before the video track".to_owned()));
                    };
                    let block = VideoBlock::new(tag, self.cluster_timestamp, video.codec)?;
                    if block.track != video.number {
                        return Ok(self.stop(format!("block for unknown track {}", block.track)));
                    }
                    return Ok(Some(Frame {
                        timestamp_ms: block.absolute_timestamp()?,
                        data: block.get_frame()?,
                    }));
                }
                _ => {}
            }
        }
    }

    fn finish_track_entry(&mut self, entry: TrackEntry) -> Result<(), String> {
        if entry.track_type != Some(1) {
            return Err("only video tracks are supported".to_owned());
        }
        let codec = match entry.codec_id.as_deref() {
            Some("V_VP8") => VpxCodec::VP8,
            Some("V_VP9") => VpxCodec::VP9,
            other => return Err(format!("codec {other:?} is not supported")),
        };
        let dimension = |value: Option<u64>| value.and_then(|value| u32::try_from(value).ok());
        self.video = Some(VideoTrack {
            number: entry.number.ok_or("video track number is missing")?,
            codec,
            width: dimension(entry.width),
            height: dimension(entry.height),
        });
        Ok(())
    }

    fn stop(&mut self, reason: String) -> Option<Frame> {
        self.unsupported = Some(reason);
        None
    }
}

struct Compactor {
    /// The output keeps the input codec.
    codec: VpxCodec,
    width: u32,
    height: u32,
    first_ms: u64,
    decoder: VpxDecoder,
    encoder: VpxEncoder,
    writer: WebmWriter<BufWriter<File>>,
    /// Luma of the last kept picture, `width * height` bytes.
    kept_luma: Vec<u8>,
    luma: Vec<u8>,
    has_kept: bool,
    previous_encoded_ms: Option<u64>,
    last_key_frame_ms: Option<u64>,
    cluster_start_ms: Option<u64>,
    input_frames: u64,
    kept_frames: u64,
    input_bytes: u64,
    input_size: u64,
    output_bytes: u64,
}

impl Compactor {
    fn new(probe: &Probe, input_size: u64, output_path: &Path) -> anyhow::Result<Self> {
        let decoder = VpxDecoder::builder()
            .threads(1)
            .width(probe.width)
            .height(probe.height)
            .codec(probe.codec)
            .build()
            .context("build decoder")?;

        let span_ms = probe.last_ms.saturating_sub(probe.first_ms).max(1000);
        let bitrate_kbps = input_size.saturating_mul(8).div_ceil(span_ms).max(1);
        let encoder = VpxEncoder::builder()
            .timebase_num(1)
            .timebase_den(1000)
            .codec(probe.codec)
            .width(probe.width)
            .height(probe.height)
            .threads(1)
            .bitrate(u32::try_from(bitrate_kbps).unwrap_or(u32::MAX))
            .max_quantizer(MAX_QUANTIZER)
            .build()
            .context("build encoder")?;

        let file = File::create(output_path).with_context(|| format!("create {}", output_path.display()))?;
        let mut writer = WebmWriter::new(BufWriter::new(file));
        write_header(&mut writer, probe)?;

        let luma_size = usize::try_from(u64::from(probe.width) * u64::from(probe.height))?;

        Ok(Self {
            codec: probe.codec,
            width: probe.width,
            height: probe.height,
            first_ms: probe.first_ms,
            decoder,
            encoder,
            writer,
            kept_luma: vec![0; luma_size],
            luma: vec![0; luma_size],
            has_kept: false,
            previous_encoded_ms: None,
            last_key_frame_ms: None,
            cluster_start_ms: None,
            input_frames: 0,
            kept_frames: 0,
            input_bytes: 0,
            input_size,
            output_bytes: 0,
        })
    }

    fn push(&mut self, frame: Frame, is_last: bool) -> anyhow::Result<Option<SkipReason>> {
        self.input_frames += 1;
        self.input_bytes += u64::try_from(frame.data.len())?;

        self.decoder.decode(&frame.data).context("decode frame")?;
        // Frames that produce no picture (e.g. VP9 hidden frames) leave the screen unchanged.
        let Ok(image) = self.decoder.next_frame() else {
            return Ok(None);
        };

        if image.width() != self.width || image.height() != self.height {
            return Ok(Some(SkipReason::Unsupported(
                "resolution changes inside the recording".to_owned(),
            )));
        }

        copy_luma(&image, &mut self.luma)?;
        let keep =
            !self.has_kept || is_last || picture_changed(&self.kept_luma, &self.luma, usize::try_from(self.width)?);
        if keep {
            Self::encode(
                &mut self.encoder,
                &image,
                frame.timestamp_ms,
                &mut self.previous_encoded_ms,
                self.last_key_frame_ms,
            )?;
            drop(image);
            core::mem::swap(&mut self.kept_luma, &mut self.luma);
            self.has_kept = true;
            self.kept_frames += 1;
            self.write_encoded_frames()?;
        }

        let media_ms = frame.timestamp_ms.saturating_sub(self.first_ms);
        let outgrown = self.output_bytes > self.input_size
            || (media_ms >= SIZE_CHECK_GRACE_MS && self.output_bytes > self.input_bytes);
        Ok(outgrown.then_some(SkipReason::NotSmaller))
    }

    fn encode(
        encoder: &mut VpxEncoder,
        image: &VpxImage<'_>,
        timestamp_ms: u64,
        previous_encoded_ms: &mut Option<u64>,
        last_key_frame_ms: Option<u64>,
    ) -> anyhow::Result<()> {
        let force_key_frame = last_key_frame_ms
            .is_none_or(|key_frame_ms| timestamp_ms.saturating_sub(key_frame_ms) >= KEY_FRAME_INTERVAL_MS);
        // The duration only drives rate control; a kept frame may stand for minutes of unchanged picture.
        let duration = previous_encoded_ms.map_or(1000, |previous| timestamp_ms.saturating_sub(previous).max(1));
        *previous_encoded_ms = Some(timestamp_ms);

        encoder.encode_frame(
            image,
            i64::try_from(timestamp_ms).context("timestamp is too large")?,
            usize::try_from(duration).unwrap_or(usize::MAX),
            if force_key_frame { VPX_EFLAG_FORCE_KF } else { 0 },
        )?;
        Ok(())
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
            let is_key_frame = is_vpx_key_frame(&data, self.codec);
            if is_key_frame {
                self.last_key_frame_ms = Some(timestamp);
            }

            let new_cluster = match self.cluster_start_ms {
                None => true,
                Some(start) => is_key_frame || timestamp.saturating_sub(start) > MAX_CLUSTER_SPAN_MS,
            };
            if new_cluster {
                if self.cluster_start_ms.is_some() {
                    self.writer.write(&MatroskaSpec::Cluster(Master::End))?;
                }
                self.writer.write(&MatroskaSpec::Cluster(Master::Start))?;
                self.writer.write(&MatroskaSpec::Timestamp(timestamp))?;
                self.cluster_start_ms = Some(timestamp);
            }

            let cluster_start = self.cluster_start_ms.context("cluster timestamp is missing")?;
            let block_timestamp = i16::try_from(
                timestamp
                    .checked_sub(cluster_start)
                    .context("frame timestamp precedes its cluster")?,
            )
            .context("cluster exceeds the block timestamp range")?;
            let block = SimpleBlock::new_uncheked(&data, 1, block_timestamp, false, None, false, is_key_frame);
            self.writer.write(&MatroskaSpec::from(block))?;
            self.output_bytes += u64::try_from(data.len())?;
        }

        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<CompactOutcome> {
        self.encoder.flush()?;
        self.write_encoded_frames()?;
        if self.cluster_start_ms.is_some() {
            self.writer.write(&MatroskaSpec::Cluster(Master::End))?;
        }
        let mut file = self.writer.into_inner()?;
        file.flush()?;

        if self.output_bytes >= self.input_size {
            return Ok(CompactOutcome::Skipped(SkipReason::NotSmaller));
        }

        Ok(CompactOutcome::Written(CompactStats {
            input_frames: self.input_frames,
            kept_frames: self.kept_frames,
        }))
    }
}

fn write_header<W: std::io::Write>(writer: &mut WebmWriter<W>, probe: &Probe) -> anyhow::Result<()> {
    let codec_id = match probe.codec {
        VpxCodec::VP8 => "V_VP8",
        VpxCodec::VP9 => "V_VP9",
    };
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
            MatroskaSpec::FlagLacing(0),
            MatroskaSpec::CodecID(codec_id.to_owned()),
            MatroskaSpec::Video(Master::Full(vec![
                MatroskaSpec::PixelWidth(u64::from(probe.width)),
                MatroskaSpec::PixelHeight(u64::from(probe.height)),
            ])),
        ]),
    )])))?;
    Ok(())
}

fn copy_luma(image: &VpxImage<'_>, out: &mut [u8]) -> anyhow::Result<()> {
    let planes = image.i420_planes().context("decoded picture is not I420")?;
    let width = planes.y.width();
    for (row, out_row) in planes.y.rows().zip(out.chunks_exact_mut(width)) {
        out_row.copy_from_slice(&row[..width]);
    }
    Ok(())
}

/// Returns true when any 8x8 block's mean absolute luma difference exceeds [`CHANGE_THRESHOLD`].
fn picture_changed(previous: &[u8], current: &[u8], width: usize) -> bool {
    let height = current.len() / width;
    for block_y in (0..height).step_by(BLOCK_SIZE) {
        let rows = block_y..(block_y + BLOCK_SIZE).min(height);
        for block_x in (0..width).step_by(BLOCK_SIZE) {
            let columns = block_x..(block_x + BLOCK_SIZE).min(width);
            let mut sum = 0u32;
            for y in rows.clone() {
                let line = y * width;
                let previous = &previous[line + columns.start..line + columns.end];
                let current = &current[line + columns.start..line + columns.end];
                sum += previous
                    .iter()
                    .zip(current)
                    .map(|(a, b)| u32::from(a.abs_diff(*b)))
                    .sum::<u32>();
            }
            let pixels = u32::try_from(rows.len() * columns.len()).expect("a block has at most 64 pixels");
            if sum > CHANGE_THRESHOLD * pixels {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picture(width: usize, height: usize, value: u8) -> Vec<u8> {
        vec![value; width * height]
    }

    #[test]
    fn identical_pictures_are_unchanged() {
        let a = picture(64, 48, 100);
        assert!(!picture_changed(&a, &a, 64));
    }

    #[test]
    fn noise_below_threshold_is_unchanged() {
        let a = picture(64, 48, 100);
        let mut b = a.clone();
        for (index, pixel) in b.iter_mut().enumerate() {
            *pixel = if index % 2 == 0 { 110 } else { 90 };
        }
        assert!(!picture_changed(&a, &b, 64));
    }

    #[test]
    fn one_changed_block_counts() {
        let a = picture(64, 48, 100);
        let mut b = a.clone();
        // A single 8x8 block in the bottom-right corner, like a clock's seconds digit.
        for y in 40..48 {
            for x in 56..64 {
                b[y * 64 + x] = 200;
            }
        }
        assert!(picture_changed(&a, &b, 64));
    }

    #[test]
    fn partial_edge_block_counts() {
        // 66x50 leaves 2-pixel-wide/high blocks on the right and bottom edges.
        let a = picture(66, 50, 100);
        let mut b = a.clone();
        b[49 * 66 + 65] = 255;
        b[49 * 66 + 64] = 255;
        assert!(picture_changed(&a, &b, 66));
    }
}
