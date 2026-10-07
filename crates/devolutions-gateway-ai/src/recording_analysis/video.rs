//! Picks the screenshots of a video recording worth showing to the AI: the frames where the screen changed.
//!
//! The video is decoded with XMF and sampled at [`SAMPLES_PER_SECOND`]. A sample is compared with the previous one in
//! 16x16 tiles of a half-resolution gray image. Tiles that keep changing, such as a clock or a spinner, count as
//! animated and are ignored. A frame is kept at the start, once the screen settles after a change, and regularly while
//! a change goes on.
//! Only the current and the previous samples are held in memory, whatever the length of the video.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufReader, BufWriter};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use cadeau::xmf::vpx::{VpxCodec, VpxDecoder, VpxImage};
use camino::{Utf8Path, Utf8PathBuf};
use tokio_util::sync::CancellationToken;
use webm_iterable::WebmIterator;
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

/// Decoded samples per second of video.
const SAMPLES_PER_SECOND: u32 = 2;

const SAMPLE_INTERVAL_MS: u64 = 1000 / SAMPLES_PER_SECOND as u64;

/// Side of a tile, in pixels of the half-resolution gray image.
const TILE: usize = 16;

/// Mean absolute gray difference over which a tile counts as changed.
const TILE_DIFF: u32 = 3;

const TILE_PIXELS: u32 = 16 * 16;

/// Samples of history used to find animated tiles (10 s).
const ANIMATION_WINDOW: usize = 20;

/// A tile that changed in at least this many samples of the window is animated.
const ANIMATION_HITS: usize = 3;

/// A change ends after this many quiet samples (1 s).
const SETTLE_SAMPLES: usize = 2;

/// During a long change, one frame is kept every this many samples (3 s).
const KEEP_DURING_CHANGE: usize = 6;

/// Largest screenshot sent to the AI.
const MAX_WIDTH: usize = 1280;
const MAX_HEIGHT: usize = 720;

#[derive(Debug, thiserror::Error)]
pub(super) enum VideoError {
    #[error("video decoding is not available: XMF is not loaded")]
    DecoderUnavailable,
    #[error("{0}")]
    Invalid(String),
    #[error("failed to write a screenshot: {0}")]
    Write(io::Error),
    #[error("cancelled")]
    Cancelled,
}

/// A screenshot kept from a video, saved as `<id>.png` in the working files.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct KeptFrame {
    pub(super) id: String,
    /// Elapsed time since the start of the session.
    pub(super) offset: Duration,
}

pub(super) fn frame_path(workspace: &Utf8Path, id: &str) -> Utf8PathBuf {
    workspace.join(format!("{id}.png"))
}

/// Keeps the frames of the video at `path` where the screen changed, as PNG files in `workspace`.
///
/// `offset` is when the video starts in the session. `next_id` numbers the frames across the videos of a session.
/// The bytes read from the video are added to `read_bytes`.
pub(super) fn keep_changed_frames(
    path: &Utf8Path,
    offset: Duration,
    workspace: &Utf8Path,
    next_id: &mut usize,
    read_bytes: &Arc<AtomicU64>,
    cancel: &CancellationToken,
) -> Result<Vec<KeptFrame>, VideoError> {
    if !cadeau::xmf::is_init() {
        return Err(VideoError::DecoderUnavailable);
    }

    let file = super::open_counted(path, read_bytes)
        .map_err(|error| VideoError::Invalid(format!("failed to open the video: {error}")))?;
    let mut tags = WebmIterator::new(BufReader::new(file), &[MatroskaSpec::BlockGroup(Master::Start)]);
    tags.emit_master_end_when_eof(false);

    let mut keeper = Keeper {
        selector: FrameSelector::default(),
        offset,
        workspace,
        next_id,
        kept: Vec::new(),
        current: None,
    };
    let mut track = TrackInfo::default();
    let mut decoder: Option<VpxDecoder> = None;
    let mut cluster_time = None;
    let mut timestamp_scale_ns = 1_000_000u64;
    let mut next_sample_ms = 0u64;
    let mut previous: Option<(u64, Picture)> = None;

    for tag in &mut tags {
        if cancel.is_cancelled() {
            return Err(VideoError::Cancelled);
        }

        let tag = match tag {
            Ok(tag) => tag,
            // A recording cut short, such as after a crash, ends without its last element.
            Err(TagIteratorError::UnexpectedEOF { .. }) => break,
            Err(error) => return Err(VideoError::Invalid(format!("invalid WebM: {error}"))),
        };

        let block = match tag {
            MatroskaSpec::TimestampScale(scale) => {
                timestamp_scale_ns = scale.max(1);
                continue;
            }
            MatroskaSpec::CodecID(id) => {
                track.codec = Some(match id.as_str() {
                    "V_VP8" => VpxCodec::VP8,
                    "V_VP9" => VpxCodec::VP9,
                    other => return Err(VideoError::Invalid(format!("unsupported video codec {other}"))),
                });
                continue;
            }
            MatroskaSpec::PixelWidth(width) => {
                track.width = u32::try_from(width).ok();
                continue;
            }
            MatroskaSpec::PixelHeight(height) => {
                track.height = u32::try_from(height).ok();
                continue;
            }
            MatroskaSpec::Timestamp(time) => {
                cluster_time = Some(time);
                continue;
            }
            MatroskaSpec::SimpleBlock(data) => SimpleBlock::try_from(&data)
                .map_err(|error| VideoError::Invalid(format!("invalid block: {error}")))
                .and_then(|block| frame_of(block.timestamp, block.read_frame_data()))?,
            MatroskaSpec::BlockGroup(Master::Full(children)) => {
                let Some(raw) = children.iter().find_map(|child| match child {
                    MatroskaSpec::Block(raw) => Some(raw),
                    _ => None,
                }) else {
                    continue;
                };
                Block::try_from(raw)
                    .map_err(|error| VideoError::Invalid(format!("invalid block: {error}")))
                    .and_then(|block| frame_of(block.timestamp, block.read_frame_data()))?
            }
            _ => continue,
        };

        let Some(cluster_time) = cluster_time else {
            return Err(VideoError::Invalid("block before its cluster time".to_owned()));
        };

        let ticks = i64::try_from(cluster_time)
            .unwrap_or(i64::MAX)
            .saturating_add(i64::from(block.0));
        let pts_ms = u64::try_from(ticks).unwrap_or(0).saturating_mul(timestamp_scale_ns) / 1_000_000;

        let decoder = match &mut decoder {
            Some(decoder) => decoder,
            None => decoder.insert(track.decoder()?),
        };

        decoder
            .decode(&block.1)
            .map_err(|error| VideoError::Invalid(format!("failed to decode a frame: {error:?}")))?;

        // Exactly one call per decoded frame: XMF would hand back the same image again.
        let Ok(image) = decoder.next_frame() else {
            continue;
        };
        let picture = Picture::of(&image)?;

        // Every sample time before this frame shows the previous one.
        if let Some((_, shown)) = &previous {
            while next_sample_ms < pts_ms {
                keeper.sample(next_sample_ms, shown)?;
                next_sample_ms += SAMPLE_INTERVAL_MS;
            }
        } else {
            next_sample_ms = pts_ms;
        }

        previous = Some((pts_ms, picture));
    }

    if let Some((pts_ms, shown)) = &previous {
        // The last frame stays on screen until the end: it gets at least one sample.
        loop {
            keeper.sample(next_sample_ms, shown)?;
            if *pts_ms < next_sample_ms + SAMPLE_INTERVAL_MS {
                break;
            }
            next_sample_ms += SAMPLE_INTERVAL_MS;
        }

        keeper.finish(shown)?;
    }

    Ok(keeper.kept)
}

/// The time of a block relative to its cluster, and its frame.
fn frame_of(
    timestamp: i16,
    frames: Result<Vec<webm_iterable::matroska_spec::Frame<'_>>, webm_iterable::errors::WebmCoercionError>,
) -> Result<(i16, Vec<u8>), VideoError> {
    let frames = frames.map_err(|error| VideoError::Invalid(format!("invalid block: {error}")))?;

    match frames.as_slice() {
        [frame] => Ok((timestamp, frame.data.to_vec())),
        _ => Err(VideoError::Invalid("laced blocks are not supported".to_owned())),
    }
}

#[derive(Default)]
struct TrackInfo {
    codec: Option<VpxCodec>,
    width: Option<u32>,
    height: Option<u32>,
}

impl TrackInfo {
    fn decoder(&self) -> Result<VpxDecoder, VideoError> {
        let (Some(codec), Some(width), Some(height)) = (self.codec, self.width, self.height) else {
            return Err(VideoError::Invalid("video track without codec or size".to_owned()));
        };

        VpxDecoder::builder()
            .threads(2)
            .width(width)
            .height(height)
            .codec(codec)
            .build()
            .map_err(|error| VideoError::Invalid(format!("failed to start the video decoder: {error:?}")))
    }
}

/// A decoded frame, with its I420 planes copied out of the decoder.
struct Picture {
    width: usize,
    height: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

impl Picture {
    fn of(image: &VpxImage<'_>) -> Result<Self, VideoError> {
        let planes = image
            .i420_planes()
            .ok_or_else(|| VideoError::Invalid("decoded frame is not 8-bit I420".to_owned()))?;

        let copy = |plane: cadeau::xmf::vpx::VpxPlane<'_>| {
            let mut out = Vec::with_capacity(plane.width() * plane.height());
            for row in plane.rows() {
                out.extend_from_slice(&row[..plane.width()]);
            }
            out
        };

        Ok(Self {
            width: planes.y.width(),
            height: planes.y.height(),
            y: copy(planes.y),
            u: copy(planes.u),
            v: copy(planes.v),
        })
    }

    /// Every other luma pixel of every other row.
    fn half_gray(&self) -> Gray {
        let width = self.width / 2;
        let height = self.height / 2;
        let mut pixels = Vec::with_capacity(width * height);

        for row in self.y.chunks_exact(self.width).step_by(2).take(height) {
            pixels.extend(row.iter().step_by(2).take(width));
        }

        Gray { width, height, pixels }
    }

    /// Writes the picture as a PNG no larger than [`MAX_WIDTH`]x[`MAX_HEIGHT`], averaging the pixels it shrinks.
    ///
    /// Colors are read as BT.709 full range, which is what Gateway and RDM record.
    fn write_png(&self, path: &Utf8Path) -> io::Result<()> {
        // Shrink to fit both limits, keeping the aspect ratio.
        let (out_width, out_height) = if self.width * MAX_HEIGHT >= self.height * MAX_WIDTH {
            let out_width = self.width.min(MAX_WIDTH);
            (out_width, (self.height * out_width / self.width).max(1))
        } else {
            let out_height = self.height.min(MAX_HEIGHT);
            ((self.width * out_height / self.height).max(1), out_height)
        };
        let chroma_width = self.width.div_ceil(2);

        let mut rgb = Vec::with_capacity(out_width * out_height * 3);

        for out_y in 0..out_height {
            let y0 = out_y * self.height / out_height;
            let y1 = ((out_y + 1) * self.height / out_height).max(y0 + 1);

            for out_x in 0..out_width {
                let x0 = out_x * self.width / out_width;
                let x1 = ((out_x + 1) * self.width / out_width).max(x0 + 1);

                let (mut luma, mut cb, mut cr, mut count) = (0u32, 0u32, 0u32, 0u32);
                for y in y0..y1 {
                    for x in x0..x1 {
                        let chroma = (y / 2) * chroma_width + x / 2;
                        luma += u32::from(self.y[y * self.width + x]);
                        cb += u32::from(self.u[chroma]);
                        cr += u32::from(self.v[chroma]);
                        count += 1;
                    }
                }

                let luma = f64::from(luma) / f64::from(count);
                let cb = f64::from(cb) / f64::from(count) - 128.0;
                let cr = f64::from(cr) / f64::from(count) - 128.0;

                rgb.push(to_byte(luma + 1.5748 * cr));
                rgb.push(to_byte(luma - 0.1873 * cb - 0.4681 * cr));
                rgb.push(to_byte(luma + 1.8556 * cb));
            }
        }

        let out = BufWriter::new(File::create(path)?);
        let size = |value: usize| u32::try_from(value).map_err(io::Error::other);
        let mut encoder = png::Encoder::new(out, size(out_width)?, size(out_height)?);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::Fast);
        encoder
            .write_header()
            .and_then(|mut writer| writer.write_image_data(&rgb))
            .map_err(io::Error::other)
    }
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to 0..=255 first"
)]
fn to_byte(value: f64) -> u8 {
    value.round().clamp(0.0, 255.0) as u8
}

/// Writes the kept frames, numbering them across the videos of a session.
struct Keeper<'a> {
    selector: FrameSelector,
    offset: Duration,
    workspace: &'a Utf8Path,
    next_id: &'a mut usize,
    kept: Vec<KeptFrame>,
    /// The last sample, kept if a change is still going on when the video ends.
    current: Option<(u64, String)>,
}

impl Keeper<'_> {
    fn sample(&mut self, time_ms: u64, picture: &Picture) -> Result<(), VideoError> {
        let id = format!("F{:05}", *self.next_id);
        *self.next_id += 1;

        if self.selector.sample(picture.half_gray()) {
            self.keep(time_ms, &id, picture)?;
        }

        self.current = Some((time_ms, id));
        Ok(())
    }

    fn keep(&mut self, time_ms: u64, id: &str, picture: &Picture) -> Result<(), VideoError> {
        if self.kept.last().is_some_and(|last| last.id == id) {
            return Ok(());
        }

        picture
            .write_png(&frame_path(self.workspace, id))
            .map_err(VideoError::Write)?;
        self.kept.push(KeptFrame {
            id: id.to_owned(),
            offset: self.offset + Duration::from_millis(time_ms),
        });
        Ok(())
    }

    /// Keeps the last sample, which shows last, if the screen was still changing when the video ended.
    fn finish(&mut self, last: &Picture) -> Result<(), VideoError> {
        match self.current.take() {
            Some((time_ms, id)) if self.selector.in_change() => self.keep(time_ms, &id, last),
            _ => Ok(()),
        }
    }
}

/// Half-resolution gray image of a sample.
struct Gray {
    width: usize,
    height: usize,
    pixels: Vec<u8>,
}

/// Decides which samples of a video to keep, from their gray images, in order.
#[derive(Default)]
struct FrameSelector {
    previous: Option<Gray>,
    /// Changed tiles of the last samples, to find animated ones.
    history: VecDeque<Vec<bool>>,
    in_change: bool,
    change_samples: usize,
    quiet_samples: usize,
}

impl FrameSelector {
    /// Returns `true` when the sample is worth keeping.
    fn sample(&mut self, gray: Gray) -> bool {
        let Some(previous) = self.previous.replace(gray) else {
            // The first sample shows where the video starts.
            return true;
        };
        let gray = self.previous.as_ref().expect("just set");

        let active = if previous.width == gray.width && previous.height == gray.height {
            let changed = changed_tiles(&previous, gray);
            let animated = self.animated_tiles(changed.len(), gray.width / TILE);

            if self.history.len() == ANIMATION_WINDOW {
                self.history.pop_front();
            }
            let active = changed
                .iter()
                .zip(&animated)
                .any(|(&changed, &animated)| changed && !animated);
            self.history.push_back(changed);
            active
        } else {
            // A new screen size changes everything, and the old history no longer lines up.
            self.history.clear();
            true
        };

        if active {
            if !self.in_change {
                self.in_change = true;
                self.change_samples = 0;
            }
            self.change_samples += 1;
            self.quiet_samples = 0;
            return self.change_samples.is_multiple_of(KEEP_DURING_CHANGE);
        }

        if self.in_change {
            self.quiet_samples += 1;
            if self.quiet_samples >= SETTLE_SAMPLES {
                self.in_change = false;
                return true;
            }
        }

        false
    }

    /// Whether a change is still going on, so that the last sample should be kept.
    fn in_change(&self) -> bool {
        self.in_change
    }

    /// Tiles that changed in at least [`ANIMATION_HITS`] samples of the history, grown by one tile in every direction.
    fn animated_tiles(&self, tiles: usize, columns: usize) -> Vec<bool> {
        let mut hits = vec![0usize; tiles];
        for changed in self.history.iter().filter(|changed| changed.len() == tiles) {
            for (hits, &changed) in hits.iter_mut().zip(changed) {
                *hits += usize::from(changed);
            }
        }

        let animated: Vec<bool> = hits.iter().map(|&hits| hits >= ANIMATION_HITS).collect();
        let mut grown = animated.clone();

        if columns == 0 {
            return grown;
        }

        for (index, _) in animated.iter().enumerate().filter(|(_, animated)| **animated) {
            let (row, column) = (index / columns, index % columns);
            let rows = tiles / columns;

            for (neighbor_row, neighbor_column) in [
                (row.wrapping_sub(1), column),
                (row + 1, column),
                (row, column.wrapping_sub(1)),
                (row, column + 1),
            ] {
                if neighbor_row < rows && neighbor_column < columns {
                    grown[neighbor_row * columns + neighbor_column] = true;
                }
            }
        }

        grown
    }
}

/// Which 16x16 tiles changed between two gray images of the same size, row by row; partial tiles are ignored.
fn changed_tiles(before: &Gray, after: &Gray) -> Vec<bool> {
    let columns = after.width / TILE;
    let rows = after.height / TILE;
    let mut changed = Vec::with_capacity(columns * rows);

    for row in 0..rows {
        for column in 0..columns {
            let mut sum = 0u32;
            for y in row * TILE..(row + 1) * TILE {
                let start = y * after.width + column * TILE;
                for x in start..start + TILE {
                    sum += u32::from(before.pixels[x].abs_diff(after.pixels[x]));
                }
            }
            changed.push(sum > TILE_DIFF * TILE_PIXELS);
        }
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 16 tiles wide and 2 tiles high.
    const WIDTH: usize = 256;
    const HEIGHT: usize = 32;

    /// A gray image with the 16x16 tiles in `bright` set to white, row by row.
    fn screen(bright: &[usize]) -> Gray {
        let mut pixels = vec![0; WIDTH * HEIGHT];
        let columns = WIDTH / TILE;

        for &tile in bright {
            let (row, column) = (tile / columns, tile % columns);
            for y in row * TILE..(row + 1) * TILE {
                for x in column * TILE..(column + 1) * TILE {
                    pixels[y * WIDTH + x] = 255;
                }
            }
        }

        Gray {
            width: WIDTH,
            height: HEIGHT,
            pixels,
        }
    }

    /// Indexes of the kept samples.
    fn kept(samples: impl IntoIterator<Item = Gray>) -> Vec<usize> {
        let mut selector = FrameSelector::default();
        samples
            .into_iter()
            .enumerate()
            .filter_map(|(index, sample)| selector.sample(sample).then_some(index))
            .collect()
    }

    #[test]
    fn a_still_screen_keeps_only_its_first_frame() {
        assert_eq!(kept((0..20).map(|_| screen(&[]))), [0]);
    }

    #[test]
    fn a_change_keeps_the_frame_once_the_screen_settles() {
        let samples = [
            screen(&[]),
            screen(&[]),
            screen(&[1]),
            screen(&[1]),
            screen(&[1]),
            screen(&[1]),
        ];

        // The change is at 2; the screen is quiet at 3 and 4, so 4 is kept.
        assert_eq!(kept(samples), [0, 4]);
    }

    #[test]
    fn a_long_change_keeps_a_frame_every_three_seconds() {
        // Each sample lights a different tile, so every sample changes, and no tile changes often enough to count as
        // animated.
        let samples = (0..14).map(|index| screen(&[index]));

        assert_eq!(kept(samples), [0, 6, 12]);
    }

    #[test]
    fn a_blinking_tile_stops_counting_as_a_change() {
        // Tile 5 blinks every sample: after three changes it is animated and ignored.
        let samples = (0..12).map(|index| screen(if index % 2 == 0 { &[] } else { &[5] }));
        let kept = kept(samples);

        assert!(kept.len() <= 3, "{kept:?}");
        assert_eq!(kept[0], 0);
    }

    #[test]
    fn a_new_screen_size_is_a_change() {
        let small = Gray {
            width: 32,
            height: 32,
            pixels: vec![0; 32 * 32],
        };

        // Two size changes in a row, then the screen settles after two quiet samples.
        assert_eq!(
            kept([screen(&[]), small, screen(&[]), screen(&[]), screen(&[])]),
            [0, 4]
        );
    }

    #[test]
    fn small_differences_are_not_changes() {
        let mut nearly = screen(&[]);
        nearly.pixels.iter_mut().for_each(|pixel| *pixel = 2);

        assert_eq!(changed_tiles(&screen(&[]), &nearly), vec![false; 32]);
        assert_eq!(
            changed_tiles(&screen(&[]), &screen(&[3]))
                .iter()
                .filter(|changed| **changed)
                .count(),
            1
        );
    }

    fn picture(width: usize, height: usize) -> Picture {
        Picture {
            width,
            height,
            y: vec![128; width * height],
            u: vec![128; width.div_ceil(2) * height.div_ceil(2)],
            v: vec![128; width.div_ceil(2) * height.div_ceil(2)],
        }
    }

    fn png_size(png: &Utf8Path) -> (u32, u32) {
        let decoder = png::Decoder::new(BufReader::new(File::open(png).expect("png")));
        let reader = decoder.read_info().expect("PNG header");
        let info = reader.info();
        (info.width, info.height)
    }

    #[test]
    fn screenshots_shrink_to_fit_1280_by_720() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir = Utf8Path::from_path(dir.path()).expect("UTF-8");

        for ((width, height), expected) in [
            ((1920, 1080), (1280, 720)),
            ((3840, 2400), (1152, 720)),
            ((800, 600), (800, 600)),
        ] {
            let path = dir.join(format!("{width}x{height}.png"));
            picture(width, height).write_png(&path).expect("written");

            assert_eq!(png_size(&path), expected, "{width}x{height}");
        }
    }

    #[test]
    fn half_gray_takes_every_other_pixel() {
        let mut picture = picture(4, 2);
        picture.y = vec![10, 20, 30, 40, 50, 60, 70, 80];

        let gray = picture.half_gray();

        assert_eq!((gray.width, gray.height), (2, 1));
        assert_eq!(gray.pixels, [10, 30]);
    }
}
