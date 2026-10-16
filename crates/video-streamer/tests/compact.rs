use std::path::{Path, PathBuf};

use cadeau::xmf::recorder::Recorder;
use video_streamer::{CompactOutcome, SkipReason, compact_webm};

mod support;
use support::*;

const WIDTH: usize = 320;
const HEIGHT: usize = 240;

/// Records a 1 fps BGRA picture sequence the way RDM's fixed-rate recorders do: one `UpdateFrame` + `Timeout` per
/// tick, so the encoder keeps refining an unchanged picture.
fn record(path: &Path, seconds: u64, mut picture_at: impl FnMut(u64) -> Vec<u8>) {
    let mut recorder = Recorder::builder(WIDTH, HEIGHT)
        .frame_rate(1)
        .current_time(0)
        .init(path)
        .expect("init recorder");
    for second in 0..seconds {
        recorder.set_current_time(second * 1000);
        let picture = picture_at(second);
        recorder
            .update_frame(&picture, 0, 0, WIDTH, HEIGHT, WIDTH * 4)
            .expect("update frame");
        recorder.timeout();
    }
    drop(recorder);
}

/// Dark text-like stripes on a light page, plus an optional filled rectangle.
fn page(with_box: bool) -> Vec<u8> {
    let mut picture = vec![0xF0; WIDTH * HEIGHT * 4];
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let text = (y / 6) % 3 == 0 && (x / 4) % 5 != 0 && x > 16 && x < WIDTH - 16;
            let in_box = with_box && (100..180).contains(&x) && (80..140).contains(&y);
            if text || in_box {
                let pixel = (y * WIDTH + x) * 4;
                picture[pixel..pixel + 3].copy_from_slice(&[0x20, 0x20, 0x20]);
            }
        }
    }
    picture
}

fn noise(seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..WIDTH * HEIGHT * 4)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = unique_temp_dir(name);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn decode_all(path: &Path) -> usize {
    use cadeau::xmf::vpx::{VpxCodec, VpxDecoder};
    use webm_iterable::WebmIterator;
    use webm_iterable::matroska_spec::{MatroskaSpec, SimpleBlock};

    let bytes = std::fs::read(path).expect("read output");
    let mut decoder = VpxDecoder::builder()
        .threads(1)
        .width(0)
        .height(0)
        .codec(VpxCodec::VP8)
        .build()
        .expect("build decoder");
    let mut frame_count = 0;
    for tag in WebmIterator::new(std::io::Cursor::new(bytes), &[]) {
        let Ok(tag @ MatroskaSpec::SimpleBlock(_)) = tag else {
            continue;
        };
        let block = SimpleBlock::try_from(&tag).expect("simple block");
        for frame in block.read_frame_data().expect("frame data") {
            decoder.decode(frame.data).expect("decode output frame");
            decoder.next_frame().expect("decoded picture");
            frame_count += 1;
        }
    }
    frame_count
}

#[test]
fn still_page_keeps_only_changed_frames_and_the_timeline() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let dir = temp_dir("video-streamer-compact-still");
    let input = dir.join("input.webm");
    let output = dir.join("output.webm");
    record(&input, 300, |second| page(second >= 120));

    let outcome = compact_webm(&input, &output).expect("compact");

    let CompactOutcome::Written(stats) = outcome else {
        panic!("unexpected outcome: {outcome:?}");
    };
    // First frame, the box appearing, and the last frame.
    assert!(stats.kept_frames <= 5, "{stats:?}");

    let input_bytes = std::fs::read(&input).expect("read input");
    let output_bytes = std::fs::read(&output).expect("read output");
    assert!(
        output_bytes.len() * 2 < input_bytes.len(),
        "{} vs {}",
        output_bytes.len(),
        input_bytes.len()
    );

    let input_timestamps = extract_block_absolute_timestamps_ms(&input_bytes).expect("input timestamps");
    let output_timestamps = extract_block_absolute_timestamps_ms(&output_bytes).expect("output timestamps");
    assert_eq!(input_timestamps.first(), output_timestamps.first());
    assert_eq!(input_timestamps.last(), output_timestamps.last());
    assert!(
        output_timestamps.iter().any(|&ts| (119_000..=121_000).contains(&ts)),
        "the change at 120 s is missing: {output_timestamps:?}"
    );

    assert_eq!(decode_all(&output), output_timestamps.len());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn constant_change_is_not_compacted() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let dir = temp_dir("video-streamer-compact-noise");
    let input = dir.join("input.webm");
    let output = dir.join("output.webm");
    record(&input, 90, noise);

    let outcome = compact_webm(&input, &output).expect("compact");

    assert_eq!(outcome, CompactOutcome::Skipped(SkipReason::NotSmaller));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn missing_frames_are_skipped() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let dir = temp_dir("video-streamer-compact-empty");
    let input = dir.join("input.webm");
    let output = dir.join("output.webm");
    std::fs::write(&input, b"").expect("write input");

    let outcome = compact_webm(&input, &output).expect("compact");

    assert_eq!(outcome, CompactOutcome::Skipped(SkipReason::NoFrames));

    let _ = std::fs::remove_dir_all(dir);
}
