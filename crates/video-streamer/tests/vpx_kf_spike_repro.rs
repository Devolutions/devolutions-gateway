use std::time::Instant;

use cadeau::xmf::vpx::{VpxDecoder, VpxEncoder};

mod support;
use support::*;

mod common;
use common::vpx_kf_spike::*;

const VPX_EFLAG_FORCE_KF: u32 = 0x00000001;

#[test]
#[ignore]
/// Minimal VPX-only reproduction of the production "progress stall" symptom.
///
/// What this test is checking:
/// - Given an uncued, non-seekable WebM, the streamer "attaches" at ~20s and must cut into the live stream.
/// - To make the cut decodable, it rolls back to the closest preceding keyframe (K_closest),
///   decodes K_closest..T20 to establish reference state, then force-keyframe re-encodes frames from T20 onward.
/// - The performance regression we want to reproduce is that encoding becomes extremely slow after some number
///   of consecutive force-keyframes, which makes wall clock advance while output timeline barely advances.
///
/// How this test checks it:
/// - Parses WebM tags to locate T20s and K_closest using Cluster/Timestamp + Block timestamps.
/// - Decodes frames from K_closest..T20 (decode-only warmup).
/// - Then decodes+encodes every subsequent frame as a keyframe, logging per-second samples and slow encodes.
///
/// References:
/// - [WebM: Muxing Guidelines][webm-muxing-guidelines]
/// - [Matroska: SimpleBlock][matroska-simpleblock]
///
/// [webm-muxing-guidelines]: https://www.webmproject.org/docs/container/#muxing-guidelines
/// [matroska-simpleblock]: https://www.matroska.org/technical/elements.html#simpleblock
fn vpx_force_kf_spike_min_repro_attach_20s() {
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let asset = asset_path("uncued-recording.webm");
    let cut_at_ms = 20_000u64;
    let end_ms = 26_000u64;
    let threads: u32 = 20;

    let (cfg, frames) = read_headers_and_frames_until(&asset, end_ms)
        .unwrap_or_else(|e| panic!("failed to read frames from {}: {e:#}", asset.display()));
    let (key_idx, t20_idx) = find_cut_indices(&frames, cut_at_ms).expect("failed to find cut indices");

    tracing::info!(
        prefix = "[LibVPx-Performance-Hypothesis]",
        asset = %asset.display(),
        width = cfg.width,
        height = cfg.height,
        codec = ?cfg.codec,
        threads,
        frames_total = frames.len(),
        key_idx,
        t20_idx,
        key_abs_ms = frames[key_idx].abs_ms,
        t20_abs_ms = frames[t20_idx].abs_ms,
        "KF spike repro setup"
    );

    let mut decoder = VpxDecoder::builder()
        .threads(threads)
        .width(cfg.width)
        .height(cfg.height)
        .codec(cfg.codec)
        .build()
        .expect("build decoder");

    let mut encoder = VpxEncoder::builder()
        .timebase_num(1)
        .timebase_den(1000)
        .codec(cfg.codec)
        .width(cfg.width)
        .height(cfg.height)
        .threads(threads)
        .bitrate(256 * 1024)
        .build()
        .expect("build encoder");

    let started_at = Instant::now();

    for (i, f) in frames.iter().enumerate().take(t20_idx).skip(key_idx) {
        decoder
            .decode(&f.data)
            .unwrap_or_else(|e| panic!("decode warmup failed at idx={i}: {e:#}"));
        let _ = decoder
            .next_frame()
            .unwrap_or_else(|e| panic!("next_frame warmup failed at idx={i}: {e:#}"));
    }

    let mut frames_encoded: u64 = 0;
    let mut max_encode_ms: u64 = 0;
    let mut last_logged_sec: Option<u64> = None;

    for (i, f) in frames.iter().enumerate().skip(t20_idx) {
        let decode_started_at = Instant::now();
        decoder
            .decode(&f.data)
            .unwrap_or_else(|e| panic!("decode failed at idx={i} abs_ms={}: {e:#}", f.abs_ms));
        let image = decoder
            .next_frame()
            .unwrap_or_else(|e| panic!("next_frame failed at idx={i} abs_ms={}: {e:#}", f.abs_ms));
        let decode_ms = u64::try_from(decode_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);

        let encode_started_at = Instant::now();
        let pts = i64::try_from(f.abs_ms).unwrap_or(i64::MAX);
        encoder
            .encode_frame(&image, pts, 30, VPX_EFLAG_FORCE_KF)
            .unwrap_or_else(|e| panic!("encode_frame failed at idx={i} abs_ms={}: {e:#}", f.abs_ms));
        let encode_ms = u64::try_from(encode_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        max_encode_ms = max_encode_ms.max(encode_ms);
        frames_encoded += 1;

        let _ = encoder
            .next_frame()
            .unwrap_or_else(|e| panic!("encoder.next_frame failed at idx={i} abs_ms={}: {e:#}", f.abs_ms));

        let sec = f.abs_ms / 1000;
        let should_sample = matches!(sec, 20..=26) && last_logged_sec != Some(sec);
        let wall_elapsed_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        if should_sample || encode_ms >= 50 {
            last_logged_sec = Some(sec);
            tracing::info!(
                prefix = "[LibVPx-Performance-Hypothesis]",
                idx = i,
                abs_ms = f.abs_ms,
                second = sec,
                frames_encoded,
                wall_elapsed_ms,
                decode_ms,
                encode_ms,
                max_encode_ms,
                force_kf = true,
                input_frame_bytes = f.data.len(),
                "KF spike sample"
            );
        }

        if end_ms <= f.abs_ms {
            break;
        }
    }

    tracing::info!(
        prefix = "[LibVPx-Performance-Hypothesis]",
        frames_encoded,
        max_encode_ms,
        wall_elapsed_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        "KF spike repro done"
    );
}
