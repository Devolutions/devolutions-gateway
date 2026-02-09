use std::io::{self, Write as _};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

fn verbose_bench_logging_enabled() -> bool {
    let value = std::env::var_os("VIDEO_STREAMER_BENCH_VERBOSE");
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

fn maybe_log_line(message: impl std::fmt::Display) {
    if !verbose_bench_logging_enabled() {
        return;
    }

    let _ = writeln!(io::stdout(), "{message}");
}

fn bench_reencode_first_500_tags(c: &mut Criterion) {
    let xmf_initialized = {
        let Ok(path) = std::env::var("DGATEWAY_LIB_XMF_PATH") else {
            maybe_log_line("DGATEWAY_LIB_XMF_PATH not set; skipping benchmarks");
            return;
        };

        // SAFETY: This is how the project loads XMF elsewhere.
        if let Err(e) = unsafe { cadeau::xmf::init(&path) } {
            maybe_log_line(format_args!(
                "failed to initialize XMF from DGATEWAY_LIB_XMF_PATH={path}: {e:#}"
            ));
            return;
        }

        true
    };
    if !xmf_initialized {
        return;
    }

    let input = {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir.join("testing-assets").join("uncued-recording.webm")
    };
    let mut group = c.benchmark_group("vpx_reencode");
    // Criterion requires sample_size >= 10.
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("reencode_first_500_tags_uncued_recording", |b| {
        // Keep per-iteration work bounded; Criterion may run many iterations per sample.
        let per_iter_deadline = Duration::from_millis(200);

        b.iter_custom(|iters| {
            let start = Instant::now();
            let mut tags_processed_total: u64 = 0;
            let mut bytes_written_total: u64 = 0;
            let mut frames_reencoded_total: u64 = 0;
            let mut input_media_span_ms_total: u64 = 0;
            let mut timed_out_any = false;

            for _ in 0..iters {
                let stats =
                    video_streamer::bench_support::reencode_first_tags_from_path_until_deadline(
                        &input,
                        video_streamer::StreamingConfig {
                            encoder_threads: video_streamer::config::CpuCount::new(1),
                            adaptive_frame_skip: false,
                        },
                        500,
                        per_iter_deadline,
                    )
                    .expect("reencode failed");

                tags_processed_total += stats.tags_processed as u64;
                bytes_written_total += stats.bytes_written as u64;
                frames_reencoded_total += stats.frames_reencoded as u64;
                input_media_span_ms_total += stats.input_media_span_ms as u64;
                timed_out_any |= stats.timed_out;

                criterion::black_box(stats);
            }

            let elapsed = start.elapsed();
            let elapsed_secs = elapsed.as_secs_f64().max(1e-9);
            let tags_per_sec = (tags_processed_total as f64) / elapsed_secs;
            let bytes_per_sec = (bytes_written_total as f64) / elapsed_secs;
            let frames_per_sec = (frames_reencoded_total as f64) / elapsed_secs;
            let media_ms_per_sec = (input_media_span_ms_total as f64) / elapsed_secs;

            maybe_log_line(format_args!(
                "[LibVPx-Performance-Hypothesis] iters={} elapsed_ms={} per_iter_deadline_ms={} frames_total={} frames_per_sec={:.2} input_media_ms_total={} input_media_ms_per_sec={:.2} tags_total={} tags_per_sec={:.2} bytes_total={} bytes_per_sec={:.2} timed_out_any={}",
                iters,
                elapsed.as_millis(),
                per_iter_deadline.as_millis(),
                frames_reencoded_total,
                frames_per_sec,
                input_media_span_ms_total,
                media_ms_per_sec,
                tags_processed_total,
                tags_per_sec,
                bytes_written_total,
                bytes_per_sec,
                timed_out_any,
            ));

            elapsed
        });
    });

    group.finish();
}

criterion_group!(benches, bench_reencode_first_500_tags);
criterion_main!(benches);
