use std::io::{BufReader, Write as _};
use std::time::Duration;

mod support;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
/// Reproduces the production performance symptom where wall clock advances but output media time barely moves.
///
/// This is intentionally a local-only perf reproduction:
/// - The input is an uncued, non-seekable WebM "recording" that grows over time.
/// - The stream attaches after 20s and cuts near the live tail (keyframe rollback + timeline reset).
/// - The test measures output timeline advancement using WebM timestamps (Cluster/Timestamp + SimpleBlock timestamp).
///
/// References:
/// - [WebM: Muxing Guidelines][webm-muxing-guidelines]
/// - [Matroska: Cluster][matroska-cluster]
/// - [Matroska: SimpleBlock][matroska-simpleblock]
///
/// [webm-muxing-guidelines]: https://www.webmproject.org/docs/container/#muxing-guidelines
/// [matroska-cluster]: https://www.matroska.org/technical/elements.html#cluster
/// [matroska-simpleblock]: https://www.matroska.org/technical/elements.html#simpleblock
async fn webm_stream_progress_stall_attach_at_20s() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let asset = asset_path("uncued-recording.webm");
    let asset_duration = Duration::from_secs(38);
    let start_after = Duration::from_secs(20);
    let run_for = Duration::from_secs(20);
    let encoder_threads = 20usize;

    let asset_len = std::fs::metadata(&asset)
        .unwrap_or_else(|e| panic!("failed to stat asset {}: {e:#}", asset.display()))
        .len();

    let write_cfg = {
        let mut cfg = LiveWriteConfig::default();
        let chunks = asset_len.div_ceil(cfg.chunk_size as u64).max(1);
        let asset_duration_ms = u64::try_from(asset_duration.as_millis()).unwrap_or(u64::MAX);
        let per_chunk_ms = asset_duration_ms.div_ceil(chunks).max(1);
        cfg.delay = Duration::from_millis(per_chunk_ms);
        cfg.initial_burst_bytes = 0;
        cfg.notify_every_n_writes = 1;
        cfg
    };

    let out_dir = unique_temp_dir("video-streamer-webm_stream_perf");
    std::fs::create_dir_all(&out_dir).expect("create perf output dir");
    let out_path = out_dir.join("shadow_output.webm");
    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&out_path)
        .unwrap_or_else(|e| panic!("failed to create output {}: {e:#}", out_path.display()));

    let mut h = spawn_stream_harness_delayed_start(asset.clone(), write_cfg, encoder_threads, start_after).await;
    assert!(h.client_tx.send(vec![0]).is_ok(), "failed to send Start");

    let started_at = tokio::time::Instant::now();
    let mut pulls_sent: u64 = 0;
    let mut chunks_received: u64 = 0;
    let mut bytes_received: u64 = 0;

    while started_at.elapsed() < run_for {
        assert!(h.client_tx.send(vec![1]).is_ok(), "failed to send Pull");
        pulls_sent += 1;

        let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_secs(3)).await else {
            continue;
        };
        let (ty, payload) = parse_server_message(&msg);
        match ty {
            0 => {
                out_file
                    .write_all(payload)
                    .unwrap_or_else(|e| panic!("failed to write output: {e:#}"));
                bytes_received += payload.len() as u64;
                chunks_received += 1;
            }
            1 => {}
            2 => panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload)),
            3 => break,
            _ => {}
        }
    }

    shutdown_and_join_with_timeout(h, Duration::from_secs(10)).await;
    out_file
        .flush()
        .unwrap_or_else(|e| panic!("failed to flush output {}: {e:#}", out_path.display()));
    drop(out_file);

    let wall_elapsed_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let file = std::fs::File::open(&out_path)
        .unwrap_or_else(|e| panic!("failed to open output {}: {e:#}", out_path.display()));
    let (first, last, blocks) = extract_first_last_block_absolute_timestamps_ms_from_reader(BufReader::new(file))
        .unwrap_or_else(|e| panic!("failed to parse output timestamps: {e:#}"));

    let media_advanced_ms = match (first, last) {
        (Some(f), Some(l)) => u64::try_from((l - f).max(0)).unwrap_or(0),
        _ => 0,
    };
    let ratio = if wall_elapsed_ms == 0 {
        0.0
    } else {
        media_advanced_ms as f64 / wall_elapsed_ms as f64
    };

    tracing::info!(
        prefix = "[LibVPx-Performance-Hypothesis]",
        asset = %asset.display(),
        out = %out_path.display(),
        encoder_threads,
        pulls_sent,
        chunks_received,
        bytes_received,
        blocks,
        wall_elapsed_ms,
        media_advanced_ms,
        realtime_ratio = ratio,
        "Perf reproduction summary"
    );

    assert!(
        ratio < 0.2,
        "did not reproduce progress stall: realtime_ratio={ratio} wall_elapsed_ms={wall_elapsed_ms} media_advanced_ms={media_advanced_ms}"
    );
}
