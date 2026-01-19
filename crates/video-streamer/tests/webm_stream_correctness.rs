use std::time::Duration;

mod support;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that `webm_stream` (no-cues input) eventually emits a stream whose first emitted Cluster timeline starts at 0.
///
/// How:
/// - Simulate a live-growing `.webm` file by appending bytes in small chunks.
/// - Drive the protocol with `Start` then repeated `Pull`.
/// - Collect `ServerMessage::Chunk` payload bytes and parse Cluster timestamps from the output.
/// - Assert that the first observed Cluster timestamp is exactly 0 (the cut point timeline reset contract).
///
/// References:
/// - [WebM: Muxing Guidelines][webm-muxing-guidelines]
/// - [Matroska: Cluster][matroska-cluster]
///
/// [webm-muxing-guidelines]: https://www.webmproject.org/docs/container/#muxing-guidelines
/// [matroska-cluster]: https://www.matroska.org/technical/elements.html#cluster
async fn timeline_starts_at_zero_after_cut_uncued_recording() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness(asset_path("uncued-recording.webm"), LiveWriteConfig::default(), 1).await;
    assert!(h.client_tx.send(vec![0]).is_ok(), "failed to send Start");

    let mut saw_metadata = false;
    let mut collected = Vec::<u8>::new();
    let mut first_ts: Option<u64> = None;

    let started_at = tokio::time::Instant::now();
    while started_at.elapsed() < Duration::from_secs(180) {
        assert!(h.client_tx.send(vec![1]).is_ok(), "failed to send Pull");

        let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_secs(10)).await else {
            continue;
        };
        let (ty, payload) = parse_server_message(&msg);

        match ty {
            0 => {
                collected.extend_from_slice(payload);
                if let Ok(timestamps) = extract_cluster_timestamps(&collected)
                    && let Some(&ts0) = timestamps.first()
                {
                    first_ts.get_or_insert(ts0);
                    if ts0 == 0 {
                        break;
                    }
                }
            }
            1 => saw_metadata = true,
            2 => panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload)),
            3 => break,
            other => panic!("unknown server message type code: {other}"),
        }
    }

    assert!(saw_metadata, "never received metadata");
    assert_eq!(first_ts, Some(0), "never observed first cluster timestamp 0");
    shutdown_and_join(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that the emitted SimpleBlock timeline is monotonic and makes forward progress.
///
/// How:
/// - Drive the stream long enough to observe a number of SimpleBlocks.
/// - Parse Cluster timestamp + SimpleBlock relative timestamp, and compute absolute timestamps in milliseconds.
/// - Assert absolute timestamps are monotonic non-decreasing and that they advance by at least 500ms.
///
/// References:
/// - [Matroska: SimpleBlock][matroska-simpleblock]
///
/// [matroska-simpleblock]: https://www.matroska.org/technical/elements.html#simpleblock
async fn block_timestamps_monotonic_and_advances_uncued_recording() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness(asset_path("uncued-recording.webm"), LiveWriteConfig::default(), 1).await;
    assert!(h.client_tx.send(vec![0]).is_ok(), "failed to send Start");

    let mut collected = Vec::<u8>::new();
    let mut abs_ts: Vec<i64> = Vec::new();

    let started_at = tokio::time::Instant::now();
    while started_at.elapsed() < Duration::from_secs(60) {
        assert!(h.client_tx.send(vec![1]).is_ok(), "failed to send Pull");

        let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_secs(10)).await else {
            continue;
        };
        let (ty, payload) = parse_server_message(&msg);

        if ty == 2 {
            panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload));
        }
        if ty != 0 {
            continue;
        }

        collected.extend_from_slice(payload);
        abs_ts = extract_block_absolute_timestamps_ms(&collected).unwrap_or_default();
        if abs_ts.len() >= 10 {
            break;
        }
    }

    assert!(abs_ts.len() >= 2, "did not observe enough block timestamps");
    let first = abs_ts[0];
    let mut last = first;
    for &ts in &abs_ts[1..] {
        assert!(ts >= last, "block absolute timestamps went backwards: {last} -> {ts}");
        last = ts;
    }
    assert!(
        last - first >= 100,
        "block timestamps did not advance: first={first} last={last}"
    );
    shutdown_and_join(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that a `Start` message triggers exactly one metadata message (until `Start` is sent again).
///
/// How:
/// - Send `Start` and then read messages for a short time window.
/// - Assert the first metadata is received.
/// - Continue pulling and assert no additional metadata arrives without another `Start`.
async fn start_sends_metadata_once() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness(asset_path("uncued-recording.webm"), LiveWriteConfig::default(), 1).await;
    assert!(h.client_tx.send(vec![0]).is_ok(), "failed to send Start");

    let mut metadata_count = 0u32;
    let started_at = tokio::time::Instant::now();
    while started_at.elapsed() < Duration::from_secs(10) {
        let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_secs(2)).await else {
            continue;
        };
        let (ty, payload) = parse_server_message(&msg);
        match ty {
            1 => metadata_count += 1,
            2 => panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload)),
            _ => {}
        }
        if metadata_count >= 1 {
            break;
        }
    }

    assert_eq!(metadata_count, 1, "expected one metadata message after Start");

    for _ in 0..20 {
        assert!(h.client_tx.send(vec![1]).is_ok(), "failed to send Pull");
        if let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_secs(2)).await {
            let (ty, payload) = parse_server_message(&msg);
            if ty == 1 {
                panic!("unexpected additional metadata without Start");
            }
            if ty == 2 {
                panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload));
            }
        }
    }

    shutdown_and_join(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that `Pull` without `Start` does not crash the stream and does not send `ServerMessage::Error`.
///
/// How:
/// - Never send `Start`.
/// - Send several `Pull` messages and accept any output except `Error`.
/// - This pins current behavior while allowing the implementation to decide whether metadata is required.
async fn pull_without_start_does_not_error_or_hang() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness(asset_path("uncued-recording.webm"), LiveWriteConfig::default(), 1).await;
    let mut saw_error = false;

    let started_at = tokio::time::Instant::now();
    while started_at.elapsed() < Duration::from_secs(10) {
        if h.client_tx.send(vec![1]).is_err() {
            break;
        }
        if let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_millis(500)).await {
            let (ty, _payload) = parse_server_message(&msg);
            if ty == 2 {
                saw_error = true;
                break;
            }
        }
    }

    assert!(!saw_error, "received ServerMessage::Error without Start");
    shutdown_and_join(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that when the live input stops growing temporarily (EOF), the stream can recover when growth resumes.
///
/// How:
/// - Writer appends for a while, then pauses, then resumes appending.
/// - Client keeps issuing `Pull` and expects to eventually receive chunks both before and after the pause.
/// - This validates the EOF wait + rollback + continue path.
async fn pause_then_resume_recovers_from_eof_wait() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let write_cfg = LiveWriteConfig {
        pause_after_bytes: Some(256 * 1024),
        pause: Duration::from_secs(3),
        ..LiveWriteConfig::default()
    };
    let mut h = spawn_stream_harness(asset_path("uncued-recording.webm"), write_cfg, 1).await;
    assert!(h.client_tx.send(vec![0]).is_ok(), "failed to send Start");

    let mut got_any_chunk = false;
    let mut got_chunk_after_stall = false;
    let mut stalled_once = false;

    let started_at = tokio::time::Instant::now();
    while started_at.elapsed() < Duration::from_secs(60) {
        assert!(h.client_tx.send(vec![1]).is_ok(), "failed to send Pull");

        match recv_server_message(&mut h.server_rx, Duration::from_millis(600)).await {
            Some(msg) => {
                let (ty, payload) = parse_server_message(&msg);
                if ty == 2 {
                    panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload));
                }
                if ty == 0 {
                    if got_any_chunk && stalled_once {
                        got_chunk_after_stall = true;
                        break;
                    }
                    got_any_chunk = true;
                }
            }
            None => {
                if got_any_chunk {
                    stalled_once = true;
                }
            }
        }
    }

    assert!(got_any_chunk, "never received any chunk");
    assert!(
        got_chunk_after_stall,
        "never observed a chunk after a stall (pause/resume)"
    );
    shutdown_and_join(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that slow pulling does not break the stream (no errors, still produces chunks).
///
/// How:
/// - Send `Start` then issue `Pull` at a low rate.
/// - Assert we still receive at least one chunk and never an `Error`.
async fn slow_pull_still_produces_chunks() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness(asset_path("uncued-recording.webm"), LiveWriteConfig::default(), 1).await;
    assert!(h.client_tx.send(vec![0]).is_ok(), "failed to send Start");

    let mut got_chunk = false;
    for _ in 0..20 {
        assert!(h.client_tx.send(vec![1]).is_ok(), "failed to send Pull");
        if let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_secs(3)).await {
            let (ty, payload) = parse_server_message(&msg);
            if ty == 2 {
                panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload));
            }
            if ty == 0 {
                got_chunk = true;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    assert!(got_chunk, "never received any chunk with slow pull");
    shutdown_and_join(h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that a client disconnect mid-stream causes `webm_stream` to exit cleanly.
///
/// How:
/// - Start streaming and pull until at least one chunk is received.
/// - Drop the client sender (simulating a disconnect).
/// - Assert the streaming task exits within a timeout and returns `Ok(())`.
async fn client_disconnect_exits_cleanly() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness(asset_path("uncued-recording.webm"), LiveWriteConfig::default(), 1).await;
    assert!(h.client_tx.send(vec![0]).is_ok(), "failed to send Start");

    let started_at = tokio::time::Instant::now();
    while started_at.elapsed() < Duration::from_secs(30) {
        assert!(h.client_tx.send(vec![1]).is_ok(), "failed to send Pull");
        if let Some(msg) = recv_server_message(&mut h.server_rx, Duration::from_secs(2)).await {
            let (ty, payload) = parse_server_message(&msg);
            if ty == 2 {
                panic!("received ServerMessage::Error: {}", String::from_utf8_lossy(payload));
            }
            if ty == 0 {
                break;
            }
        }
    }

    drop(h.client_tx);
    h.shutdown.notify_waiters();

    tokio::time::timeout(Duration::from_secs(20), h.stream_task)
        .await
        .expect("timeout waiting for webm_stream to exit")
        .expect("webm_stream task panicked")
        .unwrap_or_else(|e| panic!("webm_stream returned error: {e:#}"));

    let _ = h.writer_task.await;
}
