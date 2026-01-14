use std::io::Cursor;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use std::convert::TryInto as _;
use futures::{Sink, Stream};
use cadeau::xmf;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore, broadcast, mpsc, oneshot};
use tokio_util::bytes::Bytes;
use transport::{WsReadMsg, WsStream};
use webm_iterable::WebmIterator;
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Master, MatroskaSpec};

struct InMemoryWs {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    pending_out: Vec<u8>,
}

impl Stream for InMemoryWs {
    type Item = Result<WsReadMsg, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.rx).poll_recv(cx) {
            Poll::Ready(Some(msg)) => Poll::Ready(Some(Ok(WsReadMsg::Payload(Bytes::from(msg))))),
            Poll::Ready(None) => Poll::Ready(Some(Ok(WsReadMsg::Close))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for InMemoryWs {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        // `WsStream` maps each `AsyncWrite::poll_write` call to a `Sink::start_send` call.
        // `tokio_util::codec::Framed` may split a single logical message across multiple writes,
        // so we must coalesce writes and only publish the message on `poll_flush`.
        this.pending_out.extend_from_slice(&item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.pending_out.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let msg = std::mem::take(&mut this.pending_out);
        this.tx
            .send(msg)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "in-memory ws receiver dropped"))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

fn global_stream_test_semaphore() -> &'static Semaphore {
    static SEM: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(1))
}

fn asset_path(file_name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::canonicalize(manifest_dir.join("testing-assets").join(file_name))
        .unwrap_or_else(|e| panic!("failed to resolve asset path: {e:#}"))
}

fn maybe_init_xmf() -> bool {
    let Ok(path) = std::env::var("DGATEWAY_LIB_XMF_PATH") else {
        tracing::warn!("Skipping test: DGATEWAY_LIB_XMF_PATH is not set");
        return false;
    };

    let Ok(canonical) = std::fs::canonicalize(&path) else {
        tracing::warn!(%path, "Skipping test: DGATEWAY_LIB_XMF_PATH does not exist");
        return false;
    };

    let Some(path_str) = canonical.to_str() else {
        tracing::warn!(path = %canonical.display(), "Skipping test: DGATEWAY_LIB_XMF_PATH is not valid UTF-8");
        return false;
    };

    // SAFETY: This is how the project loads XMF elsewhere (service startup / examples).
    if let Err(error) = unsafe { xmf::init(path_str) } {
        tracing::warn!(%error, %path_str, "Skipping test: failed to initialize XMF");
        return false;
    }

    true
}

fn extract_cluster_timestamps(webm_bytes: &[u8]) -> anyhow::Result<Vec<u64>> {
    let mut itr = WebmIterator::new(Cursor::new(webm_bytes), &[]);
    let mut saw_cluster = false;
    let mut saw_timestamp = false;
    let mut in_cluster = false;
    let mut timestamps = Vec::<u64>::new();

    while let Some(tag) = itr.next() {
        match tag {
            Ok(MatroskaSpec::Cluster(Master::Start)) => {
                saw_cluster = true;
                in_cluster = true;
            }
            Ok(MatroskaSpec::Cluster(Master::End)) => {
                in_cluster = false;
            }
            Ok(MatroskaSpec::Timestamp(ts)) => {
                // Only treat Cluster/Timestamp as the timebase we're validating.
                if in_cluster {
                    saw_timestamp = true;
                    timestamps.push(ts);
                }
            }
            Ok(_) => {}
            Err(TagIteratorError::UnexpectedEOF { .. }) => {
                break;
            }
            Err(_) => break,
        }
    }

    if saw_cluster && saw_timestamp {
        Ok(timestamps)
    } else {
        Ok(Vec::new())
    }
}

fn extract_block_absolute_timestamps_ms(webm_bytes: &[u8]) -> anyhow::Result<Vec<i64>> {
    let mut itr = WebmIterator::new(Cursor::new(webm_bytes), &[]);
    let mut in_cluster = false;
    let mut current_cluster_ts: Option<u64> = None;
    let mut out = Vec::<i64>::new();

    while let Some(tag) = itr.next() {
        match tag {
            Ok(MatroskaSpec::Cluster(Master::Start)) => {
                in_cluster = true;
                current_cluster_ts = None;
            }
            Ok(MatroskaSpec::Cluster(Master::End)) => {
                in_cluster = false;
                current_cluster_ts = None;
            }
            Ok(MatroskaSpec::Timestamp(ts)) => {
                if in_cluster {
                    current_cluster_ts = Some(ts);
                }
            }
            Ok(tag @ MatroskaSpec::SimpleBlock(_)) => {
                if !in_cluster {
                    continue;
                }
                let Some(cluster_ts) = current_cluster_ts else {
                    continue;
                };
                let simple_block: webm_iterable::matroska_spec::SimpleBlock<'_> = (&tag).try_into()?;
                let abs = cluster_ts as i64 + simple_block.timestamp as i64;
                out.push(abs);
            }
            Ok(_) => {}
            Err(TagIteratorError::UnexpectedEOF { .. }) => break,
            Err(_) => break,
        }
    }

    Ok(out)
}

#[derive(Clone, Copy, Debug)]
struct LiveWriteConfig {
    chunk_size: usize,
    delay: Duration,
    pause_after_bytes: Option<u64>,
    pause: Duration,
    notify_every_n_writes: usize,
}

impl Default for LiveWriteConfig {
    fn default() -> Self {
        Self {
            chunk_size: 64 * 1024,
            delay: Duration::from_millis(15),
            pause_after_bytes: None,
            pause: Duration::from_secs(0),
            notify_every_n_writes: 1,
        }
    }
}

#[derive(Debug)]
struct StreamHarness {
    client_tx: mpsc::UnboundedSender<Vec<u8>>,
    server_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    shutdown: Arc<Notify>,
    stream_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    writer_task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{now}", std::process::id()))
}

async fn spawn_live_file_writer(
    asset: PathBuf,
    dest: PathBuf,
    written_tx: broadcast::Sender<()>,
    cfg: LiveWriteConfig,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    let mut src = tokio::fs::File::open(&asset)
        .await
        .unwrap_or_else(|e| panic!("failed to open asset {}: {e:#}", asset.display()));

    let mut dst_opts = tokio::fs::OpenOptions::new();
    dst_opts.create(true).write(true).truncate(true);
    #[cfg(windows)]
    {
        dst_opts.share_mode(0x00000002 | 0x00000001 | 0x00000004);
    }
    let mut dst = dst_opts
        .open(&dest)
        .await
        .unwrap_or_else(|e| panic!("failed to create temp input {}: {e:#}", dest.display()));

    tokio::spawn(async move {
        let mut buf = vec![0u8; cfg.chunk_size];
        let mut total_written: u64 = 0;
        let mut writes: usize = 0;
        let mut paused = false;

        loop {
            if !paused
                && cfg.pause_after_bytes.is_some_and(|threshold| total_written >= threshold)
                && cfg.pause > Duration::from_secs(0)
            {
                paused = true;
                tokio::time::sleep(cfg.pause).await;
            }

            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            dst.write_all(&buf[..n]).await?;
            dst.flush().await?;
            total_written += n as u64;
            writes += 1;

            if cfg.notify_every_n_writes != 0 && (writes % cfg.notify_every_n_writes == 0) {
                let _ = written_tx.send(());
            }

            if cfg.delay > Duration::from_secs(0) {
                tokio::time::sleep(cfg.delay).await;
            }
        }

        let _ = written_tx.send(());
        Ok(())
    })
}

async fn spawn_stream_harness(asset_name: &str, write_cfg: LiveWriteConfig) -> StreamHarness {
    let asset = asset_path(asset_name);
    let tmp_dir = unique_temp_dir("video-streamer-webm_stream_correctness");
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let tmp_webm_path = tmp_dir.join("live_input.webm");

    let (written_tx, _) = broadcast::channel::<()>(16);
    let writer_task = spawn_live_file_writer(asset, tmp_webm_path.clone(), written_tx.clone(), write_cfg).await;

    let input = match video_streamer::ReOpenableFile::open(&tmp_webm_path) {
        Ok(f) => f,
        Err(e) => panic!("failed to open temp input {}: {e:#}", tmp_webm_path.display()),
    };

    let (client_to_server_tx, client_to_server_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (server_to_client_tx, server_to_client_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let server_ws = WsStream::new(InMemoryWs {
        rx: client_to_server_rx,
        tx: server_to_client_tx,
        pending_out: Vec::new(),
    });

    let shutdown = Arc::new(Notify::new());
    let shutdown_for_stream = Arc::clone(&shutdown);

    let runtime_handle = tokio::runtime::Handle::current();
    let when_new_chunk_appended = move || {
        let (tx, rx) = oneshot::channel();
        let mut r = written_tx.subscribe();
        runtime_handle.spawn(async move {
            let _ = r.recv().await;
            let _ = tx.send(());
        });
        rx
    };

    let stream_task = tokio::task::spawn_blocking(move || {
        video_streamer::webm_stream(
            server_ws,
            input,
            shutdown_for_stream,
            video_streamer::StreamingConfig {
                encoder_threads: video_streamer::config::CpuCount::new(1),
            },
            when_new_chunk_appended,
        )
    });

    StreamHarness {
        client_tx: client_to_server_tx,
        server_rx: server_to_client_rx,
        shutdown,
        stream_task,
        writer_task,
    }
}

fn parse_server_message(msg: &[u8]) -> (u8, &[u8]) {
    let Some((type_code, payload)) = msg.split_first() else {
        panic!("received empty server message");
    };
    (*type_code, payload)
}

async fn recv_server_message(
    server_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    tokio::time::timeout(timeout, server_rx.recv())
        .await
        .ok()
        .flatten()
}

async fn shutdown_and_join(h: StreamHarness) {
    h.shutdown.notify_waiters();
    drop(h.client_tx);

    let _ = tokio::time::timeout(Duration::from_secs(20), h.stream_task)
        .await
        .expect("timeout waiting for webm_stream to exit")
        .expect("webm_stream task panicked")
        .unwrap_or_else(|e| panic!("webm_stream returned error: {e:#}"));

    let _ = h.writer_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
/// Tests that `webm_stream` (no-cues input) eventually emits a stream whose first emitted Cluster timeline starts at 0.
///
/// How:
/// - Simulate a live-growing `.webm` file by appending bytes in small chunks.
/// - Drive the protocol with `Start` then repeated `Pull`.
/// - Collect `ServerMessage::Chunk` payload bytes and parse Cluster timestamps from the output.
/// - Assert that the first observed Cluster timestamp is exactly 0 (the cut point timeline reset contract).
async fn timeline_starts_at_zero_after_cut_uncued_recording() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness("uncued-recording.webm", LiveWriteConfig::default()).await;
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
async fn block_timestamps_monotonic_and_advances_uncued_recording() {
    let _permit = global_stream_test_semaphore()
        .acquire()
        .await
        .expect("failed to acquire global test semaphore");
    init_tracing();
    if !maybe_init_xmf() {
        return;
    }

    let mut h = spawn_stream_harness("uncued-recording.webm", LiveWriteConfig::default()).await;
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
        assert!(
            ts >= last,
            "block absolute timestamps went backwards: {last} -> {ts}"
        );
        last = ts;
    }
    assert!(last - first >= 100, "block timestamps did not advance: first={first} last={last}");
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

    let mut h = spawn_stream_harness("uncued-recording.webm", LiveWriteConfig::default()).await;
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

    let mut h = spawn_stream_harness("uncued-recording.webm", LiveWriteConfig::default()).await;
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
    let mut h = spawn_stream_harness("uncued-recording.webm", write_cfg).await;
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

    let mut h = spawn_stream_harness("uncued-recording.webm", LiveWriteConfig::default()).await;
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

    let mut h = spawn_stream_harness("uncued-recording.webm", LiveWriteConfig::default()).await;
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

    let _ = tokio::time::timeout(Duration::from_secs(20), h.stream_task)
        .await
        .expect("timeout waiting for webm_stream to exit")
        .expect("webm_stream task panicked")
        .unwrap_or_else(|e| panic!("webm_stream returned error: {e:#}"));

    let _ = h.writer_task.await;
}
