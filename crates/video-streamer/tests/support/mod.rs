#![allow(dead_code)]

use std::io::Cursor;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as _;
use futures::{Sink, Stream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore, broadcast, mpsc, oneshot};
use tokio_util::bytes::Bytes;
use transport::{WsReadMsg, WsStream};
use webm_iterable::WebmIterator;
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Master, MatroskaSpec};

pub(crate) struct InMemoryWs {
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

pub(crate) fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

pub(crate) fn global_stream_test_semaphore() -> &'static Semaphore {
    static SEM: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(1))
}

pub(crate) fn asset_path(file_name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::canonicalize(manifest_dir.join("testing-assets").join(file_name))
        .unwrap_or_else(|e| panic!("failed to resolve asset path: {e:#}"))
}

pub(crate) fn maybe_init_xmf() -> bool {
    use cadeau::xmf;

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

pub(crate) fn extract_cluster_timestamps(webm_bytes: &[u8]) -> anyhow::Result<Vec<u64>> {
    let mut itr = WebmIterator::new(Cursor::new(webm_bytes), &[]);
    let mut saw_cluster = false;
    let mut saw_timestamp = false;
    let mut in_cluster = false;
    let mut timestamps = Vec::<u64>::new();

    for tag in &mut itr {
        match tag {
            Ok(MatroskaSpec::Cluster(Master::Start)) => {
                saw_cluster = true;
                in_cluster = true;
            }
            Ok(MatroskaSpec::Cluster(Master::End)) => {
                in_cluster = false;
            }
            Ok(MatroskaSpec::Timestamp(ts)) => {
                if in_cluster {
                    saw_timestamp = true;
                    timestamps.push(ts);
                }
            }
            Ok(_) => {}
            Err(TagIteratorError::UnexpectedEOF { .. }) => break,
            Err(_) => break,
        }
    }

    if saw_cluster && saw_timestamp {
        Ok(timestamps)
    } else {
        Ok(Vec::new())
    }
}

pub(crate) fn extract_block_absolute_timestamps_ms(webm_bytes: &[u8]) -> anyhow::Result<Vec<i64>> {
    use std::convert::TryInto as _;

    let mut itr = WebmIterator::new(Cursor::new(webm_bytes), &[]);
    let mut in_cluster = false;
    let mut current_cluster_ts: Option<u64> = None;
    let mut out = Vec::<i64>::new();

    for tag in &mut itr {
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
                let cluster_ts_i64 = i64::try_from(cluster_ts).context("cluster timestamp does not fit in i64")?;
                out.push(cluster_ts_i64 + i64::from(simple_block.timestamp));
            }
            Ok(_) => {}
            Err(TagIteratorError::UnexpectedEOF { .. }) => break,
            Err(_) => break,
        }
    }

    Ok(out)
}

pub(crate) fn extract_first_last_block_absolute_timestamps_ms_from_reader<R: std::io::Read>(
    reader: R,
) -> anyhow::Result<(Option<i64>, Option<i64>, u64)> {
    use std::convert::TryInto as _;

    let mut itr = WebmIterator::new(reader, &[]);
    let mut in_cluster = false;
    let mut current_cluster_ts: Option<u64> = None;
    let mut first: Option<i64> = None;
    let mut last: Option<i64> = None;
    let mut count: u64 = 0;

    for tag in &mut itr {
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
                let cluster_ts_i64 = i64::try_from(cluster_ts).context("cluster timestamp does not fit in i64")?;
                let abs = cluster_ts_i64 + i64::from(simple_block.timestamp);
                first.get_or_insert(abs);
                last = Some(abs);
                count += 1;
            }
            Ok(_) => {}
            Err(TagIteratorError::UnexpectedEOF { .. }) => break,
            Err(_) => break,
        }
    }

    Ok((first, last, count))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LiveWriteConfig {
    pub(crate) chunk_size: usize,
    pub(crate) delay: Duration,
    pub(crate) pause_after_bytes: Option<u64>,
    pub(crate) pause: Duration,
    pub(crate) notify_every_n_writes: usize,
    pub(crate) initial_burst_bytes: u64,
}

impl Default for LiveWriteConfig {
    fn default() -> Self {
        Self {
            chunk_size: 64 * 1024,
            delay: Duration::from_millis(15),
            pause_after_bytes: None,
            pause: Duration::from_secs(0),
            notify_every_n_writes: 1,
            initial_burst_bytes: 0,
        }
    }
}

#[derive(Debug)]
pub(crate) struct StreamHarness {
    pub(crate) client_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub(crate) server_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub(crate) shutdown: Arc<Notify>,
    pub(crate) stream_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    pub(crate) writer_task: tokio::task::JoinHandle<std::io::Result<()>>,
}

pub(crate) fn unique_temp_dir(prefix: &str) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{now}", std::process::id()))
}

pub(crate) async fn spawn_live_file_writer(
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
    let mut dest_file = dst_opts
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
                && cfg
                    .pause_after_bytes
                    .is_some_and(|threshold| total_written >= threshold)
                && cfg.pause > Duration::from_secs(0)
            {
                paused = true;
                tokio::time::sleep(cfg.pause).await;
            }

            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            dest_file.write_all(&buf[..n]).await?;
            dest_file.flush().await?;
            total_written += n as u64;
            writes += 1;

            if cfg.notify_every_n_writes != 0 && writes.is_multiple_of(cfg.notify_every_n_writes) {
                let _ = written_tx.send(());
            }

            if cfg.delay > Duration::from_secs(0)
                && (cfg.initial_burst_bytes == 0 || total_written >= cfg.initial_burst_bytes)
            {
                tokio::time::sleep(cfg.delay).await;
            }
        }

        let _ = written_tx.send(());
        Ok(())
    })
}

pub(crate) async fn spawn_stream_harness(
    asset: PathBuf,
    write_cfg: LiveWriteConfig,
    encoder_threads: usize,
) -> StreamHarness {
    spawn_stream_harness_delayed_start(asset, write_cfg, encoder_threads, Duration::from_secs(0)).await
}

pub(crate) async fn spawn_stream_harness_delayed_start(
    asset: PathBuf,
    write_cfg: LiveWriteConfig,
    encoder_threads: usize,
    start_after: Duration,
) -> StreamHarness {
    let tmp_dir = unique_temp_dir("video-streamer-webm_stream_harness");
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let tmp_webm_path = tmp_dir.join("live_input.webm");

    let (written_tx, _) = broadcast::channel::<()>(16);
    let writer_task = spawn_live_file_writer(asset, tmp_webm_path.clone(), written_tx.clone(), write_cfg).await;

    if start_after > Duration::from_secs(0) {
        tokio::time::sleep(start_after).await;
    }

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
                encoder_threads: video_streamer::config::CpuCount::new(encoder_threads),
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

pub(crate) fn parse_server_message(msg: &[u8]) -> (u8, &[u8]) {
    let Some((type_code, payload)) = msg.split_first() else {
        panic!("received empty server message");
    };
    (*type_code, payload)
}

pub(crate) async fn recv_server_message(
    server_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    tokio::time::timeout(timeout, server_rx.recv()).await.ok().flatten()
}

pub(crate) async fn shutdown_and_join(h: StreamHarness) {
    shutdown_and_join_with_timeout(h, Duration::from_secs(20)).await;
}

pub(crate) async fn shutdown_and_join_with_timeout(h: StreamHarness, timeout: Duration) {
    h.shutdown.notify_waiters();
    drop(h.client_tx);

    let mut stream_task = h.stream_task;
    match tokio::time::timeout(timeout, &mut stream_task).await {
        Ok(joined) => {
            joined
                .expect("webm_stream task panicked")
                .unwrap_or_else(|e| panic!("webm_stream returned error: {e:#}"));
        }
        Err(_) => {
            stream_task.abort();
        }
    }

    let _ = h.writer_task.await;
}
