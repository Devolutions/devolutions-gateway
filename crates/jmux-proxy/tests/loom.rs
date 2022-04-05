#![cfg(loom)]

use anyhow::Context as _;
use jmux_proxy::{
    ApiRequestReceiver, ApiRequestSender, DestinationUrl, JmuxApiRequest, JmuxApiResponse, JmuxConfig, JmuxProxy,
};
use loom::future::block_on;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread::spawn;
use mock_net::{TcpListener, TcpStream};
use slog::Drain as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

const BUFFER_CONTENTS: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

async fn echo_server(bind_addr: (&str, u16), counter: Arc<AtomicUsize>, logger: slog::Logger) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    slog::info!(logger, "Echo server listening on {}:{}", bind_addr.0, bind_addr.1);

    loop {
        let (mut socket, _) = listener.accept().await.context("Accept operation")?;

        let mut buf = [0; 256];

        counter.fetch_add(1, Ordering::AcqRel);

        loop {
            let n = socket.read(&mut buf).await.expect("failed to read data from socket");

            slog::debug!(logger, "Read {n}");

            if n == 0 {
                break;
            }

            socket
                .write_all(&buf[0..n])
                .await
                .expect("failed to write data to socket");
        }

        slog::debug!(logger, "Closed");
    }
}

async fn client(api_request_tx: ApiRequestSender, target: (&str, u16)) -> anyhow::Result<()> {
    let api_request_tx = api_request_tx.clone();

    let (api_rsp_tx, api_rsp_rx) = oneshot::channel();
    api_request_tx
        .send(JmuxApiRequest::OpenChannel {
            destination_url: DestinationUrl::new("tcp", target.0, target.1),
            api_response_tx: api_rsp_tx,
        })
        .await?;
    let id = if let Ok(JmuxApiResponse::Success { id }) = api_rsp_rx.await {
        id
    } else {
        anyhow::bail!("Couldn't open JMUX channel");
    };

    let (mut one, two) = tokio::io::duplex(256);
    api_request_tx
        .send(JmuxApiRequest::Start {
            id,
            stream: mock_net::TcpStream(two),
        })
        .await?;

    one.write_all(&BUFFER_CONTENTS).await?;

    let mut buf = [0u8; 10];

    one.read_exact(&mut buf).await?;

    assert_eq!(buf, BUFFER_CONTENTS);

    Ok(())
}

async fn client_side_jmux(
    api_request_rx: ApiRequestReceiver,
    server_addr: (&str, u16),
    logger: slog::Logger,
) -> anyhow::Result<()> {
    let jmux_stream = TcpStream::connect(server_addr).await?;
    let (jmux_reader, jmux_writer) = jmux_stream.into_split();

    JmuxProxy::new(Box::new(jmux_reader), Box::new(jmux_writer))
        .with_requester_api(api_request_rx)
        .with_logger(logger)
        .run()
        .await
}

async fn server_side_jmux(bind_addr: (&str, u16), logger: slog::Logger) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    slog::info!(logger, "JMUX server listening on {}:{}", bind_addr.0, bind_addr.1);

    let (socket, _) = listener.accept().await.context("Accept operation")?;
    let (reader, writer) = socket.into_split();

    JmuxProxy::new(Box::new(reader), Box::new(writer))
        .with_config(JmuxConfig::permissive())
        .with_logger(logger)
        .run()
        .await
}

#[test]
fn jmux_proxy() {
    loom::model(|| {
        let decorator = slog_term::PlainDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::CompactFormat::new(decorator).build().fuse();
        let async_drain = slog_async::Async::new(drain).build().fuse();
        let logger = slog::Logger::root(async_drain, slog::o!());

        let counter = Arc::new(AtomicUsize::new(0));

        spawn({
            let counter = counter.clone();
            let logger = logger.clone();
            move || {
                let fut1 = echo_server(("232.192.0.94", 42), counter.clone(), logger.clone());
                let fut2 = echo_server(("3.199.201.72", 666), counter, logger);
                let (res1, res2) = block_on(async { tokio::join!(fut1, fut2) });
                res1.expect("echo server 1");
                res2.expect("echo server 2");
            }
        });

        let (api_request_tx, api_request_rx) = mpsc::channel(3);

        spawn(move || {
            let jmux_server_addr = ("3.141.0.207", 893);
            let (server_res, client_res) = block_on(async {
                tokio::join!(
                    server_side_jmux(jmux_server_addr, logger.clone()),
                    client_side_jmux(api_request_rx, jmux_server_addr, logger)
                )
            });
            server_res.expect("JMUX server");
            client_res.expect("JMUX client");
        });

        let handle = spawn({
            let api_request_tx = api_request_tx.clone();
            move || {
                let fut1 = client(api_request_tx.clone(), ("232.192.0.94", 42));
                let fut2 = client(api_request_tx, ("3.199.201.72", 666));
                block_on(async { tokio::join!(fut1, fut2) })
            }
        });

        block_on(client(api_request_tx, ("232.192.0.94", 42))).expect("client 1");
        let (client2, client3) = handle.join().unwrap();
        client2.expect("client 2");
        client3.expect("client 3");

        assert_eq!(counter.load(Ordering::Acquire), 3);
    })
}

#[test]
fn reader_task_window_size() {
    loom::model(|| {
        println!("hello");

        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        rt.block_on(async {
            let lock = Arc::new(AtomicUsize::new(0));
            let num = Arc::new(AtomicUsize::new(0));

            let ths: Vec<_> = (0..2)
                .map(|_| {
                    let lock = lock.clone();
                    let num = num.clone();
                    tokio::spawn(async move {
                        while lock.compare_and_swap(0, 1, Ordering::Acquire) == 1 {}
                        let curr = num.load(Ordering::Acquire);
                        num.store(curr + 1, Ordering::Release);
                        lock.store(0, Ordering::Release);
                    })
                })
                .collect();

            for th in ths {
                th.await.unwrap();
            }

            assert_eq!(2, num.load(Ordering::Relaxed));
        });
    });
}
