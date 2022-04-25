//! Multiple socks5 clients → socks5 server → jmux peer → several TCP listeners

use anyhow::Context as _;
use futures_util::FutureExt;
use proptest::prelude::*;
use test_utils::{
    find_unused_ports, read_assert_payload, small_payload, transport_kind, write_payload, Payload, TransportKind,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NB_TARGETS: usize = 3;

#[derive(Debug)]
struct ClientConfig {
    operations: Vec<Operation>,
}

#[derive(Clone, Debug)]
enum Operation {
    FetchHtml,
    Echo { target_id: usize, payload: Payload },
}

fn target_id() -> impl Strategy<Value = usize> {
    0..NB_TARGETS
}

fn operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        1 => Just(Operation::FetchHtml),
        9 => (target_id(), small_payload().no_shrink()).prop_map(|(target_id, payload)| Operation::Echo { target_id, payload }),
    ]
}

fn client_cfg() -> impl Strategy<Value = ClientConfig> {
    prop::collection::vec(operation(), 1..=5).prop_map(|operations| ClientConfig { operations })
}

async fn retry<Fut, T, E>(fut: impl Fn() -> Fut) -> Result<T, E>
where
    Fut: std::future::Future<Output = Result<T, E>>,
{
    for _ in 0..10 {
        match fut().await {
            Ok(o) => return Ok(o),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
        }
    }
    fut().await
}

async fn client(
    cfg: ClientConfig,
    socks5_port: u16,
    targets: [u16; NB_TARGETS],
    logger: slog::Logger,
) -> anyhow::Result<()> {
    use proxy_socks::Socks5Stream;
    use tokio::net::TcpStream;

    for (idx, op) in cfg.operations.into_iter().enumerate() {
        let logger = logger.new(slog::o!("operation" => idx));

        let stream = retry(|| {
            slog::info!(logger, "Connecting to SOCKS5 proxy");
            TcpStream::connect(("127.0.0.1", socks5_port))
        })
        .await
        .with_context(|| format!("TCP stream connect (port = {socks5_port})"))?;

        match op {
            Operation::Echo { target_id, payload } => {
                let stream = Socks5Stream::connect(stream, format!("127.0.0.1:{}", targets[target_id]))
                    .await
                    .context("SOCKS5 connect")?;
                let (mut reader, mut writer) = tokio::io::split(stream);

                slog::info!(logger, "Echo test");

                let write_fut = write_payload(&mut writer, &payload.0).map(|res| res.context("Write payload"));
                let read_fut = read_assert_payload(&mut reader, &payload.0).map(|res| res.context("Assert payload"));
                tokio::try_join!(write_fut, read_fut)?;

                writer.shutdown().await.context("Shutdown operation")?;
            }
            Operation::FetchHtml => {
                let mut stream = Socks5Stream::connect(stream, "rust-lang.org:80")
                    .await
                    .context("SOCKS5 connect")?;

                slog::info!(logger, "HTML test");

                stream
                    .write_all(b"GET / HTTP/1.0\r\n\r\n")
                    .await
                    .context("write_all operation")?;

                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await.context("read_to_end operation")?;
                let html = String::from_utf8(buf).unwrap();
                assert!(!html.is_empty());
                assert!(html.trim().starts_with("HTTP/1.1"));
                assert!(html.trim().ends_with("</HTML>") || html.trim().ends_with("</html>"));

                stream.shutdown().await.context("Shutdown operation")?;
            }
        }
    }

    Ok(())
}

async fn echo_server(port: u16, logger: slog::Logger) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    slog::info!(logger, "Echo server listening on 127.0.0.1:{}", port);

    loop {
        let (mut socket, _) = listener.accept().await.context("Accept operation")?;

        let logger = logger.clone();

        tokio::spawn(async move {
            let mut buf = [0; 256];

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
        });
    }
}

/// Client-side relay converting SOCKS5 to JMUX
async fn client_side_jmux(
    socks5_port: u16,
    jmux_server_port: u16,
    kind: TransportKind,
    logger: slog::Logger,
) -> anyhow::Result<()> {
    use jetsocat::pipe::PipeMode;

    let pipe_mode = match kind {
        TransportKind::Tcp => PipeMode::Tcp {
            addr: format!("127.0.0.1:{}", jmux_server_port),
        },
        TransportKind::Ws => PipeMode::WebSocket {
            url: format!("ws://127.0.0.1:{}", jmux_server_port),
        },
    };

    let listener_mode = jetsocat::listener::ListenerMode::Socks5 {
        bind_addr: format!("127.0.0.1:{}", socks5_port),
    };

    let cfg = jetsocat::JmuxProxyCfg {
        pipe_mode,
        proxy_cfg: None,
        listener_modes: vec![listener_mode],
        timeout: None,
        jmux_cfg: jmux_proxy::JmuxConfig::client(),
    };

    jetsocat::jmux_proxy(cfg, logger.new(slog::o!("side" => "client")))
        .await
        .context("Client-side JMUX")
}

/// Server-side relay processing JMUX requests
async fn server_side_jmux(port: u16, kind: TransportKind, logger: slog::Logger) -> anyhow::Result<()> {
    use jetsocat::pipe::PipeMode;
    use jmux_proxy::{FilteringRule, JmuxConfig};

    let pipe_mode = match kind {
        TransportKind::Tcp => PipeMode::TcpListen {
            bind_addr: format!("127.0.0.1:{}", port),
        },
        TransportKind::Ws => PipeMode::WebSocketListen {
            bind_addr: format!("127.0.0.1:{}", port),
        },
    };

    // just to make sure tests can't do just anything
    let filtering_rule = FilteringRule::host("127.0.0.1").or(FilteringRule::host_and_port("rust-lang.org", 80));

    let cfg = jetsocat::JmuxProxyCfg {
        pipe_mode,
        proxy_cfg: None,
        listener_modes: Vec::new(),
        timeout: None,
        jmux_cfg: JmuxConfig {
            filtering: filtering_rule,
        },
    };

    jetsocat::jmux_proxy(cfg, logger.new(slog::o!("side" => "server")))
        .await
        .context("Server-side JMUX")
}

#[test]
fn socks5_to_jmux() {
    use slog::Drain as _;

    let decorator = slog_term::PlainDecorator::new(slog_term::TestStdoutWriter);
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let async_drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(async_drain, slog::o!());

    let ports = find_unused_ports(NB_TARGETS + 2);
    let socks5_port = ports[0];
    let jmux_server_port = ports[1];
    let mut targets = [0u16; NB_TARGETS];
    for i in 0..NB_TARGETS {
        targets[i] = ports[i + 2];
    }

    proptest!(ProptestConfig::with_cases(32), |(
        cfgs in prop::collection::vec(client_cfg(), 1..5),
        pipe_kind in transport_kind(),
    )| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut to_await = Vec::new();
            let mut to_abort = Vec::new();

            for (index, target_port) in targets.into_iter().enumerate() {
                to_abort.push(tokio::spawn(echo_server(target_port, logger.new(slog::o!("echo server" => index)))));
            }

            to_abort.push(tokio::spawn(server_side_jmux(jmux_server_port, pipe_kind, logger.clone())));
            to_abort.push(tokio::spawn(client_side_jmux(socks5_port, jmux_server_port, pipe_kind, logger.clone())));

            for (index, cfg) in cfgs.into_iter().enumerate() {
                to_await.push(tokio::spawn(client(cfg, socks5_port, targets, logger.new(slog::o!("client" => index)))));
            }

            for handle in to_await {
                handle.await.unwrap().unwrap();
            }

            for handle in to_abort {
                handle.abort();
                assert!(handle.await.unwrap_err().is_cancelled());
            }
        });
    })
}
