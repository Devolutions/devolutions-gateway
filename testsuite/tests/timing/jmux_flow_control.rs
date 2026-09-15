use std::time::{Duration, Instant};

use rstest::rstest;
use test_utils::find_unused_ports;
use testsuite::cli::{jetsocat_tokio_cmd, wait_for_port_bound};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const WINDOW_SIZE: usize = 4 * 1024;
const MEASURED_WINDOWS: usize = 256;
const CREDIT: u8 = 1;
const HANG_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_BUDGET: Duration = Duration::from_secs(2);

/// Relays windowed data through the jetsocat CLI and measures how quickly credits return.
async fn run_jmux_flow_control_case(use_websocket: bool) -> Duration {
    let ports = find_unused_ports(2);
    let jmux_server_port = ports[0];
    let proxy_port = ports[1];

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target_listener.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let window = vec![0; WINDOW_SIZE];
        let mut credit = [0];

        // Model receiver-driven flow control: each complete window releases one byte of credit.
        for _ in 0..=MEASURED_WINDOWS {
            stream.write_all(&window).await.unwrap();
            stream.read_exact(&mut credit).await.unwrap();
            assert_eq!(credit, [CREDIT]);
        }
    });

    let jmux_pipe = if use_websocket {
        format!("ws-listen://127.0.0.1:{jmux_server_port}")
    } else {
        format!("tcp-listen://127.0.0.1:{jmux_server_port}")
    };
    let mut jmux_server = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy {jmux_pipe} --allow-all --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX server");

    wait_for_port_bound(jmux_server_port).await.expect("JMUX server ready");

    let peer_pipe = if use_websocket {
        format!("ws://127.0.0.1:{jmux_server_port}")
    } else {
        format!("tcp://127.0.0.1:{jmux_server_port}")
    };
    let mut jmux_client = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy {peer_pipe} tcp-listen://127.0.0.1:{proxy_port}/127.0.0.1:{target_port} --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX client");

    wait_for_port_bound(proxy_port).await.expect("JMUX client proxy ready");

    let transfer = timeout(HANG_TIMEOUT, async move {
        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut window = vec![0; WINDOW_SIZE];

        // Warm up the tunnel so connection setup is excluded from the measurement.
        stream.read_exact(&mut window).await.unwrap();
        stream.write_all(&[CREDIT]).await.unwrap();

        let started_at = Instant::now();

        for _ in 0..MEASURED_WINDOWS {
            stream.read_exact(&mut window).await.unwrap();
            stream.write_all(&[CREDIT]).await.unwrap();
        }

        let elapsed = started_at.elapsed();
        target_task.await.expect("target server task panicked");
        elapsed
    })
    .await;

    let _ = jmux_client.start_kill();
    let _ = jmux_server.start_kill();
    let _ = jmux_client.wait().await;
    let _ = jmux_server.wait().await;

    transfer.expect("flow-controlled transfer timed out")
}

/// Reproduces the round-trip bottleneck seen in VMware HTTP/2 uploads without embedding an HTTP stack.
///
/// HTTP/2 commonly limits an upload to about 64 KiB before the server returns a small flow-control update.
/// This test mirrors that dependency by making the sender wait for one byte of credit after every 4 KiB window.
/// The direction is immaterial because both JMUX peers use the same sender implementation.
/// The old JMUX sender delayed each credit behind its flush timer, so the accumulated delay exceeds the transfer budget.
#[rstest]
#[case::tcp(false)]
#[case::websocket(true)]
#[tokio::test]
#[ignore = "run serially by the timing-sensitive CI step"]
async fn jmux_flow_control_credits_are_not_delayed(#[case] use_websocket: bool) {
    let elapsed = run_jmux_flow_control_case(use_websocket).await;
    let transport = if use_websocket { "WebSocket" } else { "TCP" };

    println!("{transport} JMUX flow-controlled transfer completed in {elapsed:?}");

    assert!(
        elapsed < TRANSFER_BUDGET,
        "{transport} JMUX took {elapsed:?} to relay flow-controlled traffic, exceeding the \
         {TRANSFER_BUDGET:?} budget"
    );
}
