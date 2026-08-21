//! Checks that JMUX does not penalize round trips.
//!
//! HTTP/2 gates an upload on its per-stream flow control window: the client may only have
//! `SETTINGS_INITIAL_WINDOW_SIZE` bytes of DATA in flight before it must wait for a
//! `WINDOW_UPDATE` to come back. RFC 9113 puts the default at 65535 bytes, and a server that
//! never raises it turns a large upload into a long sequence of round trips rather than one
//! continuous stream. HTTP/1.1 has no such gate and streams the body in one go.
//!
//! That makes an HTTP/2 upload a sensitive probe for latency added *per round trip* by
//! anything relaying the connection. A JMUX sender that waits on a timer before flushing
//! small messages (a `WINDOW_UPDATE` never fills a write buffer on its own) turns every one
//! of those round trips into a stall, while leaving bulk HTTP/1.1 transfers untouched.
//!
//! These tests pin that behavior down: same payload, same JMUX pipe, HTTP/1.1 versus HTTP/2.

use core::time::Duration;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use jmux_proxy::{DestinationUrl, JmuxApiRequest, JmuxApiResponse, JmuxConfig, JmuxProxy};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// The HTTP/2 default initial window from RFC 9113, which a server has to explicitly raise.
/// Left at the default, it makes an upload round trip every 64 KiB.
///
/// Servers really do leave it there: vCenter is one, and Broadcom documents raising it as the
/// remedy for slow Content Library uploads over high-latency links.
/// See <https://knowledge.broadcom.com/external/article/411225>.
const STREAM_WINDOW: u32 = 64 * 1024;

/// Kept comfortably above `STREAM_WINDOW` so the per-stream window stays the binding limit.
const CONNECTION_WINDOW: u32 = 1024 * 1024;

const PAYLOAD_SIZE: usize = 8 * 1024 * 1024;

/// How much slower the same upload may be through JMUX than straight to the server.
///
/// Expressed as a ratio rather than a wall-clock budget on purpose. An absolute budget has to
/// be loose enough for slow CI, which makes it too loose to catch the regression: with a 10 ms
/// per-flush delay over the 128 round trips this payload takes, the old sender only needs to
/// lose 10-20 ms per round trip to blow past any budget generous enough to be safe, and on a
/// platform where the timer fires closer to its nominal delay it could sneak under. Scaling
/// against the direct measurement normalizes for machine speed instead.
///
/// Observed ratios: ~2.5x with the current sender, ~70x with the 10 ms idle-flush timer.
const MAX_JMUX_OVERHEAD_FACTOR: u32 = 8;

/// Bound for the HTTP/1.1 control case, which is not round-trip gated and so is not the
/// sensitive measurement. It only needs to be loose enough not to flake.
const H1_BUDGET: Duration = Duration::from_secs(2);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Proto {
    Http1,
    Http2,
}

/// Spawns a server that drains request bodies and replies with an empty 200.
async fn spawn_server(proto: Proto) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                let service = hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let mut body = req.into_body();

                    // Consume the body as it arrives. This is what releases flow control
                    // credit back to the peer, so it must not buffer the whole thing.
                    while let Some(frame) = body.frame().await {
                        frame?;
                    }

                    Ok::<_, hyper::Error>(hyper::Response::new(Empty::<Bytes>::new()))
                });

                match proto {
                    Proto::Http1 => hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                        .map_err(|error| format!("{error}")),
                    Proto::Http2 => hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .initial_stream_window_size(STREAM_WINDOW)
                        .initial_connection_window_size(CONNECTION_WINDOW)
                        .serve_connection(io, service)
                        .await
                        .map_err(|error| format!("{error}")),
                }
            });
        }
    });

    addr
}

/// Uploads `PAYLOAD_SIZE` bytes to `addr` and returns how long it took.
async fn upload(addr: SocketAddr, proto: Proto) -> Duration {
    let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());

    let request = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{addr}/upload"))
        .body(Full::new(Bytes::from(vec![0u8; PAYLOAD_SIZE])))
        .unwrap();

    let started_at = Instant::now();

    let response = match proto {
        Proto::Http1 => {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(conn);
            sender.send_request(request).await.unwrap()
        }
        Proto::Http2 => {
            let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                .await
                .unwrap();
            tokio::spawn(conn);
            sender.send_request(request).await.unwrap()
        }
    };

    assert!(response.status().is_success(), "upload failed: {}", response.status());
    response.into_body().collect().await.unwrap();

    started_at.elapsed()
}

/// Runs a JMUX proxy pair and returns a local address forwarding to `target` through it.
///
/// This mirrors the deployed topology — jetsocat on one end exposing a local listener, the
/// Gateway on the other end connecting out to the target — with the two ends wired together
/// by a loopback TCP connection standing in for the WebSocket pipe.
async fn spawn_jmux_forward(target: SocketAddr) -> SocketAddr {
    let pipe_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pipe_addr = pipe_listener.local_addr().unwrap();
    let dialing = tokio::spawn(async move { TcpStream::connect(pipe_addr).await.unwrap() });
    let (gateway_end, _) = pipe_listener.accept().await.unwrap();
    let client_end = dialing.await.unwrap();

    // The end that accepts channels and connects out to the target.
    let (reader, writer) = gateway_end.into_split();
    tokio::spawn(
        JmuxProxy::new(Box::new(reader), Box::new(writer))
            .with_config(JmuxConfig::permissive())
            .run(),
    );

    // The end that opens channels on behalf of local connections.
    let (api_request_tx, api_request_rx) = mpsc::channel(16);
    let (reader, writer) = client_end.into_split();
    tokio::spawn(
        JmuxProxy::new(Box::new(reader), Box::new(writer))
            .with_requester_api(api_request_rx)
            .run(),
    );

    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let destination_url = DestinationUrl::new("tcp", &target.ip().to_string(), target.port());

    tokio::spawn(async move {
        loop {
            let (stream, _) = local_listener.accept().await.unwrap();
            let api_request_tx = api_request_tx.clone();
            let destination_url = destination_url.clone();

            tokio::spawn(async move {
                let (api_response_tx, api_response_rx) = oneshot::channel();

                api_request_tx
                    .send(JmuxApiRequest::OpenChannel {
                        destination_url,
                        api_response_tx,
                    })
                    .await
                    .unwrap();

                match api_response_rx.await.unwrap() {
                    JmuxApiResponse::Success { id } => {
                        api_request_tx
                            .send(JmuxApiRequest::Start {
                                id,
                                stream,
                                leftover: None,
                            })
                            .await
                            .unwrap();
                    }
                    JmuxApiResponse::Failure { id, reason_code } => {
                        panic!("channel {id} failed to open: {reason_code}")
                    }
                }
            });
        }
    });

    local_addr
}

/// An HTTP/2 upload is gated on a 64 KiB window, so it round trips 128 times for this payload.
/// Any per-round-trip latency introduced by JMUX shows up here, multiplied.
#[tokio::test(flavor = "multi_thread")]
async fn http2_upload_through_jmux_is_not_round_trip_penalized() {
    let server_addr = spawn_server(Proto::Http2).await;
    let forward_addr = spawn_jmux_forward(server_addr).await;

    let direct = upload(server_addr, Proto::Http2).await;
    let through_jmux = upload(forward_addr, Proto::Http2).await;

    println!("http2 direct={direct:?} through_jmux={through_jmux:?}");

    let budget = direct * MAX_JMUX_OVERHEAD_FACTOR;

    assert!(
        through_jmux < budget,
        "HTTP/2 upload took {through_jmux:?} through JMUX versus {direct:?} direct, over the \
         {MAX_JMUX_OVERHEAD_FACTOR}x budget of {budget:?}; JMUX is likely delaying flow \
         control updates"
    );
}

/// The HTTP/1.1 counterpart streams the body without gating, so it stays fast even when JMUX
/// delays small messages. Keeping it here documents *why* the HTTP/2 case is the sensitive one:
/// a regression that only this test catches is a round-trip regression, not a bandwidth one.
#[tokio::test(flavor = "multi_thread")]
async fn http1_upload_through_jmux_matches_direct() {
    let server_addr = spawn_server(Proto::Http1).await;
    let forward_addr = spawn_jmux_forward(server_addr).await;

    let direct = upload(server_addr, Proto::Http1).await;
    let through_jmux = upload(forward_addr, Proto::Http1).await;

    println!("http1 direct={direct:?} through_jmux={through_jmux:?}");

    assert!(
        through_jmux < H1_BUDGET,
        "HTTP/1.1 upload through JMUX took {through_jmux:?}, over the {H1_BUDGET:?} budget \
         (direct took {direct:?})"
    );
}

/// Pins the sender's flush behavior directly, without depending on wall-clock timing.
///
/// With the clock paused, tokio advances virtual time only when every task is idle. A sender
/// that parks on a timer before flushing therefore shows up as virtual time elapsing between
/// queueing a message and it reaching the pipe, on any machine and at any speed. A sender that
/// flushes once its queue is drained shows zero.
///
/// This is the deterministic counterpart to the HTTP/2 test above: that one proves the
/// end-to-end effect on realistic traffic, this one fails for exactly one reason.
#[tokio::test(start_paused = true)]
async fn sender_flushes_without_advancing_the_clock() {
    use tokio::io::AsyncReadExt as _;

    let (near, mut far) = tokio::io::duplex(64 * 1024);
    let (near_reader, near_writer) = tokio::io::split(near);
    let (api_request_tx, api_request_rx) = mpsc::channel(1);

    tokio::spawn(
        JmuxProxy::new(Box::new(near_reader), Box::new(near_writer))
            .with_requester_api(api_request_rx)
            .run(),
    );

    // Opening a channel queues a single small message, which is exactly the shape of traffic
    // that never fills the sender's write buffer on its own.
    let (api_response_tx, _api_response_rx) = oneshot::channel();
    api_request_tx
        .send(JmuxApiRequest::OpenChannel {
            destination_url: DestinationUrl::new("tcp", "127.0.0.1", 1),
            api_response_tx,
        })
        .await
        .unwrap();

    let started_at = tokio::time::Instant::now();

    let mut buf = [0u8; 128];
    let read = tokio::time::timeout(Duration::from_secs(5), far.read(&mut buf))
        .await
        .expect("sender never flushed the CHANNEL OPEN")
        .unwrap();

    let waited = started_at.elapsed();

    assert!(read > 0, "sender flushed an empty write");
    assert!(
        waited < Duration::from_millis(1),
        "sender held the message for {waited:?} of virtual time before flushing; it is \
         waiting on a timer rather than flushing once its queue is drained"
    );
}
