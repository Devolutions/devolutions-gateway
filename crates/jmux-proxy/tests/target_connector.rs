#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use jmux_proto::{BytesMut, DistantChannelId, Header, LocalChannelId, Message, ReasonCode};
use jmux_proxy::{ConnectedTarget, DestinationUrl, EventOutcome, JmuxConfig, JmuxProxy, TrafficEvent};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn send_message(writer: &mut (impl AsyncWrite + Unpin), message: Message) {
    let mut bytes = BytesMut::new();
    message.encode(&mut bytes).expect("encode JMUX message");
    writer.write_all(&bytes).await.expect("send JMUX message");
}

async fn receive_message(reader: &mut (impl AsyncRead + Unpin)) -> Message {
    timeout(TEST_TIMEOUT, async {
        let mut header = [0; Header::SIZE];
        reader.read_exact(&mut header).await.expect("read JMUX header");
        let message_size = usize::from(u16::from_be_bytes([header[1], header[2]]));
        let mut body = vec![0; message_size - Header::SIZE];
        reader.read_exact(&mut body).await.expect("read JMUX body");

        let mut bytes = BytesMut::with_capacity(message_size);
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&body);
        Message::decode(bytes.freeze()).expect("decode JMUX message")
    })
    .await
    .expect("JMUX response timed out")
}

#[tokio::test]
async fn connected_target_ip_is_used_for_audit() {
    let (proxy_stream, peer_stream) = tokio::io::duplex(8192);
    let (proxy_reader, proxy_writer) = tokio::io::split(proxy_stream);
    let (mut peer_reader, mut peer_writer) = tokio::io::split(peer_stream);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<TrafficEvent>();
    let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    let proxy = JmuxProxy::new(Box::new(proxy_reader), Box::new(proxy_writer))
        .with_config(JmuxConfig::permissive())
        .with_target_connector(move |destination| async move {
            assert_eq!(destination.host(), "agent.example");
            let (target_stream, mut target_peer) = tokio::io::duplex(64);
            tokio::spawn(async move {
                target_peer.shutdown().await.expect("close target stream");
            });
            Ok(Some(ConnectedTarget::new(target_stream, Some(target_ip))))
        })
        .with_outgoing_traffic_event_callback(move |event| {
            event_tx.send(event).expect("capture traffic event");
        });
    let proxy_task = tokio::spawn(proxy.run());

    send_message(
        &mut peer_writer,
        Message::open(
            LocalChannelId::from(7),
            4096,
            DestinationUrl::new("tcp", "agent.example", 443),
        ),
    )
    .await;

    let Message::OpenSuccess(open_success) = receive_message(&mut peer_reader).await else {
        panic!("expected OPEN SUCCESS");
    };
    let local_id = DistantChannelId::from(open_success.sender_channel_id);

    assert!(matches!(receive_message(&mut peer_reader).await, Message::Eof(_)));
    send_message(&mut peer_writer, Message::eof(local_id)).await;
    assert!(matches!(receive_message(&mut peer_reader).await, Message::Close(_)));
    send_message(&mut peer_writer, Message::close(local_id)).await;

    let event = timeout(TEST_TIMEOUT, event_rx.recv())
        .await
        .expect("traffic event timed out")
        .expect("traffic event channel closed");
    assert_eq!(event.outcome, EventOutcome::NormalTermination);
    assert_eq!(event.target_host, "agent.example");
    assert_eq!(event.target_ip, target_ip);
    assert_eq!(event.target_port, 443);

    proxy_task.abort();
}

#[tokio::test]
async fn connector_failure_is_bounded_and_does_not_stop_direct_fallback() {
    let (proxy_stream, peer_stream) = tokio::io::duplex(8192);
    let (proxy_reader, proxy_writer) = tokio::io::split(proxy_stream);
    let (mut peer_reader, mut peer_writer) = tokio::io::split(peer_stream);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<TrafficEvent>();

    let proxy = JmuxProxy::new(Box::new(proxy_reader), Box::new(proxy_writer))
        .with_config(JmuxConfig::permissive())
        .with_target_connector(|destination| async move {
            if destination.host() == "fail.example" {
                anyhow::bail!("{}", "agent error ".repeat(8192));
            }
            Ok(None)
        })
        .with_outgoing_traffic_event_callback(move |event| {
            event_tx.send(event).expect("capture traffic event");
        });
    let proxy_task = tokio::spawn(proxy.run());

    send_message(
        &mut peer_writer,
        Message::open(
            LocalChannelId::from(11),
            4096,
            DestinationUrl::new("tcp", "fail.example", 443),
        ),
    )
    .await;

    let Message::OpenFailure(open_failure) = receive_message(&mut peer_reader).await else {
        panic!("expected OPEN FAILURE");
    };
    assert_eq!(open_failure.reason_code, ReasonCode::GENERAL_FAILURE);
    assert_eq!(open_failure.description, "target connection failed");
    assert!(timeout(Duration::from_millis(100), event_rx.recv()).await.is_err());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind direct target");
    let target_port = listener.local_addr().expect("read direct target address").port();
    let server_task = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept direct connection");
        std::future::pending::<()>().await;
    });

    send_message(
        &mut peer_writer,
        Message::open(
            LocalChannelId::from(12),
            4096,
            DestinationUrl::new("tcp", "127.0.0.1", target_port),
        ),
    )
    .await;
    let Message::OpenSuccess(open_success) = receive_message(&mut peer_reader).await else {
        panic!("expected OPEN SUCCESS");
    };
    assert_eq!(open_success.sender_channel_id, 0);

    server_task.abort();
    proxy_task.abort();
}
