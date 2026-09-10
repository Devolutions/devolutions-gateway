use std::time::Duration;

use jmux_proto::{Bytes, BytesMut, DistantChannelId, Header, LocalChannelId, Message, ReasonCode};
use jmux_proxy::{DestinationUrl, JmuxConfig, JmuxProxy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
async fn override_stream_carries_channel_data() {
    let (proxy_stream, peer_stream) = tokio::io::duplex(8192);
    let (proxy_reader, proxy_writer) = tokio::io::split(proxy_stream);
    let (mut peer_reader, mut peer_writer) = tokio::io::split(peer_stream);
    let proxy = JmuxProxy::new(Box::new(proxy_reader), Box::new(proxy_writer))
        .with_config(JmuxConfig::permissive())
        .with_target_connector_override(|_| async move {
            let (target_stream, mut target_peer) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let mut payload = [0; 4];
                target_peer.read_exact(&mut payload).await.expect("read target data");
                let mut eof_probe = [0u8; 1];
                assert_eq!(target_peer.read(&mut eof_probe).await.expect("read target EOF"), 0);
                target_peer.write_all(&payload).await.expect("echo target data");
            });
            Ok(Some(target_stream))
        });
    let _proxy_task = tokio::spawn(proxy.run());

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

    send_message(&mut peer_writer, Message::data(local_id, Bytes::from_static(b"ping"))).await;
    send_message(&mut peer_writer, Message::eof(local_id)).await;
    let Message::Data(data) = receive_message(&mut peer_reader).await else {
        panic!("expected CHANNEL DATA");
    };
    assert_eq!(data.recipient_channel_id, 7);
    assert_eq!(data.transfer_data, b"ping"[..]);
}

#[tokio::test]
async fn resolution_failures_free_id_and_keep_direct_fallback() {
    let (proxy_stream, peer_stream) = tokio::io::duplex(8192);
    let (proxy_reader, proxy_writer) = tokio::io::split(proxy_stream);
    let (mut peer_reader, mut peer_writer) = tokio::io::split(peer_stream);
    let proxy = JmuxProxy::new(Box::new(proxy_reader), Box::new(proxy_writer))
        .with_config(JmuxConfig::permissive())
        .with_target_connector_override(|destination| async move {
            if destination.host() == "fail.example" {
                anyhow::bail!("agent error");
            }
            Ok(None::<tokio::io::DuplexStream>)
        });
    let _proxy_task = tokio::spawn(proxy.run());

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

    send_message(
        &mut peer_writer,
        Message::open(
            LocalChannelId::from(12),
            4096,
            DestinationUrl::new("tcp", "127.0.0.1", 0),
        ),
    )
    .await;
    assert!(matches!(
        receive_message(&mut peer_reader).await,
        Message::OpenFailure(_)
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind direct target");
    let target_port = listener.local_addr().expect("read direct target address").port();

    send_message(
        &mut peer_writer,
        Message::open(
            LocalChannelId::from(13),
            4096,
            DestinationUrl::new("tcp", "127.0.0.1", target_port),
        ),
    )
    .await;
    let Message::OpenSuccess(open_success) = receive_message(&mut peer_reader).await else {
        panic!("expected OPEN SUCCESS");
    };
    // The failed channel released ID 0 for reuse.
    assert_eq!(open_success.sender_channel_id, 0);
}
