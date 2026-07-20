#![allow(clippy::unwrap_used)]

use std::future;
use std::time::Duration;

use jmux_proto::{Bytes, BytesMut, Header, LocalChannelId, Message};
use jmux_proxy::{DestinationUrl, JmuxConfig, JmuxProxy, OutgoingStreamFuture, OutgoingStreamHandler};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn send_message(stream: &mut DuplexStream, message: Message) {
    let mut packet = BytesMut::new();
    message.encode(&mut packet).unwrap();
    stream.write_all(&packet).await.unwrap();
}

async fn receive_message(stream: &mut DuplexStream) -> Message {
    let mut header_bytes = [0; Header::SIZE];
    stream.read_exact(&mut header_bytes).await.unwrap();

    let header = Header::decode(Bytes::copy_from_slice(&header_bytes)).unwrap();
    let mut body = vec![0; usize::from(header.size) - Header::SIZE];
    stream.read_exact(&mut body).await.unwrap();

    let mut packet = BytesMut::with_capacity(usize::from(header.size));
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&body);
    Message::decode(packet.freeze()).unwrap()
}

fn run_proxy(handler: impl OutgoingStreamHandler) -> (DuplexStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let (proxy_stream, peer_stream) = tokio::io::duplex(8192);
    let (reader, writer) = tokio::io::split(proxy_stream);
    let proxy = JmuxProxy::new(Box::new(reader), Box::new(writer))
        .with_config(JmuxConfig::permissive())
        .with_outgoing_stream_handler(handler);

    (peer_stream, tokio::spawn(proxy.run()))
}

async fn open_channel(peer_stream: &mut DuplexStream, destination: DestinationUrl) {
    send_message(peer_stream, Message::open(LocalChannelId::from(7), 4096, destination)).await;

    match timeout(TEST_TIMEOUT, receive_message(peer_stream)).await.unwrap() {
        Message::OpenSuccess(_) => {}
        message => panic!("expected OPEN SUCCESS, got {message:?}"),
    }
}

struct DropSignal(mpsc::Sender<()>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

struct BlockingHandler {
    started_tx: mpsc::Sender<(DestinationUrl, std::net::SocketAddr)>,
    dropped_tx: mpsc::Sender<()>,
}

impl OutgoingStreamHandler for BlockingHandler {
    fn handle(
        &self,
        destination: DestinationUrl,
        channel_stream: DuplexStream,
        target_stream: TcpStream,
    ) -> OutgoingStreamFuture {
        let started_tx = self.started_tx.clone();
        let dropped_tx = self.dropped_tx.clone();

        Box::pin(async move {
            let _drop_signal = DropSignal(dropped_tx);
            let target_addr = target_stream.peer_addr()?;
            let _streams = (channel_stream, target_stream);
            let _ = started_tx.send((destination, target_addr)).await;
            future::pending::<()>().await;
            Ok(())
        })
    }
}

struct FailingHandler;

impl OutgoingStreamHandler for FailingHandler {
    fn handle(
        &self,
        _destination: DestinationUrl,
        _channel_stream: DuplexStream,
        _target_stream: TcpStream,
    ) -> OutgoingStreamFuture {
        Box::pin(async { anyhow::bail!("expected handler failure") })
    }
}

#[tokio::test]
async fn proxy_shutdown_aborts_running_handler() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();
    let destination = DestinationUrl::new("tcp", "127.0.0.1", target_addr.port());
    let (started_tx, mut started_rx) = mpsc::channel(1);
    let (dropped_tx, mut dropped_rx) = mpsc::channel(1);
    let handler = BlockingHandler { started_tx, dropped_tx };
    let (mut peer_stream, proxy_task) = run_proxy(handler);

    open_channel(&mut peer_stream, destination.clone()).await;

    let (handled_destination, connected_addr) = timeout(TEST_TIMEOUT, started_rx.recv()).await.unwrap().unwrap();
    assert_eq!(handled_destination, destination);
    assert_eq!(connected_addr, target_addr);

    drop(peer_stream);

    timeout(TEST_TIMEOUT, dropped_rx.recv())
        .await
        .unwrap()
        .expect("handler task should be dropped");
    timeout(TEST_TIMEOUT, proxy_task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn handler_failure_closes_its_channel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();
    let destination = DestinationUrl::new("tcp", "127.0.0.1", target_addr.port());
    let (mut peer_stream, proxy_task) = run_proxy(FailingHandler);

    open_channel(&mut peer_stream, destination).await;

    let close = timeout(TEST_TIMEOUT, async {
        loop {
            if let Message::Close(message) = receive_message(&mut peer_stream).await {
                break message;
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(close.recipient_channel_id, 7);
    assert!(!proxy_task.is_finished());

    drop(peer_stream);
    timeout(TEST_TIMEOUT, proxy_task).await.unwrap().unwrap().unwrap();
}
