use anyhow::Context as _;
use proptest::collection::size_range;
use proptest::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use transport::{Transport, WebSocketStream};

/// For sane Debug display
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Payload(pub Vec<u8>);

impl core::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for v in self.0.iter().take(15) {
            write!(f, "{:X?}", v)?;
        }
        write!(f, "..")
    }
}

const PAYLOAD_MINIMUM_SIZE: usize = 256;
const PAYLOAD_MAXIMUM_SIZE: usize = 24 * 256 * 144; // approximately the size of a 144p 24bpp BMP image

prop_compose! {
    pub fn payload()(data in any_with::<Vec<u8>>(size_range(PAYLOAD_MINIMUM_SIZE..PAYLOAD_MAXIMUM_SIZE).lift())) -> Payload {
        Payload(data)
    }
}

const LARGE_MINIMUM_SIZE: usize = 24 * 1920 * 1080; // approximately the size of a 1080p 24bpp BMP image
const LARGE_MAXIMUM_SIZE: usize = 24 * 3840 * 2160; // approximately the size of a 4K 24bpp BMP image

prop_compose! {
    pub fn large_payload()(data in any_with::<Vec<u8>>(size_range(LARGE_MINIMUM_SIZE..LARGE_MAXIMUM_SIZE).lift())) -> Payload {
        Payload(data)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TransportKind {
    Tcp,
    Ws,
}

pub fn transport_kind() -> impl Strategy<Value = TransportKind> {
    prop_oneof![Just(TransportKind::Tcp), Just(TransportKind::Ws)]
}

impl TransportKind {
    pub async fn connect(self, port: u16) -> anyhow::Result<Transport> {
        match self {
            TransportKind::Ws => ws_connect(port).await,
            TransportKind::Tcp => tcp_connect(port).await,
        }
    }

    pub async fn accept(self, port: u16) -> anyhow::Result<Transport> {
        match self {
            TransportKind::Ws => ws_accept(port).await,
            TransportKind::Tcp => tcp_accept(port).await,
        }
    }
}

pub async fn ws_accept(port: u16) -> anyhow::Result<Transport> {
    use tokio_tungstenite::accept_async;

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let (stream, addr) = listener.accept().await?;
    let ws = accept_async(stream)
        .await
        .context("WebSocket handshake failed (accept)")?;
    let ws = WebSocketStream::new(ws);

    Ok(Transport::new(ws, addr))
}

pub async fn ws_connect(port: u16) -> anyhow::Result<Transport> {
    use tokio_tungstenite::client_async;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let addr = stream.peer_addr()?;

    let req = format!("ws://127.0.0.1:{}", port).into_client_request()?;
    let (ws, ..) = client_async(req, stream)
        .await
        .context("WebSocket handshake failed (connect)")?;
    let ws = WebSocketStream::new(ws);

    Ok(Transport::new(ws, addr))
}

pub async fn tcp_accept(port: u16) -> anyhow::Result<Transport> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let (stream, addr) = listener.accept().await?;
    Ok(Transport::new(stream, addr))
}

pub async fn tcp_connect(port: u16) -> anyhow::Result<Transport> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let addr = stream.peer_addr()?;
    Ok(Transport::new(stream, addr))
}

pub async fn write_payload<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut cursor = 0;
    while cursor < payload.len() {
        let from = cursor;
        let to = core::cmp::min(payload.len(), cursor + 9999);
        writer
            .write_all(&payload[from..to])
            .await
            .context("write_all operation")?;
        cursor = to;
    }
    writer.flush().await.context("Flush operation")?;

    Ok(())
}

pub async fn read_assert_payload<R: AsyncRead + Unpin>(reader: &mut R, expected_payload: &[u8]) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut buf = [0; 5120];
    let mut current_idx = 0;
    loop {
        if current_idx == expected_payload.len() {
            break;
        }

        let n = reader.read(&mut buf).await.context("read operation")?;
        if n == 0 {
            anyhow::bail!(
                "Read {current_idx} bytes, but expected exactly {} bytes",
                expected_payload.len()
            );
        }

        let from = current_idx;
        let to = current_idx + n;

        if to > expected_payload.len() {
            anyhow::bail!("Received too much bytes");
        }

        if expected_payload[from..to] != buf[..n] {
            anyhow::bail!("Received bytes didn't match expected payload ({from}..{to})");
        }

        current_idx += n;
    }

    Ok(())
}
