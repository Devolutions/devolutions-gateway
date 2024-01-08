use std::net::Ipv4Addr;

use network_scanner_net::tokio_raw_socket::TokioRawSocketStream;
use network_scanner_proto::icmp_v4;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::trace;

pub async fn ping(ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut socket = TokioRawSocketStream::connect(ip)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("cannot access system time")?
        .as_secs();

    let echo_message = network_scanner_proto::icmp_v4::Icmpv4Message::Echo {
        identifier: 0,
        sequence: 0,
        payload: time.to_be_bytes().to_vec(),
    };

    let packet = icmp_v4::Icmpv4Packet::from_message(echo_message);
    socket.write(&packet.to_bytes(true)).await?;
    let mut buffer = [0u8; icmp_v4::ICMPV4_MTU];
    let size = socket.read(&mut buffer).await.map_err(|e| anyhow::anyhow!(e))?;

    let packet = icmp_v4::Icmpv4Packet::parse(&buffer[..size]).map_err(|e| anyhow::anyhow!(e))?;

    match packet.message {
        icmp_v4::Icmpv4Message::EchoReply {
            payload,
            identifier,
            sequence,
        } => {
            trace!(%identifier, %sequence,?payload, "Received echo reply");
            if payload != time.to_be_bytes().to_vec() {
                anyhow::bail!("payload does not match for echo reply");
            }
        }
        _ => {
            anyhow::bail!("received non-echo reply");
        }
    }

    Ok(())
}
