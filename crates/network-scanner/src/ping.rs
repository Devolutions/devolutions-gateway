use std::net::Ipv4Addr;

use network_scanner_net::tokio_raw_socket::TokioRawSocketStream;
use network_scanner_proto::icmp_v4;

use crate::NetworkScanError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type NetowrkScanResult<T> = Result<T, NetworkScanError>;

pub async fn ping(ip: impl Into<Ipv4Addr>) -> NetowrkScanResult<()> {
    let mut socket = TokioRawSocketStream::connect(ip)
        .await
        .map_err(|e| NetworkScanError::IoError(e))?;

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| NetworkScanError::Other(format!("Failed to get time: {}", e)))?
        .as_secs();

    let echo_message = network_scanner_proto::icmp_v4::Icmpv4Message::Echo {
        identifier: 0,
        sequence: 0,
        payload: time.to_be_bytes().to_vec(),
    };

    let packet = icmp_v4::Icmpv4Packet::from_message(echo_message);
    socket.write(&packet.to_bytes(true)).await?;
    let mut buffer = [0u8; icmp_v4::ICMPV4_MTU];
    let size = socket
        .read(&mut buffer)
        .await
        .map_err(|e| NetworkScanError::IoError(e))?;

    let packet = icmp_v4::Icmpv4Packet::parse(&buffer[..size])
        .map_err(|e| NetworkScanError::ProtocolError(format!("Failed to parse ICMP packet: {:?}", e)))?;

    match packet.message {
        icmp_v4::Icmpv4Message::EchoReply {
            identifier,
            sequence,
            payload,
        } => {
            tracing::info!("Received echo reply: {:?} {:?} {:?}", identifier, sequence, payload);
            if payload != time.to_be_bytes().to_vec() {
                return Err(NetworkScanError::ProtocolError(format!("Payload mismatch")));
            }
        }
        _ => {
            return Err(NetworkScanError::ProtocolError(format!("Unexpected message type")));
        }
    }

    Ok(())
}
