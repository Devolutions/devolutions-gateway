use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr},
};

use anyhow::Context;
use network_scanner_net::tokio_raw_socket::TokioRawSocket;
use network_scanner_proto::icmp_v4;

use tracing::trace;

#[macro_export]
macro_rules! create_echo_request {
    () => {{
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!(e))?
            .as_secs();

        let echo_message = network_scanner_proto::icmp_v4::Icmpv4Message::Echo {
            identifier: 0,
            sequence: 0,
            payload: time.to_be_bytes().to_vec(),
        };

        let packet = network_scanner_proto::icmp_v4::Icmpv4Packet::from_message(echo_message);
        (packet, time.to_be_bytes().to_vec())
    }};
}

pub async fn ping(ip: Ipv4Addr) -> anyhow::Result<()> {
    let socket = TokioRawSocket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .with_context(|| format!("failed to create tokio raw socket"))?;

    let addr = SocketAddr::new(ip.into(), 0);

    let (packet, verifier) = create_echo_request!();

    socket
        .send_to(&packet.to_bytes(true), socket2::SockAddr::from(addr))
        .await
        .with_context(|| format!("Failed to send packet to {}", ip))?;

    let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];

    let (size, _) = socket
        .recv_from(&mut buffer)
        .await
        .with_context(|| format!("Failed to receive packet from {}", ip))?;

    let inited_buf = buffer[..size].as_ref();

    let buffer = inited_buf
        .iter()
        .map(|u| unsafe { u.assume_init() })
        .collect::<Vec<u8>>();

    let packet = icmp_v4::Icmpv4Packet::parse(&buffer[..size])
        .with_context(|| format!("failed to parse incomming icmp v4 packet"))?;

    if let icmp_v4::Icmpv4Message::EchoReply { payload, .. } = packet.message {
        if payload != verifier {
            anyhow::bail!("payload does not match for echo reply");
        } else {
            Ok(())
        }
    } else {
        anyhow::bail!("received non-echo reply");
    }
}

pub fn block_ping(ip: Ipv4Addr) -> anyhow::Result<()> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;

    let addr = SocketAddr::new(ip.into(), 0);

    let (packet, verifier) = create_echo_request!();

    socket
        .send_to(&packet.to_bytes(true), &addr.into())
        .with_context(|| format!("Failed to send packet to {}", ip))?;

    let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
    let (size, _) = socket
        .recv_from(&mut buffer)
        .with_context(|| format!("Failed to receive packet from {}", ip))?;

    let inited_buf = buffer[..size].as_ref();

    let buffer = inited_buf
        .iter()
        .map(|u| unsafe { u.assume_init() })
        .collect::<Vec<u8>>();

    let packet = icmp_v4::Icmpv4Packet::parse(&buffer[..size]).with_context(|| format!("cannot parse icmp packet"))?;

    if let icmp_v4::Icmpv4Message::EchoReply { payload, .. } = packet.message {
        if payload != verifier {
            anyhow::bail!("payload does not match for echo reply");
        } else {
            Ok(())
        }
    } else {
        anyhow::bail!("received non-echo reply");
    }
}
