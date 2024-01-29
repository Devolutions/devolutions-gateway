use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use network_scanner_net::runtime::Socket2Runtime;
use network_scanner_proto::icmp_v4;

pub async fn ping(runtime: Arc<Socket2Runtime>, ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut socket = runtime.new_socket(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;

    let addr = SocketAddr::new(ip.into(), 0);

    let (packet, verifier) = create_echo_request()?;
    socket
        .send_to(&packet.to_bytes(true), &addr.into())
        .await
        .with_context(|| format!("failed to send packet to {}", ip))?;

    let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
    let (size, _) = socket
        .recv_from(&mut buffer)
        .await
        .with_context(|| format!("failed to receive packet from {}", ip))?;

    let filled = unsafe { assume_init(&buffer[..size]) };

    let packet = icmp_v4::Icmpv4Packet::parse(filled).context("cannot parse icmp packet")?;

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

pub fn blocking_ping(ip: Ipv4Addr) -> anyhow::Result<()> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;

    let addr = SocketAddr::new(ip.into(), 0);

    let (packet, verifier) = create_echo_request()?;

    socket
        .send_to(&packet.to_bytes(true), &addr.into())
        .with_context(|| format!("failed to send packet to {}", ip))?;

    let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
    let (size, _) = socket
        .recv_from(&mut buffer)
        .with_context(|| format!("failed to receive packet from {}", ip))?;

    // SAFETY: `recv_from` returns the number of bytes written into the buffer, so the `size` first
    // elements are in an initialized state.
    let filled = unsafe { assume_init(&buffer[..size]) };

    let packet = icmp_v4::Icmpv4Packet::parse(filled).context("cannot parse icmp packet")?;

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

/// Assume the `buf`fer to be initialised.
///
/// # Safety
///
/// It is up to the caller to guarantee that the MaybeUninit<T> elements really are in an initialized state.
/// Calling this when the content is not yet fully initialized causes undefined behavior.
// TODO: replace with `MaybeUninit::slice_assume_init_ref` once stable.
// https://github.com/rust-lang/rust/issues/63569
pub(crate) unsafe fn assume_init(buf: &[MaybeUninit<u8>]) -> &[u8] {
    &*(buf as *const [MaybeUninit<u8>] as *const [u8])
}

pub(crate) fn create_echo_request() -> anyhow::Result<(icmp_v4::Icmpv4Packet, Vec<u8>)> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .with_context(|| "failed to get current time")?
        .as_secs();

    let echo_message = icmp_v4::Icmpv4Message::Echo {
        identifier: 0,
        sequence: 0,
        payload: time.to_be_bytes().to_vec(),
    };

    let packet = icmp_v4::Icmpv4Packet::from_message(echo_message);
    Ok((packet, time.to_be_bytes().to_vec()))
}
