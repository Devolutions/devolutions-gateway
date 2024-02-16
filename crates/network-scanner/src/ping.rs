use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use network_scanner_net::{runtime::Socket2Runtime, socket::AsyncRawSocket};
use network_scanner_proto::icmp_v4;
use tokio::time::timeout;

use crate::{create_echo_request, ip_utils::IpAddrRange};

pub fn ping_range(
    runtime: Arc<Socket2Runtime>,
    range: IpAddrRange,
    ping_interval: Duration,
    ping_wait_time: Duration,
    should_ping: impl Fn(IpAddr) -> bool + Send + Sync + 'static + Clone,
    task_manager: crate::task_utils::TaskManager,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<IpAddr>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(255);
    let mut futures = vec![];

    for ip in range.into_iter() {
        let socket = runtime.new_socket(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        let addr = SocketAddr::new(ip, 0);
        let sender = sender.clone();
        let should_ping = should_ping.clone();

        let ping_future = async move {
            if !should_ping(ip) {
                return anyhow::Ok(());
            }
            if try_ping(addr.into(), socket).await.is_ok() {
                sender.send(ip).await?;
            }
            anyhow::Ok(())
        };

        futures.push(ping_future);
    }

    task_manager.spawn(move |task_manager| async move {
        for future in futures {
            task_manager.with_timeout(ping_wait_time).spawn(|_| future);
            tokio::time::sleep(ping_interval).await;
        }
        anyhow::Ok(())
    });

    Ok(receiver)
}

pub async fn ping(runtime: Arc<Socket2Runtime>, ip: impl Into<IpAddr>, duration: Duration) -> anyhow::Result<()> {
    let socket = runtime.new_socket(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;
    let addr = SocketAddr::new(ip.into(), 0);
    timeout(duration, try_ping(addr.into(), socket)).await?
}

async fn try_ping(addr: socket2::SockAddr, mut socket: AsyncRawSocket) -> anyhow::Result<()> {
    // skip verification, we are not interested in the response
    let (packet, _) = create_echo_request()?;
    let packet_bytes = packet.to_bytes(true);

    socket.send_to(&packet_bytes, &addr).await?;

    let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
    socket.recv_from(&mut buffer).await?;
    Ok(())
}

pub fn blocking_ping(ip: Ipv4Addr) -> anyhow::Result<()> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;

    let addr = SocketAddr::new(ip.into(), 0);

    let (packet, _) = create_echo_request()?;

    socket
        .send_to(&packet.to_bytes(true), &addr.into())
        .with_context(|| format!("failed to send packet to {}", ip))?;

    let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
    let _ = socket
        .recv_from(&mut buffer)
        .with_context(|| format!("failed to receive packet from {}", ip))?;

    Ok(())
}
