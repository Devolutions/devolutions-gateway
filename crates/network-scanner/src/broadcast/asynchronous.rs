use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use network_scanner_net::runtime;
use network_scanner_proto::icmp_v4;
use socket2::SockAddr;

use crate::create_v4_echo_request;

use super::BroadcastEvent;

/// Broadcasts a ping to the given ip address
/// caller need to make sure that the ip address is a broadcast address
/// The timeout is for the read, if for more than given time no packet is received, the stream will end
pub async fn broadcast(
    ip: Ipv4Addr,
    read_time_out: Duration,
    runtime: Arc<runtime::Socket2Runtime>,
    task_manager: crate::task_utils::TaskManager,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<BroadcastEvent>> {
    let socket = runtime.new_socket(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;

    socket.set_broadcast(true)?;

    // skip verification, we are not interested in the response
    let (packet, _) = create_v4_echo_request()?;
    let (sender, receiver) = tokio::sync::mpsc::channel(255);

    task_manager.spawn_no_sub_task(async move {
        sender
            .send(BroadcastEvent::Start { broadcast_ip: ip })
            .await
            .context("failed to send broadcast start event")?;

        socket
            .send_to(&packet.to_bytes(true), &SockAddr::from(SocketAddr::new(ip.into(), 0)))
            .await?;

        tokio::time::timeout(read_time_out, loop_receive(socket, sender)).await??;
        debug!("Broadcast future dropped");
        anyhow::Ok(())
    });

    async fn loop_receive(
        mut socket: network_scanner_net::socket::AsyncRawSocket,
        sender: tokio::sync::mpsc::Sender<BroadcastEvent>,
    ) -> anyhow::Result<()> {
        let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
        loop {
            if let Ok((_, addr)) = socket.recv_from(&mut buffer).await {
                let ip = *addr
                    .as_socket_ipv4()
                    .context("unreachable: we only use ipv4 for broadcast")?
                    .ip();

                sender.send(BroadcastEvent::Entry { ip }).await?;
            };
        }
    }

    Ok(receiver)
}
