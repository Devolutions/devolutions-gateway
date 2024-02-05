use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use network_scanner_net::runtime;
use network_scanner_proto::icmp_v4;
use socket2::SockAddr;

use crate::{create_echo_request, Ok};

/// Broadcasts a ping to the given ip address
/// caller need to make sure that the ip address is a broadcast address
/// The timeout is for the read, if for more than given time no packet is received, the stream will end
pub async fn broadcast(
    ip: Ipv4Addr,
    read_time_out: Duration,
    runtime: Arc<runtime::Socket2Runtime>,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<Ipv4Addr>> {
    let socket = runtime.new_socket(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;

    socket.set_broadcast(true)?;

    // skip verification, we are not interested in the response
    let (packet, _) = create_echo_request()?;
    let (sender, receiver) = tokio::sync::mpsc::channel(255);

    tokio::task::spawn(async move {
        socket
            .send_to(&packet.to_bytes(true), &SockAddr::from(SocketAddr::new(ip.into(), 0)))
            .await?;
        tokio::time::timeout(read_time_out, loop_receive(socket, sender)).await??;
        Ok!()
    });

    async fn loop_receive(
        mut socket: network_scanner_net::socket::AsyncRawSocket,
        sender: tokio::sync::mpsc::Sender<Ipv4Addr>,
    ) -> anyhow::Result<()> {
        let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
        loop {
            if let Ok((_, addr)) = socket.recv_from(&mut buffer).await {
                let ip = *addr
                    .as_socket_ipv4()
                    .context("unreachable: we only use ipv4 for broadcast")?
                    .ip();
                sender.send(ip).await?;
            };
        }
    }

    Ok(receiver)
}
