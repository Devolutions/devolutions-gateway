use std::default;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use network_scanner_net::runtime::Socket2Runtime;
use network_scanner_net::socket::AsyncRawSocket;
use network_scanner_proto::icmp_v4;
use network_scanner_proto::icmp_v6::Icmpv6Message;
use tokio::time::timeout;

use crate::create_v4_echo_request;
use crate::ip_utils::IpAddrRange;

#[derive(Debug, Clone)]
pub enum PingFailedReason {
    Rejected,
    TimedOut,
}

impl std::fmt::Display for PingFailedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingFailedReason::Rejected => write!(f, "ping rejected"),
            PingFailedReason::TimedOut => write!(f, "ping timed out"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PingEvent {
    Start { ip: IpAddr },
    Success { ip: IpAddr, time: u128 },
    Failed { ip: IpAddr, reason: PingFailedReason },
}

pub fn ping_range(
    runtime: Arc<Socket2Runtime>,
    range: IpAddrRange,
    ping_interval: Duration,
    ping_wait_time: Duration,
    should_ping: impl Fn(IpAddr) -> bool + Send + Sync + 'static + Clone,
    task_manager: crate::task_utils::TaskManager,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<PingEvent>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(255);
    let mut futures = vec![];

    for ip in range.into_iter() {
        let socket = runtime.new_socket(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        let addr = SocketAddr::new(ip, 0);
        let should_ping = should_ping.clone();
        if !should_ping(ip) {
            continue;
        }

        let sender_clone = sender.clone();

        let ping_future = move || async move {
            let _ = sender_clone.send(PingEvent::Start { ip: addr.ip() }).await;
            let start_time = std::time::Instant::now();
            let ping_future = try_ping(addr.into(), socket);
            let ping_future = timeout(ping_wait_time, ping_future);
            match ping_future.await {
                Ok(Ok(_)) => {
                    let elapsed = start_time.elapsed().as_millis();
                    let _ = sender_clone
                        .send(PingEvent::Success {
                            ip: addr.ip(),
                            time: elapsed,
                        })
                        .await;
                }
                Ok(Err(_)) => {
                    let _ = sender_clone
                        .send(PingEvent::Failed {
                            ip: addr.ip(),
                            reason: PingFailedReason::Rejected,
                        })
                        .await;
                }
                Err(_) => {
                    let _ = sender_clone
                        .send(PingEvent::Failed {
                            ip: addr.ip(),
                            reason: PingFailedReason::TimedOut,
                        })
                        .await;
                }
            };

            anyhow::Ok(())
        };

        futures.push(ping_future);
    }

    task_manager.spawn(move |task_manager| async move {
        for future in futures {
            task_manager.spawn_no_sub_task(future());
            tokio::time::sleep(ping_interval).await;
        }
        anyhow::Ok(())
    });

    Ok(receiver)
}

pub async fn ping_addr(
    runtime: Arc<Socket2Runtime>,
    addr: impl ToSocketAddrs,
    duration: Duration,
) -> anyhow::Result<()> {
    let socket_addr = addr.to_socket_addrs()?.next().context("Hostname not found")?; //TODO return proper error
    let socket2_sockaddr: socket2::SockAddr = socket_addr.into();

    let socket = runtime.new_socket(
        socket2_sockaddr.domain(),
        socket2::Type::RAW,
        match socket_addr {
            SocketAddr::V4(_) => Some(socket2::Protocol::ICMPV4),
            SocketAddr::V6(_) => Some(socket2::Protocol::ICMPV6),
        },
    )?;

    timeout(duration, try_ping(socket2_sockaddr, socket)).await?
}

pub async fn ping(runtime: Arc<Socket2Runtime>, ip: impl Into<IpAddr>, duration: Duration) -> anyhow::Result<()> {
    let socket_addr = SocketAddr::new(ip.into(), 0);
    let socket2_sockaddr: socket2::SockAddr = socket_addr.into();

    let socket = runtime.new_socket(
        socket2_sockaddr.domain(),
        socket2::Type::RAW,
        match socket_addr {
            SocketAddr::V4(_) => Some(socket2::Protocol::ICMPV4),
            SocketAddr::V6(_) => Some(socket2::Protocol::ICMPV6),
        },
    )?;

    timeout(duration, try_ping(socket2_sockaddr, socket)).await?
}

async fn try_ping(addr: socket2::SockAddr, mut socket: AsyncRawSocket) -> anyhow::Result<()> {
    // skip verification, we are not interested in the response
    let (packet, _) = create_v4_echo_request()?;

    let packet_bytes = match addr.domain() {
        socket2::Domain::IPV4 => create_v4_echo_request()?.0.to_bytes(true),
        socket2::Domain::IPV6 => Icmpv6Message::EchoRequest {
            identifier: 42,
            sequence_number: 0,
            payload: vec![42; 32],
        }
        .into(),
        _ => return Err(anyhow::anyhow!("Can't ping a unix socket")),
    };

    socket.send_to(&packet_bytes, &addr).await?;

    // TODO: because this is a raw socket, packets indicating failure will reach us. we need to check the response code
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

    let (packet, _) = create_v4_echo_request()?;

    socket
        .send_to(&packet.to_bytes(true), &addr.into())
        .with_context(|| format!("failed to send packet to {ip}"))?;

    let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
    let _ = socket
        .recv_from(&mut buffer)
        .with_context(|| format!("failed to receive packet from {ip}"))?;

    Ok(())
}
