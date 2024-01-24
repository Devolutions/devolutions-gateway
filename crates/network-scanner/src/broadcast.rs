use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::Context;
use network_scanner_net::socket::AsyncRawSocket;
use network_scanner_proto::icmp_v4;
use socket2::SockAddr;

use crate::ping::create_echo_request;

#[derive(Debug)]
pub struct PingResponse {
    pub addr: Ipv4Addr,
    pub packet: icmp_v4::Icmpv4Packet,
}

impl PingResponse {
    pub(crate) unsafe fn from_raw(
        addr: socket2::SockAddr,
        payload: &[MaybeUninit<u8>],
        size: usize,
    ) -> anyhow::Result<Self> {
        let addr = *addr
            .as_socket_ipv4()
            .with_context(|| "sock addr is not ipv4".to_string())?
            .ip(); // ip is private

        let payload = payload[..size]
            .as_ref()
            .iter()
            .map(|u| unsafe { u.assume_init() })
            .collect::<Vec<u8>>();

        let packet = icmp_v4::Icmpv4Packet::parse(payload.as_slice())?;

        Ok(PingResponse { addr, packet })
    }

    pub fn verify(&self, verifier: &[u8]) -> bool {
        if let icmp_v4::Icmpv4Message::EchoReply { payload, .. } = &self.packet.message {
            payload == verifier
        } else {
            false
        }
    }
}

type StreamReceiver = tokio::sync::mpsc::Receiver<anyhow::Result<(Vec<MaybeUninit<u8>>, SockAddr), std::io::Error>>;
pub struct BroadcastStream {
    receiver: StreamReceiver,
    verifier: Vec<u8>,
    should_verify: bool,
}

impl BroadcastStream {
    pub fn should_verify(&mut self, should_verify: bool) {
        self.should_verify = should_verify;
    }
}

impl futures::stream::Stream for BroadcastStream {
    type Item = anyhow::Result<PingResponse>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let ready_res = match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(res) => res,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };

        let not_none_res = match ready_res {
            Some(res) => res,
            None => return std::task::Poll::Ready(None),
        };

        let (buf, addr) = match not_none_res {
            Ok(res) => res,
            Err(e) => return std::task::Poll::Ready(Some(Err(e.into()))),
        };

        let ping_result = unsafe { PingResponse::from_raw(addr, &buf, buf.len()) };

        let ping_result = match ping_result {
            Ok(a) => a,
            Err(e) => return std::task::Poll::Ready(Some(Err(e))),
        };

        if self.should_verify && !ping_result.verify(&self.verifier) {
            return std::task::Poll::Ready(Some(Err(anyhow::anyhow!("failed to verify ping response"))));
        }

        std::task::Poll::Ready(Some(Ok(ping_result)))
    }
}

/// Broadcasts a ping to the given ip address
/// caller need to make sure that the ip address is a broadcast address
pub async fn broadcast(
    ip: Ipv4Addr,
    read_time_out: Option<Duration>,
    mut socket: AsyncRawSocket,
) -> anyhow::Result<BroadcastStream> {
    socket.set_broadcast(true)?;
    if let Some(time_out) = read_time_out {
        socket.set_read_timeout(time_out)?;
    }
    let (packet, verifier) = create_echo_request()?;
    socket
        .send_to(&packet.to_bytes(true), &SockAddr::from(SocketAddr::new(ip.into(), 0)))
        .await?;
    let (sender, receiver) = tokio::sync::mpsc::channel(255);

    let _handle = tokio::task::spawn(async move {
        let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
        loop {
            let future = socket.recv_from(&mut buffer);

            let result = match tokio::time::timeout(read_time_out.unwrap_or(Duration::from_secs(200)), future).await {
                Ok(res) => res,
                Err(e) => {
                    sender
                        .send(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, e)))
                        .await?;
                    break;
                }
            };

            let (size, addr) = match result {
                Ok(res) => res,
                Err(e) => {
                    if sender.send(Err(e)).await.is_err() {
                        tracing::error!("channel failed, sending Err to receiver");
                    }
                    break;
                }
            };

            let buffer_copy = buffer[..size].as_ref().to_vec();
            sender.send(Ok((buffer_copy, addr))).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    Ok(BroadcastStream {
        receiver,
        verifier,
        should_verify: true,
    })
}

pub struct BorcastBlockStream {
    socket: socket2::Socket,
    verifier: Vec<u8>,
    should_verify: bool,
}

impl Iterator for BorcastBlockStream {
    type Item = anyhow::Result<PingResponse>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [MaybeUninit::uninit(); icmp_v4::ICMPV4_MTU];
        let res = self.socket.recv_from(&mut buffer);

        let (size, addr) = match res {
            Ok(res) => res,
            Err(e) => {
                return Some(Err(e.into()));
            }
        };

        if size == 0 {
            return None;
        }

        let ping_result = unsafe { PingResponse::from_raw(addr, &buffer, size) };

        let ping_result = match ping_result {
            Ok(a) => a,
            Err(e) => return Some(Err(e)),
        };

        if self.should_verify && !ping_result.verify(&self.verifier) {
            return Some(Err(anyhow::anyhow!("failed to verify ping response")));
        }

        Some(Ok(ping_result))
    }
}

impl BorcastBlockStream {
    pub fn should_verify(&mut self, should_verify: bool) {
        self.should_verify = should_verify;
    }
}

pub fn block_broadcast(ip: Ipv4Addr, read_time_out: Option<Duration>) -> anyhow::Result<BorcastBlockStream> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;
    socket.set_broadcast(true)?;

    if let Some(time_out) = read_time_out {
        socket.set_read_timeout(Some(time_out))?;
    }

    let addr = SocketAddr::new(ip.into(), 0);

    let (packet, verifier) = create_echo_request()?;

    tracing::trace!(?packet, "sending packet");
    socket
        .send_to(&packet.to_bytes(true), &addr.into())
        .with_context(|| format!("Failed to send packet to {}", ip))?;

    Ok(BorcastBlockStream {
        socket,
        verifier,
        should_verify: true,
    })
}
