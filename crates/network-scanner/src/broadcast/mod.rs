use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use anyhow::Context;

pub mod asynchronous;
pub mod blocking;

#[rustfmt::skip]
pub use asynchronous::broadcast;

#[derive(Debug, Clone)]
pub enum BroadcastEvent {
    Start { broadcast_ip: Ipv4Addr },
    Entry { ip: Ipv4Addr },
}

#[derive(Debug)]
pub struct BroadcastResponseEntry {
    pub addr: Ipv4Addr,
    pub packet: network_scanner_proto::icmp_v4::Icmpv4Packet,
}

impl BroadcastResponseEntry {
    pub(crate) unsafe fn from_raw(
        addr: socket2::SockAddr,
        payload: &[MaybeUninit<u8>],
        size: usize,
    ) -> anyhow::Result<Self> {
        let addr = *addr
            .as_socket_ipv4()
            .with_context(|| "sock addr is not ipv4".to_owned())?
            .ip(); // ip is private

        let payload = payload[..size]
            .as_ref()
            .iter()
            .map(|u| {
                // SAFETY: TODO: explain safety.
                unsafe { u.assume_init() }
            })
            .collect::<Vec<u8>>();

        let packet = network_scanner_proto::icmp_v4::Icmpv4Packet::parse(payload.as_slice())?;

        Ok(BroadcastResponseEntry { addr, packet })
    }

    pub fn verify(&self, verifier: &[u8]) -> bool {
        if let network_scanner_proto::icmp_v4::Icmpv4Message::EchoReply { payload, .. } = &self.packet.message {
            payload == verifier
        } else {
            false
        }
    }
}
