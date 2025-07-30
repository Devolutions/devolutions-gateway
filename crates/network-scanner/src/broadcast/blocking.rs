use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context;

use network_scanner_proto::icmp_v4;

use crate::create_v4_echo_request;

use super::BroadcastResponseEntry;

pub struct BorcastBlockStream {
    socket: socket2::Socket,
    verifier: Vec<u8>,
    should_verify: bool,
}

impl Iterator for BorcastBlockStream {
    type Item = anyhow::Result<BroadcastResponseEntry>;

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

        // SAFETY: TODO: explain safety.
        let ping_result = unsafe { BroadcastResponseEntry::from_raw(addr, &buffer, size) };

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

    let (packet, verifier) = create_v4_echo_request()?;

    trace!(?packet, "Sending packet");
    socket
        .send_to(&packet.to_bytes(true), &addr.into())
        .with_context(|| format!("Failed to send packet to {ip}"))?;

    Ok(BorcastBlockStream {
        socket,
        verifier,
        should_verify: true,
    })
}
