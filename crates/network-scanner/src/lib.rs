#![allow(clippy::unwrap_used)] // FIXME: fix warnings

#[macro_use]
extern crate tracing;

use std::mem::MaybeUninit;
use std::net::IpAddr;

use anyhow::Context;
use network_interface::Addr;
use network_scanner_proto::icmp_v4;

pub mod broadcast;
pub mod event_bus;
pub mod interfaces;
pub mod ip_utils;
pub mod mdns;
pub mod named_port;
pub mod netbios;
pub mod ping;
pub mod port_discovery;
pub mod scanner;
pub mod task_utils;

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("Ipv6 currently no t supported for this operation: {0}")]
    DoesNotSupportIpv6(String),

    #[error("IP range needs to be the same type")]
    IpRangeNeedsToBeTheSameType(IpAddr, IpAddr),

    #[error("Network interface does not have a netmask")]
    InterfaceDoesNotHaveNetmask(Addr),

    #[error("mDNS scan error: {0}")]
    MdnsError(#[from] mdns_sd::Error),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
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
    // SAFETY: Preconditions must be upheld by the caller.
    unsafe { &*(buf as *const [MaybeUninit<u8>] as *const [u8]) }
}

pub(crate) fn create_v4_echo_request() -> anyhow::Result<(icmp_v4::Icmpv4Packet, Vec<u8>)> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("now after UNIX_EPOCH")
        .as_secs();

    let echo_message = icmp_v4::Icmpv4Message::Echo {
        identifier: 0,
        sequence: 0,
        payload: time.to_be_bytes().to_vec(),
    };

    let packet = icmp_v4::Icmpv4Packet::from_message(echo_message);
    Ok((packet, time.to_be_bytes().to_vec()))
}
