use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use proptest::array::{uniform4, uniform8};
use proptest::prelude::*;
use proxy_types::*;

pub fn port() -> impl Strategy<Value = u16> {
    any::<u16>()
}

pub fn ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
    uniform4(any::<u8>()).prop_map(Ipv4Addr::from)
}

pub fn ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
    uniform8(any::<u16>()).prop_map(Ipv6Addr::from)
}

pub fn ip_addr() -> impl Strategy<Value = IpAddr> {
    prop_oneof![ipv4_addr().prop_map(IpAddr::from), ipv6_addr().prop_map(IpAddr::from)]
}

pub fn socket_addr() -> impl Strategy<Value = SocketAddr> {
    (ip_addr(), port()).prop_map(|(ip, port)| SocketAddr::new(ip, port))
}

pub fn domain_addr() -> impl Strategy<Value = (String, u16)> {
    ("[a-z]{1,10}\\.[a-z]{1,5}", port())
}

pub fn dest_addr() -> impl Strategy<Value = DestAddr> {
    prop_oneof![
        socket_addr().prop_map(DestAddr::Ip),
        domain_addr().prop_map(|(host, port)| DestAddr::Domain(host, port))
    ]
}
