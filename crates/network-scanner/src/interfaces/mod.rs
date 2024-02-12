#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;

use std::net::IpAddr;

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    name: String,
    mac_address: Vec<Vec<u8>>,
    ipv4_address: Option<IpAddr>,
    ipv6_address: Option<IpAddr>,
    prefixes: Vec<(IpAddr,u32)>,
    operational_status: bool,
    default_gateway: Vec<IpAddr>,
    dns_servers: Vec<IpAddr>,
}