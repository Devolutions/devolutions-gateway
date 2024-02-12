#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
pub use windows::get_network_interfaces;

#[cfg(target_os = "linux")]
pub use linux::get_network_interfaces;

use std::net::IpAddr;

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    name: String,
    description: Option<String>,
    mac_address: Vec<Vec<u8>>,
    ipv4_address: Option<IpAddr>,
    ipv6_address: Option<IpAddr>,
    prefixes: Vec<(IpAddr,u32)>,
    operational_status: bool,
    default_gateway: Vec<IpAddr>,
    dns_servers: Vec<IpAddr>,
}