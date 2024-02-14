#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::get_network_interfaces;

#[cfg(target_os = "linux")]
pub use linux::get_network_interfaces;

use std::net::IpAddr;


#[derive(Debug, Clone)]
pub enum MacAddr {
    Eui64([u8; 8]),
    Eui48([u8; 6]),
}

impl TryFrom<&[u8]> for MacAddr {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            6 => {
                let mut eui48 = [0; 6];
                eui48.copy_from_slice(value);
                Ok(MacAddr::Eui48(eui48))
            }
            8 => {
                let mut eui64 = [0; 8];
                eui64.copy_from_slice(value);
                Ok(MacAddr::Eui64(eui64))
            }
            _ => Err(anyhow::anyhow!("invalid MAC address length")),
        }
    }
}


#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    pub mac_addresses: Vec<MacAddr>,
    pub ip_addresses: Vec<IpAddr>,
    pub prefixes: Vec<(IpAddr, u32)>,
    pub operational_status: bool,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}
