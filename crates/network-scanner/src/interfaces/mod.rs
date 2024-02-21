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
            _ => anyhow::bail!("invalid MAC address length"),
        }
    }
}

impl serde::Serialize for MacAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let stringified = match self {
                MacAddr::Eui64(b) => format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ),
                MacAddr::Eui48(b) => format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    b[0], b[1], b[2], b[3], b[4], b[5],
                ),
            };

            serializer.serialize_str(&stringified)
        } else {
            match self {
                MacAddr::Eui64(bytes) => serializer.serialize_bytes(bytes),
                MacAddr::Eui48(bytes) => serializer.serialize_bytes(bytes),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    pub mac_address: Option<MacAddr>,
    pub ip_addresses: Vec<IpAddr>,
    pub prefixes: Vec<(IpAddr, u32)>,
    pub operational_status: bool,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}
