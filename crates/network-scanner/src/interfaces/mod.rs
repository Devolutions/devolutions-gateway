#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

mod filter;

pub use filter::Filter;

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum MacAddr {
    Eui64([u8; 8]),
    Eui48([u8; 6]),
}

pub async fn get_network_interfaces(filter: Filter) -> anyhow::Result<Vec<NetworkInterface>> {
    #[cfg(target_os = "windows")]
    let result = { windows::get_network_interfaces().await };
    #[cfg(target_os = "linux")]
    let result = { linux::get_network_interfaces().await };

    result.map(|interfaces| {
        interfaces
            .into_iter()
            .filter(|interface| {
                if !filter.include_loopback {
                    return !filter::is_loop_back(interface);
                }
                true
            })
            .map(|interface| filter::filter_out_ipv6_if(filter.ignore_ipv6, interface))
            .collect()
    })
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
pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub prefixlen: u32,
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    // Linux interfaces does not come with an id
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub mac_address: Option<MacAddr>,
    pub routes: Vec<InterfaceAddress>,
    pub ip_adresses: Vec<IpAddr>,
    pub operational_status: bool,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}
