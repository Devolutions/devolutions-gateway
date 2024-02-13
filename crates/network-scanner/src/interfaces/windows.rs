use std::net::IpAddr;

use crate::interfaces::NetworkInterface;
use anyhow::Context;

pub fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    ipconfig::get_adapters()
        .context("Failed to get network interfaces")?
        .into_iter()
        .map(|adapter| Ok(adapter.into()))
        .collect()
}

impl From<ipconfig::Adapter> for NetworkInterface {
    fn from(adapter: ipconfig::Adapter) -> Self {
        NetworkInterface {
            name: adapter.adapter_name().to_string(),
            description: Some(adapter.description().to_string()),
            mac_address: adapter.physical_address().into_iter().map(|b| b.to_vec()).collect(),
            ipv4_address: adapter
                .ip_addresses()
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(ipv4) => Some(ipv4.clone()),
                    _ => None,
                })
                .collect(),
            ipv6_address: adapter
                .ip_addresses()
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(ipv6) => Some(ipv6.clone()),
                    _ => None,
                })
                .collect(),
            prefixes: adapter.prefixes().to_vec(),
            operational_status: adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp,
            default_gateway: adapter.gateways().to_vec(),
            dns_servers: adapter.dns_servers().to_vec(),
        }
    }
}
