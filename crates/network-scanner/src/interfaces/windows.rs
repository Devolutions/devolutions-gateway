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
        let mac_addresses = adapter
            .physical_address()
            .iter()
            .filter_map(|mac| (*mac).try_into().ok())
            .collect();

        NetworkInterface {
            name: adapter.adapter_name().to_string(),
            description: Some(adapter.description().to_string()),
            mac_addresses,
            ip_addresses: adapter.ip_addresses().to_vec(),
            prefixes: adapter.prefixes().to_vec(),
            operational_status: adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp,
            gateways: adapter.gateways().to_vec(),
            dns_servers: adapter.dns_servers().to_vec(),
        }
    }
}
