use anyhow::Context;
use crate::interfaces::NetworkInterface;

pub fn get_adapters() -> anyhow::Result<Vec<ipconfig::Adapter>> {
    ipconfig::get_adapters().context("Failed to get network adapters")
}

pub fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    ipconfig::get_adapters().context("Failed to get network interfaces")?.into_iter().map(|adapter| {
        Ok(adapter.into())
    }).collect()
}


impl From<ipconfig::Adapter> for NetworkInterface {
    fn from(adapter: ipconfig::Adapter) -> Self {
        NetworkInterface {
            name: adapter.adapter_name().to_string(),
            mac_address: adapter.physical_address().into_iter().map(|b| {
                b.to_vec()
            }).collect(),
            ipv4_address: adapter.ip_addresses().iter().find(|ip| ip.is_ipv4()).copied(),
            ipv6_address: adapter.ip_addresses().iter().find(|ip| ip.is_ipv6()).copied(),
            prefixes: adapter.prefixes().to_vec(),
            operational_status: adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp,
            default_gateway: adapter.gateways().to_vec(),
            dns_servers: adapter.dns_servers().to_vec()
        }
    }
}