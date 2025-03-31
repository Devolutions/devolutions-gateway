use crate::interfaces::NetworkInterface;
use anyhow::Context;

use super::MacAddr;

pub(crate) async fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    ipconfig::get_adapters()
        .context("failed to get network interfaces")?
        .into_iter()
        .map(|adapter| Ok(adapter.into()))
        .collect()
}

impl From<ipconfig::Adapter> for NetworkInterface {
    fn from(adapter: ipconfig::Adapter) -> Self {
        let mac_address: Option<MacAddr> = adapter.physical_address().and_then(|addr| addr.try_into().ok());

        NetworkInterface {
            id: adapter.adapter_name().to_owned(),
            name: adapter.friendly_name().to_owned(),
            description: Some(adapter.description().to_owned()),
            mac_address,
            ip_adresses: adapter.ip_addresses().iter().map(|ip| *ip).collect(),
            addresses: adapter
                .prefixes()
                .iter()
                .map(|(ip, prefix)| super::InterfaceAddress {
                    ip: *ip,
                    prefixlen: *prefix,
                })
                .collect(),
            operational_status: adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp,
            gateways: adapter.gateways().to_vec(),
            dns_servers: adapter.dns_servers().to_vec(),
        }
    }
}
