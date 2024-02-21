use std::net::IpAddr;

use axum::Json;
use network_scanner::interfaces::{self, MacAddr};
use serde::Serialize;

use crate::http::HttpError;

pub async fn handler(_token: crate::extract::NetScanToken) -> Result<Json<Vec<NetworkInterface>>, HttpError> {
    let interfaces = network_scanner::interfaces::get_network_interfaces()
        .map_err(HttpError::internal().with_msg("failed to get network interfaces").err())?
        .into_iter()
        .map(NetworkInterface::from)
        .collect();

    Ok(Json(interfaces))
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<MacAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_addresses: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<(IpAddr, u32)>,
    pub operational_status: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<IpAddr>,
}

impl From<interfaces::NetworkInterface> for NetworkInterface {
    fn from(iface: interfaces::NetworkInterface) -> Self {
        Self {
            name: iface.name,
            description: iface.description,
            mac_address: iface.mac_address,
            ip_addresses: iface.ip_addresses,
            prefixes: iface.prefixes,
            operational_status: iface.operational_status,
            gateways: iface.gateways,
            dns_servers: iface.dns_servers,
        }
    }
}
