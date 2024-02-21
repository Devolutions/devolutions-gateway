use std::net::IpAddr;

use axum::body::Body;
use axum::response::Response;
use network_scanner::interfaces::{MacAddr, NetworkInterface};
use serde::Serialize;

use crate::http::HttpError;

pub async fn handler(_netscan_claim: crate::extract::NetScanToken) -> Result<Response, HttpError> {
    let res = network_scanner::interfaces::get_network_interfaces().map_err(|e| {
        tracing::error!("failed to get network interfaces: {:?}", e);
        HttpError::internal().build(e)
    })?;

    let body = serde_json::to_string(&res.into_iter().map(|i| i.into()).collect::<Vec<NetworkInterfaceDto>>())
        .map_err(|e| {
            tracing::error!("failed to serialize network interfaces: {:?}", e);
            HttpError::internal().build(e)
        })?;

    Response::builder().body(Body::from(body)).map_err(|e| {
        tracing::error!("failed to create response: {:?}", e);
        HttpError::internal().build(e)
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterfaceDto {
    pub name: String,
    pub description: Option<String>,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub prefixes: Vec<(IpAddr, u32)>,
    pub operational_status: bool,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}

impl From<NetworkInterface> for NetworkInterfaceDto {
    fn from(
        NetworkInterface {
            name,
            description,
            mac_address,
            ip_addresses,
            prefixes,
            operational_status,
            gateways,
            dns_servers,
        }: NetworkInterface,
    ) -> Self {
        let mac_address = mac_address.map(|mac| match mac {
            MacAddr::Eui48(mac) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
            MacAddr::Eui64(mac) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]
            ),
        });

        Self {
            name,
            description,
            mac_address,
            ip_addresses,
            prefixes,
            operational_status,
            gateways,
            dns_servers,
        }
    }
}
