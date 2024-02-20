use std::net::IpAddr;

use axum::extract::ws::Message;
use axum::extract::WebSocketUpgrade;
use axum::response::Response;
use network_scanner::scanner::{self, NetworkScannerParams};
use serde::Serialize;

use crate::http::HttpError;
use crate::token::{ApplicationProtocol, Protocol};

pub async fn handler(
    _token: crate::extract::NetScanToken,
    ws: WebSocketUpgrade,
    query_params: axum::extract::Query<NetworkScanQueryParams>,
) -> Result<Response, HttpError> {
    let scanner_params: NetworkScannerParams = query_params.0.into();

    let scanner = network_scanner::scanner::NetworkScanner::new(scanner_params).map_err(|e| {
        error!(error = format!("{e:#}"), "Failed to create network scanner");
        HttpError::internal().build(e)
    })?;

    let res = ws.on_upgrade(move |mut websocket| async move {
        let stream = match scanner.start() {
            Ok(stream) => stream,
            Err(e) => {
                error!(error = format!("{e:#}"), "Failed to start network scan");
                return;
            }
        };

        info!("Network scan started");

        loop {
            tokio::select! {
                result = stream.recv() => {
                    let Some((ip, dns, port,protocol)) = result else{
                        break;
                    };
                    let response = NetworkScanResponse::new(ip, port, dns,protocol);
                    let Ok(response) = serde_json::to_string(&response) else {
                        warn!("Failed to serialize response");
                        continue;
                    };

                    if let Err(error) = websocket.send(Message::Text(response)).await {
                        warn!(%error, "Failed to send message");
                        break;
                    }

                },
                msg = websocket.recv() => {

                    let Some(msg) = msg else {
                        break;
                    };

                    if let Ok(Message::Close(_)) = msg {
                        break;
                    }
                }
            }
        }

        info!("Network scan finished");

        stream.stop();
    });

    Ok(res)
}

#[derive(Debug, Deserialize)]
pub struct NetworkScanQueryParams {
    /// Interval in milliseconds (default is 200)
    pub ping_interval: Option<u64>,
    /// Timeout in milliseconds (default is 500)
    pub ping_timeout: Option<u64>,
    /// Timeout in milliseconds (default is 1000)
    pub broadcast_timeout: Option<u64>,
    /// Timeout in milliseconds (default is 1000)
    pub port_scan_timeout: Option<u64>,
    /// Timeout in milliseconds (default is 1000)
    pub netbios_timeout: Option<u64>,
    /// Interval in milliseconds (default is 200)
    pub netbios_interval: Option<u64>,
    /// The maximum time for each mdns query in milliseconds. (default is 5 * 1000)
    pub mdns_query_timeout: Option<u64>,
    /// The maximum duration for whole networking scan in milliseconds. Highly suggested!
    pub max_wait: Option<u64>,
}

const COMMON_PORTS: [u16; 11] = [22, 23, 80, 443, 389, 636, 3283, 3389, 5900, 5985, 5986];

impl From<NetworkScanQueryParams> for NetworkScannerParams {
    fn from(val: NetworkScanQueryParams) -> Self {
        NetworkScannerParams {
            ports: COMMON_PORTS.to_vec(),
            ping_interval: val.ping_interval.unwrap_or(200),
            ping_timeout: val.ping_timeout.unwrap_or(500),
            broadcast_timeout: val.broadcast_timeout.unwrap_or(1000),
            port_scan_timeout: val.port_scan_timeout.unwrap_or(1000),
            netbios_timeout: val.netbios_timeout.unwrap_or(1000),
            max_wait_time: val.max_wait.unwrap_or(120 * 1000),
            netbios_interval: val.netbios_interval.unwrap_or(200),
            mdns_query_timeout: val.mdns_query_timeout.unwrap_or(5 * 1000), // in milliseconds
        }
    }
}

#[derive(Debug, Serialize)]
pub struct NetworkScanResponse {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub protocol: ApplicationProtocol,
}

impl NetworkScanResponse {
    fn new(ip: IpAddr, port: u16, dns: Option<String>, service: Option<scanner::ServiceType>) -> Self {
        let hostname = dns;

        let protocol = if let Some(protocol) = service {
            match protocol {
                scanner::ServiceType::Ssh => ApplicationProtocol::Known(Protocol::Ssh),
                scanner::ServiceType::Telnet => ApplicationProtocol::Known(Protocol::Telnet),
                scanner::ServiceType::Http => ApplicationProtocol::Known(Protocol::Http),
                scanner::ServiceType::Https => ApplicationProtocol::Known(Protocol::Https),
                scanner::ServiceType::Ldap => ApplicationProtocol::Known(Protocol::Ldap),
                scanner::ServiceType::Ldaps => ApplicationProtocol::Known(Protocol::Ldaps),
                scanner::ServiceType::Rdp => ApplicationProtocol::Known(Protocol::Rdp),
                scanner::ServiceType::Vnc => ApplicationProtocol::Known(Protocol::Vnc),
                scanner::ServiceType::Ard => ApplicationProtocol::Known(Protocol::Ard),
                scanner::ServiceType::Sftp => ApplicationProtocol::Known(Protocol::Sftp),
                scanner::ServiceType::Scp => ApplicationProtocol::Known(Protocol::Scp),
            }
        } else {
            match port {
                22 => ApplicationProtocol::Known(Protocol::Ssh),
                23 => ApplicationProtocol::Known(Protocol::Telnet),
                80 => ApplicationProtocol::Known(Protocol::Http),
                443 => ApplicationProtocol::Known(Protocol::Https),
                389 => ApplicationProtocol::Known(Protocol::Ldap),
                636 => ApplicationProtocol::Known(Protocol::Ldaps),
                3389 => ApplicationProtocol::Known(Protocol::Rdp),
                5900 => ApplicationProtocol::Known(Protocol::Vnc),
                5985 => ApplicationProtocol::Known(Protocol::WinrmHttpPwsh),
                5986 => ApplicationProtocol::Known(Protocol::WinrmHttpsPwsh),
                _ => ApplicationProtocol::unknown(),
            }
        };
        Self { ip, hostname, protocol }
    }
}
