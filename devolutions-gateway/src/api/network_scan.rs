use std::net::IpAddr;

use axum::{
    extract::{ws::Message, State, WebSocketUpgrade},
    response::Response,
};

use network_scanner::scanner::NetworkScannerParams;
use serde::Serialize;

use crate::{http::HttpError, DgwState};

pub async fn handler(
    _: State<DgwState>,
    ws: WebSocketUpgrade,
    query_params: axum::extract::Query<NetworkScanQueryParams>,
) -> Result<Response, HttpError> {
    let scanner_params: NetworkScannerParams = query_params.0.into();

    let scanner = network_scanner::scanner::NetworkScanner::new(scanner_params).map_err(|e| {
        tracing::error!("Failed to create network scanner: {:?}", e);
        HttpError::internal().build(e)
    })?;

    let res = ws.on_upgrade(move |mut websocket| async move {
        let stream = scanner.start().expect("Failed to start network scanner");
        tracing::info!("Network scan started");
        loop {
            tokio::select! {
                result = stream.recv() => {
                    let Some((ip, dns, port)) = result else{
                        break;
                    };
                    let response = NetworkScanResponse::new(ip, port, dns);
                    let Ok(response) = serde_json::to_string(&response) else {
                        warn!("Failed to serialize response");
                        continue;
                    };

                    if let Err(e) = websocket.send(Message::Text(response)).await {
                        tracing::info!("Failed to send message: {:?}", e);
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
        tracing::info!("Network scan finished");
        stream.stop();
    });
    Ok(res)
}

#[derive(Debug, Deserialize)]
pub struct NetworkScanQueryParams {
    pub ping_interval: Option<u64>,     // in milliseconds,default 200
    pub ping_timeout: Option<u64>,      // in milliseconds,default 500
    pub broadcast_timeout: Option<u64>, // in milliseconds,default 1000
    pub port_scan_timeout: Option<u64>, // in milliseconds,default 1000
    pub netbios_timeout: Option<u64>,   // in milliseconds,default 1000
    pub netbios_interval: Option<u64>,  // in milliseconds,default 200
    pub max_wait: Option<u64>,          // max_wait for entire scan duration in milliseconds, suggested!
}

const FAMOUS_PORTS: [u16; 10] = [22, 23, 80, 443, 389, 636, 3389, 5900, 5985, 5986];
impl From<NetworkScanQueryParams> for NetworkScannerParams {
    fn from(val: NetworkScanQueryParams) -> Self {
        NetworkScannerParams {
            ports: FAMOUS_PORTS.to_vec(),
            ping_interval: val.ping_interval.unwrap_or(200),
            ping_timeout: val.ping_timeout.unwrap_or(500),
            broadcast_timeout: val.broadcast_timeout.unwrap_or(1000),
            port_scan_timeout: val.port_scan_timeout.unwrap_or(1000),
            netbios_timeout: val.netbios_timeout.unwrap_or(1000),
            max_wait_time: val.max_wait.unwrap_or(120 * 1000),
            netbios_interval: val.netbios_interval.unwrap_or(200),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct NetworkScanResponse {
    pub ip: String,
    pub hostname: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
}

impl NetworkScanResponse {
    fn new(ip: IpAddr, port: u16, dns: Option<String>) -> Self {
        let hostname = dns;
        // match famouse ports, ssh,telnet,http,https,ldap,ldaps,rdp,vnc,winrm
        let type_ = match port {
            22 => "SSH",
            23 => "Telnet",
            80 => "HTTP",
            443 => "HTTPS",
            389 => "LDAP",
            636 => "LDAPS",
            3389 => "RDP",
            5900 => "VNC",
            5985 | 5986 => "WinRM", // WinRM typically runs on ports 5985 (HTTP) and 5986 (HTTPS)
            _ => "Unknown",
        }
        .to_string();

        Self {
            ip: ip.to_string(),
            hostname,
            type_,
        }
    }
}
