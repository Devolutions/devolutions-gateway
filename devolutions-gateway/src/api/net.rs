use crate::extract::RepeatQuery;
use crate::http::HttpError;
use crate::token::{ApplicationProtocol, Protocol};
use crate::DgwState;
use axum::extract::ws::{Message, Utf8Bytes};
use axum::extract::{RawQuery, WebSocketUpgrade};
use axum::response::Response;
use axum::{Json, Router};
use network_scanner::interfaces;
use network_scanner::ip_utils::IpAddrRange;
use network_scanner::scanner::{self, NetworkScannerParams, ScannerConfig};
use serde::Serialize;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    let router = Router::new().route("/scan", axum::routing::get(handle_network_scan));

    let router = if state.conf_handle.get_conf().debug.enable_unstable {
        // This route is currently unstable and disabled by default.
        router.route("/config", axum::routing::get(get_net_config))
    } else {
        router
    };

    router.with_state(state)
}

pub async fn handle_network_scan(
    _token: crate::extract::NetScanToken,
    ws: WebSocketUpgrade,
    RepeatQuery(query): RepeatQuery<NetworkScanQueryParams>,
) -> Result<Response, HttpError> {
    let scanner_params: NetworkScannerParams = query.try_into().map_err(|e| {
        error!(error = format!("{e:#}"), "Failed to parse query parameters");
        HttpError::bad_request().build(e)
    })?;

    let scanner = scanner::NetworkScanner::new(scanner_params).map_err(|e| {
        error!(error = format!("{e:#}"), "Failed to create network scanner");
        HttpError::internal().build(e)
    })?;

    let res = ws.on_upgrade(move |mut websocket| async move {
        let mut stream = match scanner.start() {
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
                    let Some(entry) = result else {
                        let _ = websocket
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::NORMAL,
                                reason: Utf8Bytes::from_static("network scan finished successfully"),
                            })))
                            .await;

                        break;
                    };

                    let response: NetworkScanResponse = entry.into();

                    let Ok(response) = serde_json::to_string(&response) else {
                        warn!("Failed to serialize response");
                        continue;
                    };

                    if let Err(error) = websocket.send(Message::Text(Utf8Bytes::from(response))).await {
                        warn!(%error, "Failed to send message");

                        // It is very likely that the websocket is already closed, but send it as a precaution.
                        let _ = websocket
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::ABNORMAL,
                                reason: Utf8Bytes::from_static("network scan finished prematurely."),
                            })))
                            .await;

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

        // Stop the network scanner, whatever the code path (error or not).
        stream.stop();

        // In case the websocket is not closed yet.
        // If the logic above is correct, it’s not necessary.
        let _ = futures::SinkExt::close(&mut websocket).await;

        info!("Network scan finished");
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
    /// The start and end IP address of the range to scan.
    /// for example: 10.10.0.0-10.10.0.255
    #[serde(default, rename = "range")]
    pub ranges: Vec<String>,
    /// The ports to scan. If not specified, the default ports will be used.
    #[serde(default, rename = "port")]
    pub ports: Vec<u16>,

    /// Enable the emission of ScanEvent::Ping for status start
    #[serde(default)]
    pub enable_ping_start: bool,

    /// Enable the execution of broadcast scan
    #[serde(default = "default_true")]
    pub enable_broadcast: bool,

    /// Enable the ping scan on subnet
    #[serde(default = "default_true")]
    pub enable_subnet_scan: bool,

    /// Enable ZeroConf/mDNS
    #[serde(default = "default_true")]
    pub enable_zeroconf: bool,

    /// Enable resolve dns
    #[serde(default = "default_true")]
    pub enable_resolve_dns: bool,
}

fn default_true() -> bool {
    true
}

const COMMON_PORTS: [u16; 11] = [22, 23, 80, 443, 389, 636, 3283, 3389, 5900, 5985, 5986];

impl TryFrom<NetworkScanQueryParams> for NetworkScannerParams {
    type Error = anyhow::Error;
    fn try_from(val: NetworkScanQueryParams) -> Result<Self, Self::Error> {
        debug!(query=?val, "Network scan query parameters");

        let ports = match val.ports.len() {
            0 => COMMON_PORTS.to_vec(),
            _ => val.ports,
        };

        let ping_interval = Duration::from_millis(val.ping_interval.unwrap_or(200));
        let ping_timeout = Duration::from_millis(val.ping_timeout.unwrap_or(500));
        let broadcast_timeout = Duration::from_millis(val.broadcast_timeout.unwrap_or(1000));
        let port_scan_timeout = Duration::from_millis(val.port_scan_timeout.unwrap_or(1000));
        let netbios_timeout = Duration::from_millis(val.netbios_timeout.unwrap_or(1000));
        let netbios_interval = Duration::from_millis(val.netbios_interval.unwrap_or(200));
        let mdns_query_timeout = Duration::from_millis(val.mdns_query_timeout.unwrap_or(5 * 1000));
        let max_wait_time = Duration::from_millis(val.max_wait.unwrap_or(120 * 1000));
        let ip_ranges = val
            .ranges
            .iter()
            .map(IpAddrRange::try_from)
            .collect::<Result<Vec<IpAddrRange>, anyhow::Error>>()?;

        Ok(NetworkScannerParams {
            config: ScannerConfig {
                ports,
                ping_interval,
                ping_timeout,
                broadcast_timeout,
                port_scan_timeout,
                netbios_timeout,
                max_wait_time,
                netbios_interval,
                mdns_query_timeout,
                ip_ranges,
            },
            toggle: scanner::ScannerToggles {
                enable_ping_start: val.enable_ping_start,
                enable_broadcast: val.enable_broadcast,
                enable_subnet_scan: val.enable_subnet_scan,
                enable_zeroconf: val.enable_zeroconf,
                enable_resolve_dns: val.enable_resolve_dns,
            },
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Start,
    Failed,
    Success,
}

#[derive(Debug, Serialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ScanEvent {
    Ping {
        ip_addr: IpAddr,
        status: Status,
        #[serde(skip_serializing_if = "Option::is_none")]
        time: Option<u128>,
    },
    Dns {
        ip_addr: IpAddr,
        hostname: String,
    },
}

impl From<scanner::ScanEvent> for ScanEvent {
    fn from(event: scanner::ScanEvent) -> Self {
        match event {
            scanner::ScanEvent::PingStart { ip_addr } => Self::Ping {
                ip_addr,
                status: Status::Start,
                time: None,
            },
            scanner::ScanEvent::PingSuccess { ip_addr, time } => Self::Ping {
                ip_addr,
                status: Status::Success,
                time: Some(time),
            },
            scanner::ScanEvent::PingFailed { ip_addr, .. } => Self::Ping {
                ip_addr,
                status: Status::Failed,
                time: None,
            },
            scanner::ScanEvent::Dns { ip_addr, hostname } => Self::Dns { ip_addr, hostname },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum NetworkScanResponse {
    Event(ScanEvent),
    Entry {
        ip: IpAddr,
        hostname: Option<String>,
        protocol: ApplicationProtocol,
    },
}

impl NetworkScanResponse {
    fn new(ip: IpAddr, port: u16, dns: Option<String>, service_type: Option<scanner::ServiceType>) -> Self {
        let hostname = dns;

        let protocol = if let Some(protocol) = service_type {
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
        Self::Entry { ip, hostname, protocol }
    }
}

impl From<scanner::ScanEntry> for NetworkScanResponse {
    fn from(entry: scanner::ScanEntry) -> Self {
        match entry {
            scanner::ScanEntry::ScanEvent(event) => Self::Event(event.into()),
            scanner::ScanEntry::Result {
                addr,
                hostname,
                port,
                service_type,
            } => Self::new(addr, port, hostname, service_type),
        }
    }
}

/// Lists network interfaces
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetNetConfig",
    tag = "Net",
    path = "/jet/net/config",
    responses(
        (status = 200, description = "Network interfaces", body = [Vec<NetworkInterface>]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("netscan_token" = [])),
))]
pub async fn get_net_config(_token: crate::extract::NetScanToken) -> Result<Json<Vec<NetworkInterface>>, HttpError> {
    let interfaces = interfaces::get_network_interfaces()
        .map_err(HttpError::internal().with_msg("failed to get network interfaces").err())?
        .into_iter()
        .map(NetworkInterface::from)
        .collect();

    Ok(Json(interfaces))
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    #[serde(rename = "addresses")]
    pub addrs: Vec<Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_addr: Option<String>,
    pub index: u32,
}

/// Network interface address
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Addr {
    V4(V4IfAddr),
    V6(V6IfAddr),
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Netmask<T>(pub T);

impl<T: fmt::Display> fmt::Display for Netmask<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T> Serialize for Netmask<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct V4IfAddr {
    pub ip: Ipv4Addr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netmask: Option<Netmask<Ipv4Addr>>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct V6IfAddr {
    pub ip: Ipv6Addr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<Ipv6Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netmask: Option<Netmask<Ipv6Addr>>,
}

impl From<interfaces::NetworkInterface> for NetworkInterface {
    fn from(iface: interfaces::NetworkInterface) -> Self {
        let addr = iface
            .addr
            .into_iter()
            .map(|addr| match addr {
                interfaces::Addr::V4(v4) => Addr::V4(V4IfAddr {
                    ip: v4.ip,
                    broadcast: v4.broadcast,
                    netmask: v4.netmask.map(Netmask),
                }),
                interfaces::Addr::V6(v6) => Addr::V6(V6IfAddr {
                    ip: v6.ip,
                    broadcast: v6.broadcast,
                    netmask: v6.netmask.map(Netmask),
                }),
            })
            .collect();

        NetworkInterface {
            name: iface.name,
            mac_addr: iface.mac_addr,
            addrs: addr,
            index: iface.index,
        }
    }
}
