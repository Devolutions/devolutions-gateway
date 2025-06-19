use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use axum::extract::ws::{Message, Utf8Bytes};
use axum::extract::WebSocketUpgrade;
use axum::response::Response;
use axum::{Json, Router};
use network_scanner::event_bus::ScannerEvent;
use network_scanner::interfaces;
use network_scanner::ip_utils::IpAddrRange;
use network_scanner::mdns::MdnsEvent;
use network_scanner::named_port::{MaybeNamedPort, NamedPort};
use network_scanner::netbios::NetBiosEvent;
use network_scanner::ping::PingEvent;
use network_scanner::port_discovery::TcpKnockEvent;
use network_scanner::scanner::{self, DnsEvent, NetworkScannerParams, ScannerConfig, TcpKnockWithHost};
use serde::{Deserialize, Serialize};

use crate::extract::RepeatQuery;
use crate::http::HttpError;
use crate::token::Protocol;
use crate::DgwState;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    let router = Router::new()
        .route("/scan", axum::routing::get(handle_network_scan))
        .route("/config", axum::routing::get(get_net_config));

    router.with_state(state)
}

pub async fn handle_network_scan(
    _token: crate::extract::NetScanToken,
    ws: WebSocketUpgrade,
    RepeatQuery(query): RepeatQuery<NetworkScanQueryParams>,
) -> Result<Response, HttpError> {
    let (scanner_params, filter) = query.try_into().map_err(
        HttpError::bad_request()
            .with_msg("failed to parse query parameters")
            .err(),
    )?;

    let scanner = scanner::NetworkScanner::new(scanner_params).map_err(|e| {
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

        let mut receiver = stream.subscribe::<NetworkScanResponse>().await;

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    let Ok(response) = result else {
                        let _ = websocket
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::NORMAL,
                                reason: Utf8Bytes::from_static("network scan finished successfully"),
                            })))
                            .await;

                        break;
                    };

                    if !filter.should_emit(&response) {
                        continue;
                    }

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
    #[serde(default, rename = "probe")]
    pub probes: Vec<Probe>,

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

    /// Enable Tcp port knocking and ping failure event
    #[serde(default)]
    pub enable_failure: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub enum Probe {
    Ping,
    Port(MaybeNamedPort),
}

impl TryFrom<&str> for Probe {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "ping" => Ok(Probe::Ping),
            _ => MaybeNamedPort::try_from(value).map(Probe::Port),
        }
    }
}

impl<'de> Deserialize<'de> for Probe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Probe::try_from(value.as_str()).map_err(serde::de::Error::custom)
    }
}

const COMMON_PORTS: [u16; 11] = [22, 23, 80, 443, 389, 636, 3283, 3389, 5900, 5985, 5986];

impl TryFrom<NetworkScanQueryParams> for (NetworkScannerParams, EventFilter) {
    type Error = anyhow::Error;
    fn try_from(val: NetworkScanQueryParams) -> Result<Self, Self::Error> {
        debug!(query=?val, "Network scan query parameters");

        let probe: Vec<Probe> = match val.probes.len() {
            0 => COMMON_PORTS.iter().map(|port| Probe::Port((*port).into())).collect(),
            _ => val.probes,
        };

        let enable_ping_event = probe.iter().any(|probe| matches!(probe, Probe::Ping));
        let ports = probe
            .into_iter()
            .filter_map(|probe| match probe {
                Probe::Ping => None,
                Probe::Port(port) => Some(port),
            })
            .collect::<Vec<_>>();

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

        let scanner_param = NetworkScannerParams {
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
                enable_broadcast: val.enable_broadcast,
                enable_subnet_scan: val.enable_subnet_scan,
                enable_zeroconf: val.enable_zeroconf,
                enable_resolve_dns: val.enable_resolve_dns,
            },
        };

        let event_filter = EventFilter {
            enable_ping_event,
            enable_failure: val.enable_failure,
        };

        Ok((scanner_param, event_filter))
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
        ip: IpAddr,
        status: Status,
        #[serde(skip_serializing_if = "Option::is_none")]
        time: Option<u128>,
    },
    Host {
        ip: IpAddr,
        hostname: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum TcpKnockProbe {
    Number(u16),
    NamedApplication(Protocol),
}

impl From<MaybeNamedPort> for TcpKnockProbe {
    fn from(port: MaybeNamedPort) -> Self {
        match port {
            MaybeNamedPort::Port(port) => TcpKnockProbe::Number(port),
            MaybeNamedPort::Named(named_port) => TcpKnockProbe::NamedApplication(named_port.into()),
        }
    }
}

impl From<NamedPort> for Protocol {
    fn from(named_port: NamedPort) -> Self {
        match named_port {
            NamedPort::Rdp => Protocol::Rdp,
            NamedPort::Ard => Protocol::Ard,
            NamedPort::Vnc => Protocol::Vnc,
            NamedPort::Ssh => Protocol::Ssh,
            NamedPort::Sshpwsh => Protocol::SshPwsh,
            NamedPort::Sftp => Protocol::Sftp,
            NamedPort::Scp => Protocol::Scp,
            NamedPort::Telnet => Protocol::Telnet,
            NamedPort::WinrmHttpPwsh => Protocol::WinrmHttpPwsh,
            NamedPort::WinrmHttpsPwsh => Protocol::WinrmHttpsPwsh,
            NamedPort::Http => Protocol::Http,
            NamedPort::Https => Protocol::Https,
            NamedPort::Ldap => Protocol::Ldap,
            NamedPort::Ldaps => Protocol::Ldaps,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum NetworkScanResponse {
    Event(ScanEvent),
    Entry {
        ip: IpAddr,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        protocol: TcpKnockProbe,
        status: Status,
    },
}

impl TryFrom<ScannerEvent> for NetworkScanResponse {
    type Error = ();

    fn try_from(event: ScannerEvent) -> Result<Self, Self::Error> {
        match event {
            ScannerEvent::Ping(PingEvent::Success { ip, time }) => Ok(NetworkScanResponse::Event(ScanEvent::Ping {
                ip,
                status: Status::Success,
                time: Some(time),
            })),
            ScannerEvent::Ping(PingEvent::Failed { ip, .. }) => Ok(NetworkScanResponse::Event(ScanEvent::Ping {
                ip,
                status: Status::Failed,
                time: None,
            })),
            ScannerEvent::Ping(PingEvent::Start { ip }) => Ok(NetworkScanResponse::Event(ScanEvent::Ping {
                ip,
                status: Status::Start,
                time: None,
            })),
            ScannerEvent::Dns(DnsEvent::Success { ip, hostname }) => {
                Ok(NetworkScanResponse::Event(ScanEvent::Host { ip, hostname }))
            }
            ScannerEvent::Mdns(MdnsEvent::ServiceResolved {
                addr,
                device_name,
                protocol,
                port,
            }) => {
                let protocol = match protocol {
                    None => None,
                    Some(protocol) => Some(match protocol {
                        scanner::ServiceType::Rdp => Protocol::Rdp,
                        scanner::ServiceType::Ard => Protocol::Ard,
                        scanner::ServiceType::Vnc => Protocol::Vnc,
                        scanner::ServiceType::Ssh => Protocol::Ssh,
                        scanner::ServiceType::Sftp => Protocol::Sftp,
                        scanner::ServiceType::Scp => Protocol::Scp,
                        scanner::ServiceType::Telnet => Protocol::Telnet,
                        scanner::ServiceType::Http => Protocol::Http,
                        scanner::ServiceType::Https => Protocol::Https,
                        scanner::ServiceType::Ldap => Protocol::Ldap,
                        scanner::ServiceType::Ldaps => Protocol::Ldaps,
                    }),
                };

                let protocol = match protocol {
                    Some(protocol) => TcpKnockProbe::NamedApplication(protocol),
                    None => TcpKnockProbe::Number(port),
                };

                Ok(NetworkScanResponse::Entry {
                    ip: addr,
                    hostname: Some(device_name),
                    protocol,
                    status: Status::Success,
                })
            }
            ScannerEvent::NetBios(NetBiosEvent::Success { ip, name }) => {
                Ok(NetworkScanResponse::Event(ScanEvent::Host {
                    ip: ip.into(),
                    hostname: name,
                }))
            }
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost { tcp_knock, host }) => match tcp_knock {
                TcpKnockEvent::Success { ip, port } => {
                    let protocol = port.into();
                    Ok(NetworkScanResponse::Entry {
                        ip,
                        hostname: host,
                        protocol,
                        status: Status::Success,
                    })
                }
                TcpKnockEvent::Failed { ip, port, .. } => {
                    let protocol = port.into();
                    Ok(NetworkScanResponse::Entry {
                        ip,
                        hostname: host,
                        protocol,
                        status: Status::Failed,
                    })
                }
                _ => Err(()),
            },
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EventFilter {
    // Emit ping event or not, we'll need ping event for tcp knock anyway, so we don't turn it off, instead, we just ignore the event
    enable_ping_event: bool,
    // Emit ping/tcp knock event failure or not
    enable_failure: bool,
}

impl EventFilter {
    fn should_emit(&self, response: &NetworkScanResponse) -> bool {
        match response {
            NetworkScanResponse::Event(scan_event) => match scan_event {
                ScanEvent::Ping { status, .. } if self.enable_ping_event => {
                    if matches!(status, Status::Failed) && !self.enable_failure {
                        return false;
                    }

                    true
                }
                ScanEvent::Host { .. } => true,
                _ => false,
            },
            NetworkScanResponse::Entry { status, .. } => {
                if matches!(status, Status::Failed) && !self.enable_failure {
                    return false;
                }

                true
            }
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
        (status = 200, description = "Network interfaces", body = [HashMap<String, Vec<InterfaceInfo>>]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("netscan_token" = [])),
))]
pub(crate) async fn get_net_config(
    _token: crate::extract::NetScanToken,
) -> Result<Json<HashMap<String, Vec<InterfaceInfo>>>, HttpError> {
    let net_ifaces = interfaces::get_network_interfaces()
        .map_err(HttpError::internal().with_msg("failed to get network interfaces").err())?;

    let mut interface_map = HashMap::new();

    for iface in net_ifaces {
        let addresses: Vec<InterfaceInfo> = iface
            .addr
            .into_iter()
            .map(|addr| match addr {
                interfaces::Addr::V4(addr) => InterfaceInfo {
                    address: IfAddress::V4 {
                        address: addr.ip,
                        broadcast: addr.broadcast,
                        netmask: addr.netmask,
                    },
                    mac: iface.mac_addr.clone(),
                },
                interfaces::Addr::V6(addr) => InterfaceInfo {
                    address: IfAddress::V6 {
                        address: addr.ip,
                        broadcast: addr.broadcast,
                        netmask: addr.netmask,
                    },
                    mac: iface.mac_addr.clone(),
                },
            })
            .collect();

        interface_map.insert(iface.name, addresses);
    }

    Ok(Json(interface_map))
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InterfaceInfo {
    #[serde(flatten)]
    address: IfAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "family")]
enum IfAddress {
    #[serde(rename = "IPv4")]
    V4 {
        address: Ipv4Addr,
        #[serde(skip_serializing_if = "Option::is_none")]
        broadcast: Option<Ipv4Addr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        netmask: Option<Ipv4Addr>,
    },
    #[serde(rename = "IPv6")]
    V6 {
        address: Ipv6Addr,
        #[serde(skip_serializing_if = "Option::is_none")]
        broadcast: Option<Ipv6Addr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        netmask: Option<Ipv6Addr>,
    },
}
