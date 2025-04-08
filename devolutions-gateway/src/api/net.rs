use crate::http::HttpError;
use crate::token::{ApplicationProtocol, Protocol};
use crate::DgwState;
use axum::extract::ws::Message;
use axum::extract::WebSocketUpgrade;
use axum::response::Response;
use axum::{Json, Router};
use network_scanner::interfaces;
use network_scanner::scanner::{self, NetworkScannerParams};
use serde::Serialize;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    query_params: axum::extract::Query<NetworkScanQueryParams>,
) -> Result<Response, HttpError> {
    let scanner_params: NetworkScannerParams = query_params.0.into();

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

        loop {
            tokio::select! {
                result = stream.recv() => {
                    let Some(entry) = result else {
                        let _ = websocket
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::NORMAL,
                                reason: std::borrow::Cow::from("network scan finished successfully"),
                            })))
                            .await;

                        break;
                    };

                    let response = NetworkScanResponse::new(entry.addr, entry.port, entry.hostname, entry.service_type);

                    let Ok(response) = serde_json::to_string(&response) else {
                        warn!("Failed to serialize response");
                        continue;
                    };

                    if let Err(error) = websocket.send(Message::Text(response)).await {
                        warn!(%error, "Failed to send message");

                        // It is very likely that the websocket is already closed, but send it as a precaution.
                        let _ = websocket
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::ABNORMAL,
                                reason: std::borrow::Cow::from("network scan finished prematurely."),
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
        let _ = websocket.close().await;

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
        Self { ip, hostname, protocol }
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
pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub prefixlen: u32,
}

/// Interface's description
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    /// Interface's name
    pub name: String,
    /// Interface's address
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<Addr>))]
    pub addr: Vec<Addr>,
    /// MAC Address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_addr: Option<String>,
    /// Interface's index
    #[cfg_attr(feature = "openapi", schema(value_type = u32))]
    pub index: u32,
}

/// Network interface address
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Addr {
    /// IPV4 Interface from the AFINET network interface family
    V4(V4IfAddr),
    /// IPV6 Interface from the AFINET6 network interface family
    V6(V6IfAddr),
}

/// Netmask wrapper for IP address types
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

/// IPV4 Interface from the AFINET network interface family
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct V4IfAddr {
    /// The IP address for this network interface
    pub ip: Ipv4Addr,
    /// The broadcast address for this interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<Ipv4Addr>,
    /// The netmask for this interface
    pub netmask: Option<Netmask<Ipv4Addr>>,
}

/// IPV6 Interface from the AFINET6 network interface family
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct V6IfAddr {
    /// The IP address for this network interface
    pub ip: Ipv6Addr,
    /// The broadcast address for this interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<Ipv6Addr>,
    /// The netmask for this interface
    pub netmask: Option<Netmask<Ipv6Addr>>,
}

impl From<interfaces::NetworkInterface> for NetworkInterface {
    fn from(iface: interfaces::NetworkInterface) -> Self {
        let addr = iface
            .addr
            .into_iter()
            .map(|addr| {
                match addr {
                    interfaces::Addr::V4(v4) => Addr::V4(V4IfAddr {
                        ip: v4.ip,
                        broadcast: v4.broadcast,
                        netmask: v4.netmask.map(|netmask| Netmask(netmask)),
                    }),
                    interfaces::Addr::V6(v6) => {
                        Addr::V6(V6IfAddr {
                            ip: v6.ip,
                            broadcast: v6.broadcast,
                            netmask: v6.netmask.map(|netmask| Netmask(netmask)),
                        })
                    }
                }
            })
            .collect();

        NetworkInterface {
            name: iface.name,
            mac_addr: iface.mac_addr,
            addr,
            index: iface.index,
        }
    }
}
