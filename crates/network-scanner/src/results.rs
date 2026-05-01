use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::broadcast::BroadcastEvent;
use crate::event_bus::ScannerEvent;
use crate::mdns::MdnsEvent;
use crate::named_port::{MaybeNamedPort, NamedPort};
use crate::netbios::NetBiosEvent;
use crate::ping::PingEvent;
use crate::port_discovery::TcpKnockEvent;
use crate::scanner::{DnsEvent, ServiceType, TcpKnockWithHost};
use crate::sources::{ScannerSource, source_for_address};

/// Selects which serialized shape the websocket emits. Plan §9 v1 is
/// opt-in via `response_format=network_scan_result_v1`; otherwise we keep
/// the legacy shape for back-compat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScanResponseFormat {
    #[default]
    Legacy,
    NetworkScanResultV1,
}

/// What the V1 / legacy filter should let through. Grouped into a config
/// struct so the call site uses named fields instead of five positional bools.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanEventFilterConfig {
    pub report_ping_start: bool,
    pub report_ping_success: bool,
    pub report_ping_failure: bool,
    pub report_tcp_failure: bool,
    pub include_host_results: bool,
    pub response_format: NetworkScanResponseFormat,
}

#[derive(Debug, Clone)]
pub struct ScanEventFilter {
    config: ScanEventFilterConfig,
}

impl ScanEventFilter {
    pub fn new(config: ScanEventFilterConfig) -> Self {
        Self { config }
    }

    pub fn enable_ping_event(&self) -> bool {
        self.config.report_ping_start || self.config.report_ping_success || self.config.report_ping_failure
    }

    pub fn enable_failure(&self) -> bool {
        self.config.report_ping_failure || self.config.report_tcp_failure
    }

    pub fn report_ping_start(&self) -> bool {
        self.config.report_ping_start
    }

    pub fn report_ping_success(&self) -> bool {
        self.config.report_ping_success
    }

    pub fn report_ping_failure(&self) -> bool {
        self.config.report_ping_failure
    }

    pub fn report_tcp_failure(&self) -> bool {
        self.config.report_tcp_failure
    }

    pub fn include_host_results(&self) -> bool {
        self.config.include_host_results
    }

    pub fn response_format(&self) -> NetworkScanResponseFormat {
        self.config.response_format
    }

    pub fn serialize_event(&self, event: ScannerEvent, sources: &[ScannerSource]) -> Option<String> {
        match self.config.response_format {
            NetworkScanResponseFormat::Legacy => {
                let response = LegacyNetworkScanResponse::try_from(event).ok()?;
                if !self.should_emit_legacy(&response) {
                    return None;
                }

                serde_json::to_string(&response).ok()
            }
            NetworkScanResponseFormat::NetworkScanResultV1 => {
                let response = NetworkScanResultEvent::from_scanner_event(event, sources)?;
                if !self.should_emit_result(&response) {
                    return None;
                }

                serde_json::to_string(&response).ok()
            }
        }
    }

    fn should_emit_legacy(&self, response: &LegacyNetworkScanResponse) -> bool {
        let cfg = &self.config;
        match response {
            LegacyNetworkScanResponse::Event(scan_event) => match scan_event {
                LegacyScanEvent::Ping { .. } if !cfg.include_host_results => false,
                LegacyScanEvent::Ping { status, .. } => match status {
                    ScanStatus::Start => cfg.report_ping_start,
                    ScanStatus::Failed => cfg.report_ping_failure,
                    ScanStatus::Success => cfg.report_ping_success,
                },
                LegacyScanEvent::Host { .. } => cfg.include_host_results,
            },
            LegacyNetworkScanResponse::Entry { status, .. } => {
                if matches!(status, ScanStatus::Failed) && !cfg.report_tcp_failure {
                    return false;
                }

                true
            }
        }
    }

    fn should_emit_result(&self, response: &NetworkScanResultEvent) -> bool {
        let cfg = &self.config;
        match response.kind {
            NetworkScanResultKind::Host => {
                if !cfg.include_host_results {
                    return false;
                }

                match response.host_scan_state {
                    Some(HostScanState::Queued | HostScanState::Probing) => cfg.report_ping_start,
                    // Subnet ping is the only path the caller controls
                    // success reporting for. Hosts found via broadcast,
                    // gateway DNS/NetBIOS, or zeroconf are emitted
                    // unconditionally — they're discoveries, not pings.
                    Some(HostScanState::Reachable) if matches!(response.discovery_source, ScanResultSource::Subnet) => {
                        cfg.report_ping_success
                    }
                    Some(HostScanState::Unreachable) => cfg.report_ping_failure,
                    _ => true,
                }
            }
            NetworkScanResultKind::Service => {
                // Successful service entries always emit; failed TCP probes
                // get suppressed unless the caller asked for them via
                // `report_tcp_failure` (or its legacy alias `enable_failure`).
                if response.is_reachable == Some(false) {
                    return cfg.report_tcp_failure;
                }
                true
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Start,
    Failed,
    Success,
}

#[derive(Debug, Serialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum LegacyScanEvent {
    Ping {
        ip: IpAddr,
        status: ScanStatus,
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
pub enum LegacyTcpKnockProbe {
    Number(u16),
    NamedApplication(String),
}

impl From<MaybeNamedPort> for LegacyTcpKnockProbe {
    fn from(port: MaybeNamedPort) -> Self {
        match port {
            MaybeNamedPort::Port(port) => Self::Number(port),
            MaybeNamedPort::Named(named_port) => Self::NamedApplication(named_port_legacy_code(named_port).to_owned()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum LegacyNetworkScanResponse {
    Event(LegacyScanEvent),
    Entry {
        ip: IpAddr,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        protocol: LegacyTcpKnockProbe,
        status: ScanStatus,
    },
}

impl TryFrom<ScannerEvent> for LegacyNetworkScanResponse {
    type Error = ();

    fn try_from(event: ScannerEvent) -> Result<Self, Self::Error> {
        match event {
            // Pre-branch wire emitted exactly one `status: "start"` per host
            // (from `PingEvent::Start`). The new `PingEvent::Queued` event
            // is V1-only — exposing both as legacy `Start` would double-count
            // in legacy clients that count starts. V1 keeps them distinct
            // via `hostScanState: queued | probing`.
            ScannerEvent::Ping(PingEvent::Queued { .. }) => Err(()),
            ScannerEvent::Ping(PingEvent::Start { ip }) => Ok(Self::Event(LegacyScanEvent::Ping {
                ip,
                status: ScanStatus::Start,
                time: None,
            })),
            ScannerEvent::Ping(PingEvent::Success { ip, time }) => Ok(Self::Event(LegacyScanEvent::Ping {
                ip,
                status: ScanStatus::Success,
                time: Some(time),
            })),
            ScannerEvent::Ping(PingEvent::Failed { ip, .. }) => Ok(Self::Event(LegacyScanEvent::Ping {
                ip,
                status: ScanStatus::Failed,
                time: None,
            })),
            ScannerEvent::Dns(DnsEvent::Success { ip, hostname }) => {
                Ok(Self::Event(LegacyScanEvent::Host { ip, hostname }))
            }
            ScannerEvent::Mdns(MdnsEvent::ServiceResolved {
                addr,
                device_name,
                protocol,
                port,
                time: _,
            }) => {
                let protocol = protocol
                    .map(service_type_to_protocol_code)
                    .map(|protocol| LegacyTcpKnockProbe::NamedApplication(protocol.to_owned()))
                    .unwrap_or(LegacyTcpKnockProbe::Number(port));

                Ok(Self::Entry {
                    ip: addr,
                    hostname: Some(device_name),
                    protocol,
                    status: ScanStatus::Success,
                })
            }
            ScannerEvent::NetBios(NetBiosEvent::Success { ip, name, time: _ }) => {
                Ok(Self::Event(LegacyScanEvent::Host {
                    ip: ip.into(),
                    hostname: name,
                }))
            }
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost { tcp_knock, host }) => match tcp_knock {
                TcpKnockEvent::Success { ip, port, .. } => Ok(Self::Entry {
                    ip,
                    hostname: host,
                    protocol: port.into(),
                    status: ScanStatus::Success,
                }),
                TcpKnockEvent::Failed { ip, port, .. } => Ok(Self::Entry {
                    ip,
                    hostname: host,
                    protocol: port.into(),
                    status: ScanStatus::Failed,
                }),
            },
            _ => Err(()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkScanResultKind {
    Host,
    Service,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanResultSource {
    Subnet,
    Broadcast,
    TcpProbe,
    Gateway,
    ZeroConf,
}

/// Where the scan was driven from. Single-variant today (the gateway is
/// the only origin) but modelled as an enum so OpenAPI consumers can rely
/// on the schema being a closed enum rather than a free-form string.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanOrigin {
    Gateway,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostScanState {
    Queued,
    Probing,
    Reachable,
    Unreachable,
}

/// Plan §9 wire shape for `response_format=network_scan_result_v1`.
///
/// Field set is intentionally exactly the plan's required + recommended
/// fields, with `source` constant and `discoverySource` describing how the
/// host/service was discovered (subnet, broadcast, TCP probe, mDNS, …).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkScanResultEvent {
    kind: NetworkScanResultKind,
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_name: Option<String>,
    /// Where the scan was driven from. Always [`ScanOrigin::Gateway`] in
    /// this build; modelled as an enum so the OpenAPI schema is a closed
    /// enum rather than a free-form string.
    source: ScanOrigin,
    /// How the host or service was found.
    discovery_source: ScanResultSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_reachable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_scan_state: Option<HostScanState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_time_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_type: Option<String>,
    /// Hardware address of the discovered host. Populated from ARP/NDP
    /// neighbor cache when that capability is enabled; otherwise omitted.
    /// Declared in the wire schema per plan §9 so the field is stable
    /// even in builds without ARP support.
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_address: Option<String>,
}

impl NetworkScanResultEvent {
    fn from_scanner_event(event: ScannerEvent, sources: &[ScannerSource]) -> Option<Self> {
        match event {
            ScannerEvent::Ping(PingEvent::Queued { ip }) => Some(Self::host(
                ip,
                None,
                ScanResultSource::Subnet,
                sources,
                None,
                Some(HostScanState::Queued),
                None,
            )),
            ScannerEvent::Ping(PingEvent::Start { ip }) => Some(Self::host(
                ip,
                None,
                ScanResultSource::Subnet,
                sources,
                None,
                Some(HostScanState::Probing),
                None,
            )),
            ScannerEvent::Ping(PingEvent::Success { ip, time }) => Some(Self::host(
                ip,
                None,
                ScanResultSource::Subnet,
                sources,
                Some(true),
                Some(HostScanState::Reachable),
                Some(time),
            )),
            ScannerEvent::Ping(PingEvent::Failed { ip, .. }) => Some(Self::host(
                ip,
                None,
                ScanResultSource::Subnet,
                sources,
                Some(false),
                Some(HostScanState::Unreachable),
                None,
            )),
            ScannerEvent::Broadcast(BroadcastEvent::Entry { ip, time }) => Some(Self::host(
                ip.into(),
                None,
                ScanResultSource::Broadcast,
                sources,
                Some(true),
                Some(HostScanState::Reachable),
                time,
            )),
            ScannerEvent::Dns(DnsEvent::Success { ip, hostname }) => Some(Self::host(
                ip,
                Some(hostname),
                ScanResultSource::Gateway,
                sources,
                Some(true),
                Some(HostScanState::Reachable),
                None,
            )),
            ScannerEvent::NetBios(NetBiosEvent::Success { ip, name, time }) => Some(Self::host(
                ip.into(),
                Some(name),
                ScanResultSource::Gateway,
                sources,
                Some(true),
                Some(HostScanState::Reachable),
                time,
            )),
            ScannerEvent::Mdns(MdnsEvent::ServiceResolved {
                addr,
                device_name,
                protocol,
                port,
                time,
            }) => {
                let service = protocol.map(service_type_to_service_descriptor);
                Some(Self::service(ServiceResultParams {
                    addr,
                    host_name: Some(device_name),
                    discovery_source: ScanResultSource::ZeroConf,
                    sources,
                    service_label: service.map(|service| service.label.to_owned()),
                    service_type: service.map(|service| service.code.to_owned()),
                    port: Some(port),
                    response_time_ms: time,
                    reachability: ServiceReachability::Reachable,
                }))
            }
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                tcp_knock: TcpKnockEvent::Success { ip, port, time },
                host,
            }) => {
                let raw_port = u16::from(&port);
                let service = maybe_named_port_to_service_descriptor(port);
                Some(Self::service(ServiceResultParams {
                    addr: ip,
                    host_name: host,
                    discovery_source: ScanResultSource::TcpProbe,
                    sources,
                    service_label: service.map(|service| service.label.to_owned()),
                    service_type: service.map(|service| service.code.to_owned()),
                    port: Some(raw_port),
                    response_time_ms: Some(time),
                    reachability: ServiceReachability::Reachable,
                }))
            }
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                tcp_knock: TcpKnockEvent::Failed { ip, port, .. },
                host,
            }) => {
                let raw_port = u16::from(&port);
                let service = maybe_named_port_to_service_descriptor(port);
                Some(Self::service(ServiceResultParams {
                    addr: ip,
                    host_name: host,
                    discovery_source: ScanResultSource::TcpProbe,
                    sources,
                    service_label: service.map(|service| service.label.to_owned()),
                    service_type: service.map(|service| service.code.to_owned()),
                    port: Some(raw_port),
                    response_time_ms: None,
                    reachability: ServiceReachability::Unreachable,
                }))
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)] // private helper; bundling these into a struct adds noise without saving call sites
    fn host(
        address: IpAddr,
        host_name: Option<String>,
        discovery_source: ScanResultSource,
        sources: &[ScannerSource],
        is_reachable: Option<bool>,
        host_scan_state: Option<HostScanState>,
        response_time_ms: Option<u128>,
    ) -> Self {
        let scan_source = source_for_address(sources, address);
        let InterfaceMetadata {
            id: interface_id,
            name: interface_name,
        } = source_metadata(scan_source);
        Self {
            kind: NetworkScanResultKind::Host,
            address: address.to_string(),
            host_name,
            interface_id,
            interface_name,
            source: ScanOrigin::Gateway,
            discovery_source,
            is_reachable,
            host_scan_state,
            response_time_ms,
            port: None,
            service_label: None,
            service_type: None,
            mac_address: None,
        }
    }

    fn service(params: ServiceResultParams<'_>) -> Self {
        let ServiceResultParams {
            addr,
            host_name,
            discovery_source,
            sources,
            service_label,
            service_type,
            port,
            response_time_ms,
            reachability,
        } = params;
        let address = addr;
        let scan_source = source_for_address(sources, address);
        let InterfaceMetadata {
            id: interface_id,
            name: interface_name,
        } = source_metadata(scan_source);
        Self {
            kind: NetworkScanResultKind::Service,
            address: address.to_string(),
            host_name,
            interface_id,
            interface_name,
            source: ScanOrigin::Gateway,
            discovery_source,
            is_reachable: Some(reachability.as_bool()),
            host_scan_state: None,
            response_time_ms,
            port,
            service_label,
            service_type,
            mac_address: None,
        }
    }
}

/// Whether a service-result event represents a reachable open port (mDNS
/// resolve / TCP connect success) or an unreachable one (TCP probe failed).
/// Modelled as an ADT instead of a bare `bool` so the call site reads as
/// `ServiceReachability::Unreachable` rather than `is_reachable: false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceReachability {
    Reachable,
    Unreachable,
}

impl ServiceReachability {
    fn as_bool(self) -> bool {
        matches!(self, Self::Reachable)
    }
}

struct ServiceResultParams<'a> {
    addr: IpAddr,
    host_name: Option<String>,
    discovery_source: ScanResultSource,
    sources: &'a [ScannerSource],
    service_label: Option<String>,
    service_type: Option<String>,
    port: Option<u16>,
    response_time_ms: Option<u128>,
    reachability: ServiceReachability,
}

/// Named replacement for the `(Option<String>, Option<String>)` return value
/// of `source_metadata` — clearer at call sites than positional tuple
/// destructuring.
struct InterfaceMetadata {
    id: Option<String>,
    name: Option<String>,
}

fn source_metadata(source: Option<&ScannerSource>) -> InterfaceMetadata {
    match source {
        Some(s) => InterfaceMetadata {
            id: Some(s.interface_id.clone()),
            name: Some(s.interface_name.clone()),
        },
        None => InterfaceMetadata { id: None, name: None },
    }
}

#[derive(Debug, Clone, Copy)]
struct ServiceDescriptor {
    code: &'static str,
    label: &'static str,
    legacy_code: &'static str,
}

fn maybe_named_port_to_service_descriptor(port: MaybeNamedPort) -> Option<ServiceDescriptor> {
    match port {
        MaybeNamedPort::Named(named_port) => Some(named_port_to_service_descriptor(named_port)),
        MaybeNamedPort::Port(port) => NamedPort::try_from(port).ok().map(named_port_to_service_descriptor),
    }
}

fn service_type_to_service_descriptor(service_type: ServiceType) -> ServiceDescriptor {
    match service_type {
        ServiceType::Rdp => named_port_to_service_descriptor(NamedPort::Rdp),
        ServiceType::Ard => named_port_to_service_descriptor(NamedPort::Ard),
        ServiceType::Vnc => named_port_to_service_descriptor(NamedPort::Vnc),
        ServiceType::Ssh => named_port_to_service_descriptor(NamedPort::Ssh),
        ServiceType::Sftp => named_port_to_service_descriptor(NamedPort::Sftp),
        ServiceType::Scp => named_port_to_service_descriptor(NamedPort::Scp),
        ServiceType::Telnet => named_port_to_service_descriptor(NamedPort::Telnet),
        ServiceType::Http => named_port_to_service_descriptor(NamedPort::Http),
        ServiceType::Https => named_port_to_service_descriptor(NamedPort::Https),
        ServiceType::Ldap => named_port_to_service_descriptor(NamedPort::Ldap),
        ServiceType::Ldaps => named_port_to_service_descriptor(NamedPort::Ldaps),
    }
}

fn service_type_to_protocol_code(service_type: ServiceType) -> &'static str {
    service_type_to_service_descriptor(service_type).legacy_code
}

fn named_port_legacy_code(named_port: NamedPort) -> &'static str {
    named_port_to_service_descriptor(named_port).legacy_code
}

fn named_port_to_service_descriptor(named_port: NamedPort) -> ServiceDescriptor {
    match named_port {
        NamedPort::Rdp => ServiceDescriptor {
            code: "RDP",
            label: "RDP",
            legacy_code: "rdp",
        },
        NamedPort::Ard => ServiceDescriptor {
            code: "ARD",
            label: "ARD",
            legacy_code: "ard",
        },
        NamedPort::Vnc => ServiceDescriptor {
            code: "VNC",
            label: "VNC",
            legacy_code: "vnc",
        },
        NamedPort::Ssh => ServiceDescriptor {
            code: "SSH",
            label: "SSH",
            legacy_code: "ssh",
        },
        NamedPort::Sshpwsh => ServiceDescriptor {
            code: "SSHPWSH",
            label: "SSH PowerShell",
            legacy_code: "ssh-pwsh",
        },
        NamedPort::Sftp => ServiceDescriptor {
            code: "SFTP",
            label: "SFTP",
            legacy_code: "sftp",
        },
        NamedPort::Scp => ServiceDescriptor {
            code: "SCP",
            label: "SCP",
            legacy_code: "scp",
        },
        NamedPort::Telnet => ServiceDescriptor {
            code: "TELNET",
            label: "Telnet",
            legacy_code: "telnet",
        },
        NamedPort::WinrmHttpPwsh => ServiceDescriptor {
            code: "WINRM_HTTP_PWSH",
            label: "WinRM HTTP PowerShell",
            legacy_code: "winrm-http-pwsh",
        },
        NamedPort::WinrmHttpsPwsh => ServiceDescriptor {
            code: "WINRM_HTTPS_PWSH",
            label: "WinRM HTTPS PowerShell",
            legacy_code: "winrm-https-pwsh",
        },
        NamedPort::Http => ServiceDescriptor {
            code: "HTTP",
            label: "HTTP",
            legacy_code: "http",
        },
        NamedPort::Https => ServiceDescriptor {
            code: "HTTPS",
            label: "HTTPS",
            legacy_code: "https",
        },
        NamedPort::Ldap => ServiceDescriptor {
            code: "LDAP",
            label: "LDAP",
            legacy_code: "ldap",
        },
        NamedPort::Ldaps => ServiceDescriptor {
            code: "LDAPS",
            label: "LDAPS",
            legacy_code: "ldaps",
        },
    }
}
