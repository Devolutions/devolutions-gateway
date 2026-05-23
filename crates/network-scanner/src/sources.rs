use std::net::{IpAddr, Ipv4Addr};

use anyhow::Context;
use network_interface::{Addr, NetworkInterfaceConfig};

use crate::ip_utils::{IpAddrRange, Subnet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerSourceCapabilities {
    /// Source has an IPv4 address that can be scanned.
    pub ipv4: bool,
    /// Source has an IPv6 address that can be scanned.
    pub ipv6: bool,
    pub subnet: bool,
    pub broadcast: bool,
    pub zeroconf: bool,
    pub tcp_probe: bool,
    pub dns_resolve: bool,
}

impl Default for ScannerSourceCapabilities {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: false,
            subnet: true,
            broadcast: true,
            zeroconf: true,
            tcp_probe: true,
            dns_resolve: true,
        }
    }
}

/// Coarse classification of a scan source's link layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    WiFi,
    Loopback,
    Virtual,
    Unknown,
}

impl LinkType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::WiFi => "wifi",
            Self::Loopback => "loopback",
            Self::Virtual => "virtual",
            Self::Unknown => "unknown",
        }
    }

    /// Classify based on a best-effort heuristic on the OS interface name.
    /// Cheap, no syscalls.
    ///
    /// Recognized prefixes cover the names that Linux (`eth*`, `wlan*`,
    /// `enp*`, `wlp*`, …), macOS (`en*`, `lo*`, …), and the OS-level
    /// short names that `network_interface` exposes on Windows (`Ethernet`,
    /// `Wi-Fi`, …). Verbose Windows display names like
    /// `"Local Area Connection 1"` are not enumerated and fall through to
    /// [`LinkType::Unknown`]; consumers that need precise classification on
    /// Windows should look at the OS-level GUID/index instead.
    pub fn from_interface_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("lo") {
            Self::Loopback
        } else if lower.starts_with("wlan")
            || lower.starts_with("wifi")
            || lower.starts_with("wlp")
            || lower.contains("wireless")
            || lower.contains("wi-fi")
        {
            Self::WiFi
        } else if lower.starts_with("eth")
            || lower.starts_with("en")
            || lower.starts_with("ethernet")
            || lower.starts_with("eno")
            || lower.starts_with("enp")
            || lower.starts_with("ens")
        {
            Self::Ethernet
        } else if lower.starts_with("docker")
            || lower.starts_with("br-")
            || lower.starts_with("veth")
            || lower.starts_with("tun")
            || lower.starts_with("tap")
            || lower.starts_with("vboxnet")
            || lower.starts_with("vmnet")
            || lower.starts_with("virbr")
        {
            Self::Virtual
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerSource {
    pub interface_id: String,
    pub interface_name: String,
    pub interface_description: Option<String>,
    pub interface_index: Option<u32>,
    pub mac_address: Option<String>,
    pub is_up: Option<bool>,
    /// MTU in bytes, when known.
    pub mtu: Option<u32>,
    /// Link speed in megabits per second, when reported by the OS.
    pub speed_mbps: Option<u64>,
    /// Coarse link type classification.
    pub link_type: LinkType,
    pub address: IpAddr,
    pub start_address: IpAddr,
    pub end_address: IpAddr,
    pub broadcast_address: Option<IpAddr>,
    pub prefix_length: Option<u8>,
    pub capabilities: ScannerSourceCapabilities,
}

impl ScannerSource {
    pub fn contains_address(&self, address: IpAddr) -> bool {
        match (address, self.start_address, self.end_address) {
            (IpAddr::V4(address), IpAddr::V4(start), IpAddr::V4(end)) => {
                let address = u32::from(address);
                address >= u32::from(start) && address <= u32::from(end)
            }
            (IpAddr::V6(address), IpAddr::V6(start), IpAddr::V6(end)) => {
                let address = u128::from(address);
                address >= u128::from(start) && address <= u128::from(end)
            }
            _ => false,
        }
    }

    pub fn as_broadcast_subnet(&self) -> Option<Subnet> {
        let IpAddr::V4(address) = self.address else {
            return None;
        };

        let Some(IpAddr::V4(broadcast)) = self.broadcast_address else {
            return None;
        };

        let prefix_length = self.prefix_length?;
        let netmask = ipv4_netmask_from_prefix(prefix_length)?;

        Some(Subnet {
            ip: address,
            netmask,
            broadcast,
        })
    }

    pub fn as_ip_range(&self) -> Option<IpAddrRange> {
        match (self.start_address, self.end_address) {
            (IpAddr::V4(start), IpAddr::V4(end)) => Some(IpAddrRange::new_ipv4(start, end)),
            (IpAddr::V6(start), IpAddr::V6(end)) => Some(IpAddrRange::new_ipv6(start, end)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannerSourceState {
    Eligible(ScannerSource),
    Missing { interface_id: String },
    Down { interface_id: String },
    LoopbackOnly { interface_id: String },
    NoScanCapableAddress { interface_id: String },
}

impl ScannerSourceState {
    /// The interface id this state describes, regardless of the variant.
    pub fn interface_id(&self) -> &str {
        match self {
            Self::Eligible(source) => &source.interface_id,
            Self::Missing { interface_id }
            | Self::Down { interface_id }
            | Self::LoopbackOnly { interface_id }
            | Self::NoScanCapableAddress { interface_id } => interface_id,
        }
    }
}

pub trait NetworkScanSourceProvider: Send + Sync {
    fn get_sources(&self) -> anyhow::Result<Vec<ScannerSource>>;

    fn get_source_inventory(&self) -> anyhow::Result<Vec<ScannerSourceState>> {
        Ok(self
            .get_sources()?
            .into_iter()
            .map(ScannerSourceState::Eligible)
            .collect())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SystemNetworkScanSourceProvider;

impl NetworkScanSourceProvider for SystemNetworkScanSourceProvider {
    fn get_sources(&self) -> anyhow::Result<Vec<ScannerSource>> {
        get_system_sources()
    }
}

pub fn get_system_sources() -> anyhow::Result<Vec<ScannerSource>> {
    let interfaces = network_interface::NetworkInterface::show().context("failed to get network interfaces")?;

    let sources = interfaces
        .into_iter()
        .flat_map(|interface| {
            let interface_id = interface.name.clone();
            let interface_name = interface.name;
            let mac_address = interface.mac_addr;
            let interface_index = Some(interface.index);
            let is_up = Some(!interface.internal);
            let link_type = LinkType::from_interface_name(&interface_id);
            let LinkMetadata { mtu, speed_mbps } = read_link_metadata(&interface_id, interface.index);

            interface.addr.into_iter().filter_map(move |addr| match addr {
                Addr::V4(v4) => {
                    if v4.ip.is_loopback() || v4.ip.is_link_local() {
                        return None;
                    }

                    let netmask = v4.netmask?;
                    let (start_address, end_address) = calculate_ipv4_bounds(v4.ip, netmask);
                    let prefix_length = ipv4_prefix_length(netmask);
                    Some(ScannerSource {
                        interface_id: format!("{interface_id}|IPv4|{}", v4.ip),
                        interface_name: format!("{interface_name} (IPv4)"),
                        interface_description: None,
                        interface_index,
                        mac_address: mac_address.clone(),
                        is_up,
                        mtu,
                        speed_mbps,
                        link_type,
                        address: IpAddr::V4(v4.ip),
                        start_address: IpAddr::V4(start_address),
                        end_address: IpAddr::V4(end_address),
                        broadcast_address: v4.broadcast.map(IpAddr::V4),
                        prefix_length,
                        capabilities: ScannerSourceCapabilities {
                            ipv4: true,
                            ipv6: false,
                            broadcast: v4.broadcast.is_some(),
                            ..ScannerSourceCapabilities::default()
                        },
                    })
                }
                Addr::V6(v6) => {
                    if v6.ip.is_loopback() || v6.ip.is_multicast() {
                        return None;
                    }

                    Some(ScannerSource {
                        interface_id: format!("{interface_id}|IPv6|{}", v6.ip),
                        interface_name: format!("{interface_name} (IPv6)"),
                        interface_description: None,
                        interface_index,
                        mac_address: mac_address.clone(),
                        is_up,
                        mtu,
                        speed_mbps,
                        link_type,
                        address: IpAddr::V6(v6.ip),
                        start_address: IpAddr::V6(v6.ip),
                        end_address: IpAddr::V6(v6.ip),
                        broadcast_address: None,
                        prefix_length: None,
                        capabilities: ScannerSourceCapabilities {
                            ipv4: false,
                            ipv6: true,
                            broadcast: false,
                            ..ScannerSourceCapabilities::default()
                        },
                    })
                }
            })
        })
        .collect();

    Ok(sources)
}

pub fn sources_to_broadcast_subnets(sources: &[ScannerSource]) -> Vec<Subnet> {
    sources
        .iter()
        .filter(|source| source.capabilities.broadcast)
        .filter_map(ScannerSource::as_broadcast_subnet)
        .collect()
}

pub fn source_for_address(sources: &[ScannerSource], address: IpAddr) -> Option<&ScannerSource> {
    sources.iter().find(|source| source.contains_address(address))
}

pub fn select_sources(
    sources: &[ScannerSource],
    selected_interface_ids: &[String],
) -> anyhow::Result<Vec<ScannerSource>> {
    if selected_interface_ids.is_empty() {
        return Ok(sources.to_vec());
    }

    let mut selected_sources = Vec::new();
    for selected_interface_id in selected_interface_ids {
        let mut found = false;
        for source in sources {
            if source.interface_id == *selected_interface_id {
                selected_sources.push(source.clone());
                found = true;
            }
        }

        if !found {
            anyhow::bail!("unknown network scan interface id: {}", selected_interface_id);
        }
    }

    Ok(selected_sources)
}

/// Per-interface link metadata. Returned by [`read_link_metadata`] as a
/// named struct so call sites can spell out `mtu` / `speed_mbps` rather
/// than destructure a positional tuple.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LinkMetadata {
    pub mtu: Option<u32>,
    pub speed_mbps: Option<u64>,
}

/// Best-effort link metadata lookup.
///
/// Linux: read `/sys/class/net/{name}/{mtu,speed}` directly.
/// Windows: call `GetIfEntry2` for `MIB_IF_ROW2 { Mtu, TransmitLinkSpeed }`.
/// macOS / others: empty — no cheap, dependency-free path to either value
/// without raw socket ioctls.
#[cfg(target_os = "linux")]
fn read_link_metadata(name: &str, _if_index: u32) -> LinkMetadata {
    let mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    // `/speed` returns Mbit/s, or -1 when the link is down or the driver
    // does not report it; we treat -1 as "unknown" rather than emitting
    // bogus data.
    let speed_mbps = std::fs::read_to_string(format!("/sys/class/net/{name}/speed"))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .and_then(|v| u64::try_from(v).ok());
    LinkMetadata { mtu, speed_mbps }
}

#[cfg(target_os = "windows")]
fn read_link_metadata(_name: &str, if_index: u32) -> LinkMetadata {
    use std::mem::MaybeUninit;

    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};

    let mut row: MaybeUninit<MIB_IF_ROW2> = MaybeUninit::zeroed();
    // SAFETY: zero-initialize struct, set required InterfaceIndex, hand to
    // GetIfEntry2 which fills the rest.
    unsafe {
        let row_mut = row.as_mut_ptr();
        (*row_mut).InterfaceIndex = if_index;
    }
    // SAFETY: row is fully writable.
    let rc = unsafe { GetIfEntry2(row.as_mut_ptr()) };
    if rc != NO_ERROR {
        return LinkMetadata::default();
    }
    // SAFETY: GetIfEntry2 returned NO_ERROR so all fields are initialized.
    let row = unsafe { row.assume_init() };
    LinkMetadata {
        mtu: (row.Mtu > 0).then_some(row.Mtu),
        // TransmitLinkSpeed is bits per second; convert to Mbit/s.
        speed_mbps: (row.TransmitLinkSpeed > 0).then_some(row.TransmitLinkSpeed / 1_000_000),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn read_link_metadata(_name: &str, _if_index: u32) -> LinkMetadata {
    LinkMetadata::default()
}

fn calculate_ipv4_bounds(ip: Ipv4Addr, netmask: Ipv4Addr) -> (Ipv4Addr, Ipv4Addr) {
    let ip_u32 = u32::from(ip);
    let netmask_u32 = u32::from(netmask);
    (
        Ipv4Addr::from(ip_u32 & netmask_u32),
        Ipv4Addr::from(ip_u32 | !netmask_u32),
    )
}

/// Convert an IPv4 netmask to its CIDR prefix length, rejecting any mask
/// that is not a contiguous run of 1-bits followed by 0-bits.
///
/// We can't just use `count_ones()` because `0b1110_1110_..` would have the
/// same popcount as `0b1111_0000_..` while being an invalid netmask. The
/// trick: the popcount tells us how long the prefix *would* be; we then
/// reconstruct the canonical mask of that length and require equality.
fn ipv4_prefix_length(netmask: Ipv4Addr) -> Option<u8> {
    let mask = u32::from(netmask);
    if mask == 0 {
        return Some(0);
    }

    let prefix_length = u8::try_from(mask.count_ones()).ok()?;
    let expected = u32::MAX.checked_shl(u32::from(32 - prefix_length)).unwrap_or(0);
    // Equality holds iff `mask` is the canonical /prefix_length netmask.
    (mask == expected).then_some(prefix_length)
}

fn ipv4_netmask_from_prefix(prefix_length: u8) -> Option<Ipv4Addr> {
    if prefix_length > 32 {
        return None;
    }

    let mask = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    };

    Some(Ipv4Addr::from(mask))
}
