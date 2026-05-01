use std::net::IpAddr;
use std::num::NonZeroU32;

use serde::Deserialize;

use crate::ip_utils::{IpAddrRange, IpFamily, Subnet};
use crate::sources::{ScannerSource, ScannerSourceState};

/// Convert a raw OS interface index (`Option<u32>` from `network-interface`)
/// to the `NonZeroU32` form used downstream. ifindex 0 is invalid on Linux,
/// macOS, and Windows alike, so dropping it here is safe.
fn ifindex_to_nonzero(raw: Option<u32>) -> Option<NonZeroU32> {
    raw.and_then(NonZeroU32::new)
}

pub const DEFAULT_MAX_TARGET_RANGE_ADDRESSES: u128 = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelector {
    DefaultSubnets,
    ExplicitHosts(Vec<IpAddr>),
    ExplicitRanges(Vec<IpAddrRange>),
}

impl TargetSelector {
    pub fn validate(&self, max_range_addresses: u128) -> Result<(), TargetSelectorValidationError> {
        match self {
            Self::DefaultSubnets => Ok(()),
            Self::ExplicitHosts(hosts) => validate_same_family(hosts.iter().copied().map(ip_family)),
            Self::ExplicitRanges(ranges) => {
                validate_same_family(ranges.iter().map(IpAddrRange::family))?;

                for range in ranges {
                    let address_count = range.address_count();
                    if address_count > max_range_addresses {
                        return Err(TargetSelectorValidationError::RangeTooLarge {
                            address_count,
                            max_range_addresses,
                        });
                    }
                }

                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetSelectorValidationError {
    #[error("network scan target selector mixes IPv4 and IPv6 addresses")]
    MixedIpFamilies,
    #[error("network scan range contains {address_count} addresses, maximum is {max_range_addresses}")]
    RangeTooLarge {
        address_count: u128,
        max_range_addresses: u128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceSelector {
    AllEligible,
    Selected(Vec<String>),
}

impl InterfaceSelector {
    pub fn selected_ids(&self) -> &[String] {
        match self {
            Self::AllEligible => &[],
            Self::Selected(ids) => ids,
        }
    }
}

/// What to do when an explicit `range` is requested AND specific
/// `interface_id`s are selected. Default is to intersect, so a range that
/// doesn't overlap any selected source falls back to a structured 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeInterfacePolicy {
    #[default]
    IntersectSelectedInterfaces,
    AllowCrossInterfaceRange,
}

/// A single ping target range plus the interface (if any) the planner expects
/// the ping socket to be bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRange {
    pub range: IpAddrRange,
    /// OS interface index to bind ping/TCP probe sockets to. `None` falls
    /// back to default routing, which is correct for explicit hosts/ranges
    /// that aren't constrained to a selected source. [`NonZeroU32`] makes
    /// the "no bind" sentinel distinct from a real ifindex of 0.
    pub interface_index: Option<NonZeroU32>,
}

impl PlannedRange {
    pub fn new(range: IpAddrRange, interface_index: Option<NonZeroU32>) -> Self {
        Self { range, interface_index }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkScanPlan {
    pub sources: Vec<ScannerSource>,
    pub range_to_ping: Vec<PlannedRange>,
    pub broadcast_subnet: Vec<Subnet>,
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkScanPlanError {
    #[error("invalid network scan interface: {0}")]
    InvalidInterface(#[from] ScanSourceSelectionError),
    #[error("explicit ranges {ranges:?} have no overlap with selected interfaces {interface_ids:?}")]
    RangeOutsideSelectedInterfaces {
        ranges: Vec<String>,
        interface_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanSourceSelectionError {
    #[error("missing network scan interface: {interface_id}")]
    Missing { interface_id: String },
    #[error("network scan interface is down: {interface_id}")]
    Down { interface_id: String },
    #[error("network scan interface is loopback-only: {interface_id}")]
    LoopbackOnly { interface_id: String },
    #[error("network scan interface has no scan-capable address: {interface_id}")]
    NoScanCapableAddress { interface_id: String },
}

impl ScanSourceSelectionError {
    pub fn interface_id(&self) -> &str {
        match self {
            Self::Missing { interface_id }
            | Self::Down { interface_id }
            | Self::LoopbackOnly { interface_id }
            | Self::NoScanCapableAddress { interface_id } => interface_id,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "missing",
            Self::Down { .. } => "down",
            Self::LoopbackOnly { .. } => "loopback_only",
            Self::NoScanCapableAddress { .. } => "no_scan_capable_address",
        }
    }
}

pub fn plan_scan(
    target_selector: &TargetSelector,
    interface_selector: &InterfaceSelector,
    range_interface_policy: RangeInterfacePolicy,
    source_inventory: Vec<ScannerSourceState>,
    enable_subnet_scan: bool,
) -> Result<NetworkScanPlan, NetworkScanPlanError> {
    let sources = select_sources_from_inventory(source_inventory, interface_selector)?;
    let broadcast_subnet = sources
        .iter()
        .filter(|source| source.capabilities.broadcast)
        .filter_map(ScannerSource::as_broadcast_subnet)
        .collect::<Vec<_>>();

    let range_to_ping = match target_selector {
        TargetSelector::DefaultSubnets if enable_subnet_scan => sources
            .iter()
            .filter(|source| source.capabilities.subnet)
            .filter_map(|source| {
                source
                    .as_ip_range()
                    .map(|range| PlannedRange::new(range, ifindex_to_nonzero(source.interface_index)))
            })
            .collect(),
        TargetSelector::DefaultSubnets => Vec::new(),
        TargetSelector::ExplicitHosts(hosts) => hosts
            .iter()
            .copied()
            .map(|ip| {
                let interface_index = crate::sources::source_for_address(&sources, ip)
                    .and_then(|s| ifindex_to_nonzero(s.interface_index));
                PlannedRange::new(IpAddrRange::single(ip), interface_index)
            })
            .collect(),
        TargetSelector::ExplicitRanges(ranges) => match (interface_selector, range_interface_policy) {
            (InterfaceSelector::Selected(interface_ids), RangeInterfacePolicy::IntersectSelectedInterfaces) => {
                let intersected = intersect_ranges_with_sources(ranges, &sources);
                if intersected.is_empty() && !ranges.is_empty() {
                    return Err(NetworkScanPlanError::RangeOutsideSelectedInterfaces {
                        ranges: ranges.iter().map(|range| format!("{range:?}")).collect(),
                        interface_ids: interface_ids.clone(),
                    });
                }
                intersected
            }
            _ => ranges
                .iter()
                .cloned()
                .map(|range| {
                    let interface_index = range_first_ip(&range)
                        .and_then(|ip| crate::sources::source_for_address(&sources, ip))
                        .and_then(|s| ifindex_to_nonzero(s.interface_index));
                    PlannedRange::new(range, interface_index)
                })
                .collect(),
        },
    };

    Ok(NetworkScanPlan {
        sources,
        range_to_ping,
        broadcast_subnet,
    })
}

fn ip_family(address: IpAddr) -> IpFamily {
    match address {
        IpAddr::V4(_) => IpFamily::V4,
        IpAddr::V6(_) => IpFamily::V6,
    }
}

fn validate_same_family(families: impl IntoIterator<Item = IpFamily>) -> Result<(), TargetSelectorValidationError> {
    let mut families = families.into_iter();
    let Some(first) = families.next() else {
        return Ok(());
    };

    if families.any(|family| family != first) {
        return Err(TargetSelectorValidationError::MixedIpFamilies);
    }

    Ok(())
}

fn select_sources_from_inventory(
    source_inventory: Vec<ScannerSourceState>,
    interface_selector: &InterfaceSelector,
) -> Result<Vec<ScannerSource>, ScanSourceSelectionError> {
    match interface_selector {
        InterfaceSelector::AllEligible => Ok(source_inventory
            .into_iter()
            .filter_map(|state| match state {
                ScannerSourceState::Eligible(source) => Some(source),
                _ => None,
            })
            .collect()),
        InterfaceSelector::Selected(interface_ids) => {
            // Pre-index the inventory by interface id for O(1) lookup. Each
            // id gets at most one state because the OS guarantees unique
            // interface names — we collect into a HashMap keyed by the
            // owned interface id string, then resolve each requested id
            // exactly once.
            let mut by_id: std::collections::HashMap<&str, &ScannerSourceState> =
                std::collections::HashMap::with_capacity(source_inventory.len());
            for state in &source_inventory {
                by_id.insert(state.interface_id(), state);
            }

            interface_ids
                .iter()
                .map(|requested| match by_id.get(requested.as_str()) {
                    Some(ScannerSourceState::Eligible(source)) => Ok(source.clone()),
                    Some(ScannerSourceState::Missing { .. }) | None => Err(ScanSourceSelectionError::Missing {
                        interface_id: requested.clone(),
                    }),
                    Some(ScannerSourceState::Down { .. }) => Err(ScanSourceSelectionError::Down {
                        interface_id: requested.clone(),
                    }),
                    Some(ScannerSourceState::LoopbackOnly { .. }) => Err(ScanSourceSelectionError::LoopbackOnly {
                        interface_id: requested.clone(),
                    }),
                    Some(ScannerSourceState::NoScanCapableAddress { .. }) => {
                        Err(ScanSourceSelectionError::NoScanCapableAddress {
                            interface_id: requested.clone(),
                        })
                    }
                })
                .collect()
        }
    }
}

fn intersect_ranges_with_sources(ranges: &[IpAddrRange], sources: &[ScannerSource]) -> Vec<PlannedRange> {
    let source_ranges = sources
        .iter()
        .filter(|source| source.capabilities.subnet)
        .filter_map(|source| {
            source
                .as_ip_range()
                .map(|range| (range, ifindex_to_nonzero(source.interface_index)))
        })
        .collect::<Vec<_>>();
    let mut intersections = Vec::new();

    for range in ranges {
        for (source_range, interface_index) in &source_ranges {
            if let Some(intersection) = range.intersection(source_range) {
                intersections.push(PlannedRange::new(intersection, *interface_index));
            }
        }
    }

    intersections
}

fn range_first_ip(range: &IpAddrRange) -> Option<IpAddr> {
    range.clone().into_iter().next()
}
