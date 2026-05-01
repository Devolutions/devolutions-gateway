//! Tests extracted from `crate::task_utils`.

#![allow(unused_imports)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::broadcast::BroadcastEvent;
use crate::event_bus::ScannerEvent;
use crate::ip_utils::{IpAddrRange, IpFamily, Subnet};
use crate::mdns::MdnsEvent;
use crate::named_port::{MaybeNamedPort, NamedPort};
use crate::netbios::NetBiosEvent;
use crate::ping::{PingEvent, PingFailedReason};
use crate::planner::{
    DEFAULT_MAX_TARGET_RANGE_ADDRESSES, InterfaceSelector, NetworkScanPlan, NetworkScanPlanError, PlannedRange,
    RangeInterfacePolicy, ScanSourceSelectionError, TargetSelector, TargetSelectorValidationError, plan_scan,
};
use crate::port_discovery::{PortScanFailedReason, TcpKnockEvent};
use crate::results::{
    HostScanState, NetworkScanResponseFormat, NetworkScanResultEvent, ScanEventFilter, ScanResultSource,
};
use crate::scanner::{
    DnsEvent, NetworkScanner, NetworkScannerParams, ScannerConfig, ScannerToggles, ServiceType, TcpKnockWithHost,
};
use crate::sources::{
    LinkType, NetworkScanSourceProvider, ScannerSource, ScannerSourceCapabilities, ScannerSourceState,
    get_system_sources, select_sources, source_for_address, sources_to_broadcast_subnets,
};
use crate::task_utils::{ContextConfig, TaskExecutionContext, TaskManager};

#[derive(Debug)]
struct FakeNetworkScanSourceProvider {
    sources: Vec<ScannerSource>,
}

impl NetworkScanSourceProvider for FakeNetworkScanSourceProvider {
    fn get_sources(&self) -> anyhow::Result<Vec<ScannerSource>> {
        Ok(self.sources.clone())
    }
}

#[test]
fn scanner_context_uses_injected_source_provider_for_subnet_planning() {
    let source = ScannerSource {
        interface_id: "eth0".to_owned(),
        interface_name: "eth0 (IPv4)".to_owned(),
        interface_description: None,
        interface_index: None,
        mac_address: None,
        is_up: Some(true),
        mtu: None,
        speed_mbps: None,
        link_type: crate::sources::LinkType::Unknown,
        address: "192.168.1.25".parse().unwrap(),
        start_address: "192.168.1.0".parse().unwrap(),
        end_address: "192.168.1.255".parse().unwrap(),
        broadcast_address: Some("192.168.1.255".parse().unwrap()),
        prefix_length: Some(24),
        capabilities: ScannerSourceCapabilities::default(),
    };
    let scanner = NetworkScanner::with_source_provider(
        NetworkScannerParams {
            config: scanner_config(),
            toggle: ScannerToggles {
                enable_broadcast: true,
                enable_subnet_scan: true,
                enable_zeroconf: false,
                enable_resolve_dns: false,
                enable_netbios: true,
            },
        },
        Arc::new(FakeNetworkScanSourceProvider { sources: vec![source] }),
    )
    .unwrap();

    let context = TaskExecutionContext::new(scanner).unwrap();

    assert_eq!(context.configs.broadcast_subnet.len(), 1);
    assert_eq!(
        context.configs.broadcast_subnet[0].broadcast,
        Ipv4Addr::new(192, 168, 1, 255)
    );

    assert_eq!(context.configs.range_to_ping.len(), 1);
    let first_targets = context.configs.range_to_ping[0]
        .range
        .clone()
        .into_iter()
        .take(2)
        .collect::<Vec<IpAddr>>();
    assert_eq!(
        first_targets,
        vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        ]
    );
}

#[test]
fn scanner_context_restricts_subnet_planning_to_selected_interface_ids() {
    let eth0 = scanner_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let wifi0 = scanner_source("wifi0", "10.0.0.5", "10.0.0.0", "10.0.0.255", "10.0.0.255", 24);
    let mut config = scanner_config();
    config.targeting.interface_selector = InterfaceSelector::Selected(vec!["wifi0".to_owned()]);
    let scanner = NetworkScanner::with_source_provider(
        NetworkScannerParams {
            config,
            toggle: ScannerToggles {
                enable_broadcast: true,
                enable_subnet_scan: true,
                enable_zeroconf: false,
                enable_resolve_dns: false,
                enable_netbios: true,
            },
        },
        Arc::new(FakeNetworkScanSourceProvider {
            sources: vec![eth0, wifi0],
        }),
    )
    .unwrap();

    let context = TaskExecutionContext::new(scanner).unwrap();

    assert_eq!(context.configs.broadcast_subnet.len(), 1);
    assert_eq!(
        context.configs.broadcast_subnet[0].broadcast,
        Ipv4Addr::new(10, 0, 0, 255)
    );
    let first_target = context.configs.range_to_ping[0].range.clone().into_iter().next();
    assert_eq!(first_target, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
}

#[test]
fn scanner_context_uses_explicit_target_addresses_before_source_subnet_ranges() {
    let source = scanner_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let mut config = scanner_config();
    config.targeting.target_selector =
        TargetSelector::ExplicitHosts(vec!["192.168.1.10".parse().unwrap(), "192.168.1.20".parse().unwrap()]);
    let scanner = NetworkScanner::with_source_provider(
        NetworkScannerParams {
            config,
            toggle: ScannerToggles {
                enable_broadcast: true,
                enable_subnet_scan: true,
                enable_zeroconf: false,
                enable_resolve_dns: false,
                enable_netbios: true,
            },
        },
        Arc::new(FakeNetworkScanSourceProvider { sources: vec![source] }),
    )
    .unwrap();

    let context = TaskExecutionContext::new(scanner).unwrap();

    assert_eq!(context.configs.broadcast_subnet.len(), 1);
    assert_eq!(context.configs.range_to_ping.len(), 2);
    assert_eq!(
        context.configs.range_to_ping[0]
            .range
            .clone()
            .into_iter()
            .collect::<Vec<_>>(),
        vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]
    );
    assert_eq!(
        context.configs.range_to_ping[1]
            .range
            .clone()
            .into_iter()
            .collect::<Vec<_>>(),
        vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))]
    );
}

#[test]
fn scanner_context_uses_explicit_ip_ranges_before_source_subnet_ranges() {
    let source = scanner_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let mut config = scanner_config();
    config.targeting.target_selector =
        TargetSelector::ExplicitRanges(vec![IpAddrRange::try_from("192.168.1.40-192.168.1.41").unwrap()]);
    let scanner = NetworkScanner::with_source_provider(
        NetworkScannerParams {
            config,
            toggle: ScannerToggles {
                enable_broadcast: true,
                enable_subnet_scan: true,
                enable_zeroconf: false,
                enable_resolve_dns: false,
                enable_netbios: true,
            },
        },
        Arc::new(FakeNetworkScanSourceProvider { sources: vec![source] }),
    )
    .unwrap();

    let context = TaskExecutionContext::new(scanner).unwrap();

    assert_eq!(context.configs.broadcast_subnet.len(), 1);
    assert_eq!(context.configs.range_to_ping.len(), 1);
    assert_eq!(
        context.configs.range_to_ping[0]
            .range
            .clone()
            .into_iter()
            .collect::<Vec<_>>(),
        vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 41)),
        ]
    );
}

#[test]
fn scanner_context_allows_broadcast_without_subnet_ping_when_subnet_scan_is_disabled() {
    let source = scanner_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let scanner = NetworkScanner::with_source_provider(
        NetworkScannerParams {
            config: scanner_config(),
            toggle: ScannerToggles {
                enable_broadcast: true,
                enable_subnet_scan: false,
                enable_zeroconf: false,
                enable_resolve_dns: false,
                enable_netbios: true,
            },
        },
        Arc::new(FakeNetworkScanSourceProvider { sources: vec![source] }),
    )
    .unwrap();

    let context = TaskExecutionContext::new(scanner).unwrap();

    assert_eq!(context.configs.broadcast_subnet.len(), 1);
    assert!(context.configs.range_to_ping.is_empty());
}

#[test]
fn scanner_context_carries_max_concurrency_to_execution_config() {
    let mut config = scanner_config();
    config.limits.max_concurrency = Some(8);
    let scanner = NetworkScanner::with_source_provider(
        NetworkScannerParams {
            config,
            toggle: ScannerToggles {
                enable_broadcast: false,
                enable_subnet_scan: false,
                enable_zeroconf: false,
                enable_resolve_dns: false,
                enable_netbios: true,
            },
        },
        Arc::new(FakeNetworkScanSourceProvider {
            sources: vec![scanner_source(
                "eth0",
                "192.168.1.25",
                "192.168.1.0",
                "192.168.1.255",
                "192.168.1.255",
                24,
            )],
        }),
    )
    .unwrap();

    let context = TaskExecutionContext::new(scanner).unwrap();

    assert_eq!(context.configs.max_ping_concurrency, Some(8));
    assert_eq!(context.configs.max_tcp_probe_concurrency, Some(8));
}

#[test]
fn scanner_context_carries_split_probe_concurrency_to_execution_config() {
    let mut config = scanner_config();
    config.limits.max_concurrency = Some(8);
    config.limits.max_ping_concurrency = Some(4);
    config.limits.max_tcp_probe_concurrency = Some(2);
    let scanner = NetworkScanner::with_source_provider(
        NetworkScannerParams {
            config,
            toggle: ScannerToggles {
                enable_broadcast: false,
                enable_subnet_scan: false,
                enable_zeroconf: false,
                enable_resolve_dns: false,
                enable_netbios: true,
            },
        },
        Arc::new(FakeNetworkScanSourceProvider {
            sources: vec![scanner_source(
                "eth0",
                "192.168.1.25",
                "192.168.1.0",
                "192.168.1.255",
                "192.168.1.255",
                24,
            )],
        }),
    )
    .unwrap();

    let context = TaskExecutionContext::new(scanner).unwrap();

    assert_eq!(context.configs.max_ping_concurrency, Some(4));
    assert_eq!(context.configs.max_tcp_probe_concurrency, Some(2));
}

#[test]
fn context_config_planning_matrix_covers_target_range_and_subnet_permutations() {
    for has_target_addresses in [false, true] {
        for has_ip_ranges in [false, true] {
            for enable_subnet_scan in [false, true] {
                let mut config = scanner_config();
                if has_target_addresses {
                    config.targeting.target_selector =
                        TargetSelector::ExplicitHosts(vec!["192.168.1.10".parse().unwrap()]);
                }
                if has_ip_ranges {
                    config.targeting.target_selector = TargetSelector::ExplicitRanges(vec![
                        IpAddrRange::try_from("192.168.1.40-192.168.1.41").unwrap(),
                    ]);
                }
                let context_config = ContextConfig::from_config_and_plan(
                    config,
                    NetworkScanPlan {
                        sources: vec![],
                        range_to_ping: match (has_target_addresses, has_ip_ranges, enable_subnet_scan) {
                            (true, _, _) => vec![PlannedRange::new(
                                IpAddrRange::single("192.168.1.10".parse().expect("fixture IPv4 address should parse")),
                                None,
                            )],
                            (false, true, _) => vec![PlannedRange::new(
                                IpAddrRange::try_from("192.168.1.40-192.168.1.41").unwrap(),
                                None,
                            )],
                            (false, false, true) => vec![PlannedRange::new(
                                IpAddrRange::from(&Subnet {
                                    ip: Ipv4Addr::new(192, 168, 1, 25),
                                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                                    broadcast: Ipv4Addr::new(192, 168, 1, 255),
                                }),
                                None,
                            )],
                            (false, false, false) => Vec::new(),
                        },
                        broadcast_subnet: vec![Subnet {
                            ip: Ipv4Addr::new(192, 168, 1, 25),
                            netmask: Ipv4Addr::new(255, 255, 255, 0),
                            broadcast: Ipv4Addr::new(192, 168, 1, 255),
                        }],
                    },
                );
                let first_range = context_config
                    .range_to_ping
                    .first()
                    .map(|planned| planned.range.clone().into_iter().collect::<Vec<_>>());

                match (has_target_addresses, has_ip_ranges, enable_subnet_scan) {
                    (true, _, _) => {
                        assert_eq!(context_config.broadcast_subnet.len(), 1);
                        assert_eq!(first_range, Some(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]));
                    }
                    (false, true, _) => {
                        assert_eq!(context_config.broadcast_subnet.len(), 1);
                        assert_eq!(
                            first_range,
                            Some(vec![
                                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)),
                                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 41)),
                            ])
                        );
                    }
                    (false, false, true) => {
                        assert_eq!(context_config.broadcast_subnet.len(), 1);
                        assert_eq!(
                            first_range.as_ref().and_then(|range| range.first()).copied(),
                            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)))
                        );
                    }
                    (false, false, false) => {
                        assert_eq!(context_config.broadcast_subnet.len(), 1);
                        assert!(context_config.range_to_ping.is_empty());
                    }
                }
            }
        }
    }
}

fn scanner_config() -> ScannerConfig {
    ScannerConfig {
        ports: Vec::new(),
        timing: crate::scanner::TimingConfig {
            ping_interval: Duration::from_millis(1),
            ping_timeout: Duration::from_millis(1),
            broadcast_timeout: Duration::from_millis(1),
            port_scan_timeout: Duration::from_millis(1),
            netbios_timeout: Duration::from_millis(1),
            netbios_interval: Duration::from_millis(1),
            mdns_query_timeout: Duration::from_millis(1),
            max_wait_time: Duration::from_millis(1),
        },
        limits: crate::scanner::LimitsConfig::default(),
        targeting: crate::scanner::TargetingConfig {
            target_selector: TargetSelector::DefaultSubnets,
            interface_selector: InterfaceSelector::AllEligible,
            range_interface_policy: RangeInterfacePolicy::IntersectSelectedInterfaces,
            interface_bind_strict: false,
        },
    }
}

fn scanner_source(
    interface_id: &str,
    address: &str,
    start_address: &str,
    end_address: &str,
    broadcast_address: &str,
    prefix_length: u8,
) -> ScannerSource {
    ScannerSource {
        interface_id: interface_id.to_owned(),
        interface_name: format!("{interface_id} (IPv4)"),
        interface_description: None,
        interface_index: None,
        mac_address: None,
        is_up: Some(true),
        mtu: None,
        speed_mbps: None,
        link_type: crate::sources::LinkType::Unknown,
        address: address.parse().unwrap(),
        start_address: start_address.parse().unwrap(),
        end_address: end_address.parse().unwrap(),
        broadcast_address: Some(broadcast_address.parse().unwrap()),
        prefix_length: Some(prefix_length),
        capabilities: ScannerSourceCapabilities::default(),
    }
}
