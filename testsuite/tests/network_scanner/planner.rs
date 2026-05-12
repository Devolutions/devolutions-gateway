use std::net::Ipv4Addr;

use network_scanner::ip_utils::IpAddrRange;
use network_scanner::planner::{
    DEFAULT_MAX_TARGET_RANGE_ADDRESSES, InterfaceSelector, NetworkScanPlanError, RangeInterfacePolicy,
    ScanSourceSelectionError, TargetSelector, TargetSelectorValidationError, plan_scan,
};
use network_scanner::sources::{LinkType, ScannerSource, ScannerSourceCapabilities, ScannerSourceState};

#[test]
fn default_subnets_with_all_eligible_sources_scans_all_source_ranges() {
    let plan = plan_scan(
        &TargetSelector::DefaultSubnets,
        &InterfaceSelector::AllEligible,
        RangeInterfacePolicy::IntersectSelectedInterfaces,
        vec![eligible_source("eth0", "192.168.1.25", "192.168.1.0", "192.168.1.255")],
        true,
    )
    .unwrap();

    assert_eq!(plan.sources.len(), 1);
    assert_eq!(plan.broadcast_subnet.len(), 1);
    assert_eq!(
        range_addresses(&plan.range_to_ping[0].range),
        vec!["192.168.1.0", "192.168.1.1"]
    );
}

#[test]
fn selected_interfaces_limit_default_subnets_and_broadcast() {
    let plan = plan_scan(
        &TargetSelector::DefaultSubnets,
        &InterfaceSelector::Selected(vec!["wifi0".to_owned()]),
        RangeInterfacePolicy::IntersectSelectedInterfaces,
        vec![
            eligible_source("eth0", "192.168.1.25", "192.168.1.0", "192.168.1.255"),
            eligible_source("wifi0", "10.0.0.5", "10.0.0.0", "10.0.0.255"),
        ],
        true,
    )
    .unwrap();

    assert_eq!(plan.sources[0].interface_id, "wifi0");
    assert_eq!(plan.broadcast_subnet[0].broadcast, Ipv4Addr::new(10, 0, 0, 255));
    assert_eq!(
        range_addresses(&plan.range_to_ping[0].range),
        vec!["10.0.0.0", "10.0.0.1"]
    );
}

#[test]
fn explicit_hosts_scan_exact_hosts_even_when_interface_is_selected() {
    let plan = plan_scan(
        &TargetSelector::ExplicitHosts(vec!["192.168.1.10".parse().unwrap(), "10.0.0.20".parse().unwrap()]),
        &InterfaceSelector::Selected(vec!["eth0".to_owned()]),
        RangeInterfacePolicy::IntersectSelectedInterfaces,
        vec![eligible_source("eth0", "192.168.1.25", "192.168.1.0", "192.168.1.255")],
        true,
    )
    .unwrap();

    assert_eq!(range_addresses(&plan.range_to_ping[0].range), vec!["192.168.1.10"]);
    assert_eq!(range_addresses(&plan.range_to_ping[1].range), vec!["10.0.0.20"]);
}

#[test]
fn explicit_ranges_with_selected_interfaces_intersect_by_default() {
    let plan = plan_scan(
        &TargetSelector::ExplicitRanges(vec![
            IpAddrRange::try_from("192.168.1.100-192.168.2.10").unwrap(),
            IpAddrRange::try_from("9.0.0.1-10.0.0.50").unwrap(),
        ]),
        &InterfaceSelector::Selected(vec!["eth0".to_owned(), "wifi0".to_owned()]),
        RangeInterfacePolicy::IntersectSelectedInterfaces,
        vec![
            eligible_source("eth0", "192.168.1.25", "192.168.1.0", "192.168.1.255"),
            eligible_source("wifi0", "10.0.0.5", "10.0.0.0", "10.0.0.255"),
        ],
        true,
    )
    .unwrap();

    assert_eq!(plan.range_to_ping.len(), 2);
    assert_eq!(
        range_addresses(&plan.range_to_ping[0].range),
        vec!["192.168.1.100", "192.168.1.101"]
    );
    assert_eq!(
        range_addresses(&plan.range_to_ping[1].range),
        vec!["10.0.0.0", "10.0.0.1"]
    );
}

#[test]
fn explicit_ranges_can_allow_cross_interface_ranges() {
    let plan = plan_scan(
        &TargetSelector::ExplicitRanges(vec![IpAddrRange::try_from("192.168.1.100-10.0.0.50").unwrap()]),
        &InterfaceSelector::Selected(vec!["eth0".to_owned()]),
        RangeInterfacePolicy::AllowCrossInterfaceRange,
        vec![eligible_source("eth0", "192.168.1.25", "192.168.1.0", "192.168.1.255")],
        true,
    )
    .unwrap();

    assert_eq!(plan.range_to_ping.len(), 1);
    assert_eq!(
        range_addresses(&plan.range_to_ping[0].range),
        vec!["10.0.0.50", "10.0.0.51"]
    );
}

#[test]
fn selected_interface_errors_are_structured() {
    for (state, expected) in [
        (
            ScannerSourceState::Missing {
                interface_id: "eth0".to_owned(),
            },
            ScanSourceSelectionError::Missing {
                interface_id: "eth0".to_owned(),
            },
        ),
        (
            ScannerSourceState::Down {
                interface_id: "eth0".to_owned(),
            },
            ScanSourceSelectionError::Down {
                interface_id: "eth0".to_owned(),
            },
        ),
        (
            ScannerSourceState::LoopbackOnly {
                interface_id: "eth0".to_owned(),
            },
            ScanSourceSelectionError::LoopbackOnly {
                interface_id: "eth0".to_owned(),
            },
        ),
        (
            ScannerSourceState::NoScanCapableAddress {
                interface_id: "eth0".to_owned(),
            },
            ScanSourceSelectionError::NoScanCapableAddress {
                interface_id: "eth0".to_owned(),
            },
        ),
    ] {
        let error = plan_scan(
            &TargetSelector::DefaultSubnets,
            &InterfaceSelector::Selected(vec!["eth0".to_owned()]),
            RangeInterfacePolicy::IntersectSelectedInterfaces,
            vec![state],
            true,
        )
        .unwrap_err();

        let NetworkScanPlanError::InvalidInterface(error) = error else {
            panic!("expected InvalidInterface variant");
        };
        assert_eq!(error, expected);
        assert_eq!(error.interface_id(), "eth0");
    }
}

#[test]
fn planner_matrix_has_defined_behavior_for_target_interface_and_policy_combinations() {
    for target_selector in [
        TargetSelector::DefaultSubnets,
        TargetSelector::ExplicitHosts(vec!["192.168.1.10".parse().unwrap()]),
        TargetSelector::ExplicitRanges(vec![IpAddrRange::try_from("192.168.1.100-192.168.2.10").unwrap()]),
    ] {
        for interface_selector in [
            InterfaceSelector::AllEligible,
            InterfaceSelector::Selected(vec!["eth0".to_owned()]),
        ] {
            for policy in [
                RangeInterfacePolicy::IntersectSelectedInterfaces,
                RangeInterfacePolicy::AllowCrossInterfaceRange,
            ] {
                let plan = plan_scan(
                    &target_selector,
                    &interface_selector,
                    policy,
                    vec![eligible_source("eth0", "192.168.1.25", "192.168.1.0", "192.168.1.255")],
                    true,
                )
                .expect("planner matrix combination should have defined behavior");

                match (&target_selector, &interface_selector, policy) {
                    (
                        TargetSelector::ExplicitRanges(_),
                        InterfaceSelector::Selected(_),
                        RangeInterfacePolicy::IntersectSelectedInterfaces,
                    ) => {
                        assert_eq!(plan.range_to_ping.len(), 1);
                        assert_eq!(
                            range_addresses(&plan.range_to_ping[0].range),
                            vec!["192.168.1.100", "192.168.1.101"]
                        );
                    }
                    (TargetSelector::DefaultSubnets, _, _)
                    | (TargetSelector::ExplicitHosts(_), _, _)
                    | (TargetSelector::ExplicitRanges(_), _, _) => {
                        assert!(!plan.range_to_ping.is_empty());
                    }
                }
            }
        }
    }
}

#[test]
fn target_selector_validation_rejects_mixed_host_families() {
    let error = TargetSelector::ExplicitHosts(vec!["192.168.1.10".parse().unwrap(), "fd00::10".parse().unwrap()])
        .validate(DEFAULT_MAX_TARGET_RANGE_ADDRESSES)
        .unwrap_err();

    assert_eq!(error, TargetSelectorValidationError::MixedIpFamilies);
}

#[test]
fn target_selector_validation_rejects_mixed_range_families() {
    let error = TargetSelector::ExplicitRanges(vec![
        IpAddrRange::try_from("192.168.1.1-192.168.1.2").unwrap(),
        IpAddrRange::try_from("fd00::1-fd00::2").unwrap(),
    ])
    .validate(DEFAULT_MAX_TARGET_RANGE_ADDRESSES)
    .unwrap_err();

    assert_eq!(error, TargetSelectorValidationError::MixedIpFamilies);
}

#[test]
fn target_selector_validation_rejects_oversized_ranges() {
    let error = TargetSelector::ExplicitRanges(vec![IpAddrRange::try_from("192.168.0.0-192.169.0.0").unwrap()])
        .validate(DEFAULT_MAX_TARGET_RANGE_ADDRESSES)
        .unwrap_err();

    assert_eq!(
        error,
        TargetSelectorValidationError::RangeTooLarge {
            address_count: 65_537,
            max_range_addresses: DEFAULT_MAX_TARGET_RANGE_ADDRESSES,
        }
    );
}

fn eligible_source(interface_id: &str, address: &str, start_address: &str, end_address: &str) -> ScannerSourceState {
    ScannerSourceState::Eligible(ScannerSource {
        interface_id: interface_id.to_owned(),
        interface_name: format!("{interface_id} (IPv4)"),
        interface_description: None,
        interface_index: None,
        mac_address: None,
        is_up: Some(true),
        mtu: None,
        speed_mbps: None,
        link_type: LinkType::Unknown,
        address: address.parse().unwrap(),
        start_address: start_address.parse().unwrap(),
        end_address: end_address.parse().unwrap(),
        broadcast_address: Some(end_address.parse().unwrap()),
        prefix_length: Some(24),
        capabilities: ScannerSourceCapabilities::default(),
    })
}

fn range_addresses(range: &IpAddrRange) -> Vec<String> {
    range
        .clone()
        .into_iter()
        .take(2)
        .map(|address| address.to_string())
        .collect()
}
