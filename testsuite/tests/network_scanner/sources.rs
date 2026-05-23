use std::net::Ipv4Addr;

use network_scanner::sources::{
    LinkType, NetworkScanSourceProvider, ScannerSource, ScannerSourceCapabilities, select_sources, source_for_address,
    sources_to_broadcast_subnets,
};

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
fn fake_provider_returns_fixture_sources() {
    let source = ipv4_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let provider = FakeNetworkScanSourceProvider {
        sources: vec![source.clone()],
    };

    let sources = provider.get_sources().unwrap();

    assert_eq!(sources, vec![source]);
}

#[test]
fn sources_to_broadcast_subnets_keeps_only_broadcast_capable_ipv4_sources() {
    let broadcast_source = ipv4_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let mut no_broadcast_source = ipv4_source("wifi0", "10.0.0.5", "10.0.0.0", "10.0.0.255", "10.0.0.255", 24);
    no_broadcast_source.broadcast_address = None;
    no_broadcast_source.capabilities.broadcast = false;
    let ipv6_source = ScannerSource {
        interface_id: "eth0|IPv6|fe80::1".to_owned(),
        interface_name: "eth0 (IPv6)".to_owned(),
        interface_description: None,
        interface_index: None,
        mac_address: None,
        is_up: Some(true),
        mtu: None,
        speed_mbps: None,
        link_type: LinkType::Unknown,
        address: "fe80::1".parse().unwrap(),
        start_address: "fe80::1".parse().unwrap(),
        end_address: "fe80::1".parse().unwrap(),
        broadcast_address: None,
        prefix_length: Some(64),
        capabilities: ScannerSourceCapabilities {
            broadcast: false,
            ..ScannerSourceCapabilities::default()
        },
    };

    let subnets = sources_to_broadcast_subnets(&[broadcast_source, no_broadcast_source, ipv6_source]);

    assert_eq!(subnets.len(), 1);
    assert_eq!(subnets[0].ip, Ipv4Addr::new(192, 168, 1, 25));
    assert_eq!(subnets[0].netmask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(subnets[0].broadcast, Ipv4Addr::new(192, 168, 1, 255));
}

#[test]
fn rejects_invalid_prefix_when_converting_to_broadcast_subnet() {
    let mut source = ipv4_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    source.prefix_length = Some(33);

    assert!(source.as_broadcast_subnet().is_none());
}

#[test]
fn select_sources_returns_all_sources_when_no_selection_is_requested() {
    let eth0 = ipv4_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let wifi0 = ipv4_source("wifi0", "10.0.0.5", "10.0.0.0", "10.0.0.255", "10.0.0.255", 24);

    let selected_sources = select_sources(&[eth0.clone(), wifi0.clone()], &[]).unwrap();

    assert_eq!(selected_sources, vec![eth0, wifi0]);
}

#[test]
fn select_sources_keeps_only_requested_interface_ids() {
    let eth0 = ipv4_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let wifi0 = ipv4_source("wifi0", "10.0.0.5", "10.0.0.0", "10.0.0.255", "10.0.0.255", 24);

    let selected_sources = select_sources(&[eth0.clone(), wifi0], &["eth0".to_owned()]).unwrap();

    assert_eq!(selected_sources, vec![eth0]);
}

#[test]
fn select_sources_rejects_unknown_interface_ids() {
    let eth0 = ipv4_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );

    let error = select_sources(&[eth0], &["missing".to_owned()]).unwrap_err();

    assert!(error.to_string().contains("unknown network scan interface id"));
}

#[test]
fn source_for_address_returns_matching_source_range() {
    let eth0 = ipv4_source(
        "eth0",
        "192.168.1.25",
        "192.168.1.0",
        "192.168.1.255",
        "192.168.1.255",
        24,
    );
    let wifi0 = ipv4_source("wifi0", "10.0.0.5", "10.0.0.0", "10.0.0.255", "10.0.0.255", 24);

    let sources = [eth0, wifi0];
    let source = source_for_address(&sources, "10.0.0.10".parse().unwrap()).unwrap();

    assert_eq!(source.interface_id, "wifi0");
}

fn ipv4_source(
    id: &str,
    address: &str,
    start_address: &str,
    end_address: &str,
    broadcast_address: &str,
    prefix_length: u8,
) -> ScannerSource {
    ScannerSource {
        interface_id: id.to_owned(),
        interface_name: format!("{id} (IPv4)"),
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
        broadcast_address: Some(broadcast_address.parse().unwrap()),
        prefix_length: Some(prefix_length),
        capabilities: ScannerSourceCapabilities::default(),
    }
}
