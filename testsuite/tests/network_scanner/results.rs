use network_scanner::broadcast::BroadcastEvent;
use network_scanner::event_bus::ScannerEvent;
use network_scanner::mdns::MdnsEvent;
use network_scanner::named_port::{MaybeNamedPort, NamedPort};
use network_scanner::netbios::NetBiosEvent;
use network_scanner::ping::{PingEvent, PingFailedReason};
use network_scanner::port_discovery::{PortScanFailedReason, TcpKnockEvent};
use network_scanner::results::{NetworkScanResponseFormat, ScanEventFilter, ScanEventFilterConfig};
use network_scanner::scanner::{DnsEvent, ServiceType, TcpKnockWithHost};
use network_scanner::sources::{LinkType, ScannerSource, ScannerSourceCapabilities};

/// Test helper: build a `ScanEventFilter` from positional bools so the
/// dozens of filter-matrix tests don't each have to spell out the config
/// struct.
fn filter_with(
    report_ping_start: bool,
    report_ping_success: bool,
    report_ping_failure: bool,
    report_tcp_failure: bool,
    include_host_results: bool,
    response_format: NetworkScanResponseFormat,
) -> ScanEventFilter {
    ScanEventFilter::new(ScanEventFilterConfig {
        report_ping_start,
        report_ping_success,
        report_ping_failure,
        report_tcp_failure,
        include_host_results,
        response_format,
    })
}

#[test]
fn legacy_filter_suppresses_host_results_without_suppressing_services() {
    let filter = filter_with(true, true, true, true, false, NetworkScanResponseFormat::Legacy);

    assert_eq!(
        filter.serialize_event(
            ScannerEvent::Ping(PingEvent::Success {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                time: 1,
            }),
            &[]
        ),
        None
    );
    assert!(
        filter
            .serialize_event(
                ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                    tcp_knock: TcpKnockEvent::Success {
                        ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                        port: MaybeNamedPort::Port(3389),
                        time: 12,
                    },
                    host: None,
                }),
                &[]
            )
            .is_some()
    );
}

#[test]
fn legacy_filter_hides_ping_start_unless_enabled() {
    let filter = filter_with(false, true, true, true, true, NetworkScanResponseFormat::Legacy);

    assert_eq!(
        filter.serialize_event(
            ScannerEvent::Ping(PingEvent::Start {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
            }),
            &[]
        ),
        None
    );
}

#[test]
fn legacy_filter_hides_failures_unless_enabled() {
    let filter = filter_with(true, true, false, false, true, NetworkScanResponseFormat::Legacy);

    assert_eq!(
        filter.serialize_event(
            ScannerEvent::Ping(PingEvent::Failed {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                reason: PingFailedReason::TimedOut,
            }),
            &[]
        ),
        None
    );
}

#[test]
fn legacy_maps_named_tcp_service_to_existing_protocol_code() {
    let filter = filter_with(true, true, true, true, true, NetworkScanResponseFormat::Legacy);

    let json = filter
        .serialize_event(
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                tcp_knock: TcpKnockEvent::Success {
                    ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                    port: MaybeNamedPort::Named(NamedPort::Rdp),
                    time: 12,
                },
                host: None,
            }),
            &[],
        )
        .expect("TCP success should produce legacy JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("legacy JSON should parse");

    assert_eq!(value["protocol"], "rdp");
}

#[test]
fn network_scan_result_v1_maps_ping_success_to_host_result() {
    let source = scanner_source();
    let filter = filter_with(
        true,
        true,
        true,
        true,
        true,
        NetworkScanResponseFormat::NetworkScanResultV1,
    );

    let json = filter
        .serialize_event(
            ScannerEvent::Ping(PingEvent::Success {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                time: 7,
            }),
            &[source],
        )
        .expect("ping success should produce network scan result JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("network scan result JSON should parse");

    // Plan §9 wire shape: kind/source/discoverySource/hostScanState
    // values are lowercase, `source` is constant `"gateway"`, and the
    // discovery path is in `discoverySource`.
    assert_eq!(value["kind"], "host");
    assert_eq!(value["address"], "192.168.1.10");
    assert_eq!(value["source"], "gateway");
    assert_eq!(value["discoverySource"], "subnet");
    assert_eq!(value["interfaceId"], "eth0");
    assert_eq!(value["interfaceName"], "Ethernet (IPv4)");
    assert_eq!(value["isReachable"], serde_json::Value::Bool(true));
    assert_eq!(value["hostScanState"], "reachable");
    assert_eq!(value["responseTimeMs"], 7);
}

#[test]
fn network_scan_result_v1_maps_ping_queued_to_host_result() {
    let source = scanner_source();
    let filter = filter_with(
        true,
        true,
        true,
        true,
        true,
        NetworkScanResponseFormat::NetworkScanResultV1,
    );

    let json = filter
        .serialize_event(
            ScannerEvent::Ping(PingEvent::Queued {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
            }),
            &[source],
        )
        .expect("ping queued should produce network scan result JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("network scan result JSON should parse");

    assert_eq!(value["kind"], "host");
    assert_eq!(value["hostScanState"], "queued");
}

#[test]
fn network_scan_result_v1_maps_tcp_success_to_service_result() {
    let source = scanner_source();
    let filter = filter_with(
        true,
        true,
        true,
        true,
        true,
        NetworkScanResponseFormat::NetworkScanResultV1,
    );

    let json = filter
        .serialize_event(
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                tcp_knock: TcpKnockEvent::Success {
                    ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                    port: MaybeNamedPort::Port(3389),
                    time: 12,
                },
                host: Some("host1".to_owned()),
            }),
            &[source],
        )
        .expect("TCP success should produce network scan result JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("network scan result JSON should parse");

    assert_eq!(value["kind"], "service");
    assert_eq!(value["address"], "192.168.1.10");
    assert_eq!(value["hostName"], "host1");
    assert_eq!(value["source"], "gateway");
    assert_eq!(value["discoverySource"], "tcp_probe");
    assert_eq!(value["serviceLabel"], "RDP");
    assert_eq!(value["serviceType"], "RDP");
    assert_eq!(value["port"], 3389);
    assert_eq!(value["responseTimeMs"], 12);
}

#[test]
fn network_scan_result_v1_maps_discovery_sources() {
    let source = scanner_source();
    let filter = filter_with(
        true,
        true,
        true,
        true,
        true,
        NetworkScanResponseFormat::NetworkScanResultV1,
    );

    let broadcast = filter
        .serialize_event(
            ScannerEvent::Broadcast(BroadcastEvent::Entry {
                ip: "192.168.1.11".parse().expect("fixture IPv4 address should parse"),
                time: Some(4),
            }),
            std::slice::from_ref(&source),
        )
        .expect("broadcast event should produce network scan result JSON");
    let dns = filter
        .serialize_event(
            ScannerEvent::Dns(DnsEvent::Success {
                ip: "192.168.1.12".parse().expect("fixture IPv4 address should parse"),
                hostname: "host2".to_owned(),
            }),
            &[source],
        )
        .expect("DNS event should produce network scan result JSON");

    let broadcast: serde_json::Value =
        serde_json::from_str(&broadcast).expect("broadcast network scan result JSON should parse");
    let dns: serde_json::Value = serde_json::from_str(&dns).expect("DNS network scan result JSON should parse");

    assert_eq!(broadcast["source"], "gateway");
    assert_eq!(broadcast["discoverySource"], "broadcast");
    assert_eq!(dns["source"], "gateway");
    assert_eq!(dns["discoverySource"], "gateway");
    assert_eq!(dns["hostName"], "host2");
}

#[test]
fn network_scan_result_v1_omits_mac_address_when_unknown() {
    // Plan §9 declares `macAddress` in the wire schema, but it's only
    // populated by ARP/NDP discovery (not in this build). The field must
    // therefore be absent from serialized events — neither `null` nor a
    // placeholder string — so consumers can rely on `macAddress` being
    // present iff a real hardware address was learned.
    let source = scanner_source();
    let filter = filter_with(
        true,
        true,
        true,
        true,
        true,
        NetworkScanResponseFormat::NetworkScanResultV1,
    );

    let host_json = filter
        .serialize_event(
            ScannerEvent::Ping(PingEvent::Success {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                time: 7,
            }),
            std::slice::from_ref(&source),
        )
        .expect("ping success should produce network scan result JSON");
    let service_json = filter
        .serialize_event(
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                tcp_knock: TcpKnockEvent::Success {
                    ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                    port: MaybeNamedPort::Port(3389),
                    time: 12,
                },
                host: None,
            }),
            &[source],
        )
        .expect("TCP knock success should produce network scan result JSON");

    let host: serde_json::Value = serde_json::from_str(&host_json).expect("host network scan result JSON should parse");
    let service: serde_json::Value =
        serde_json::from_str(&service_json).expect("service network scan result JSON should parse");

    let host_obj = host.as_object().expect("host result must be a JSON object");
    let service_obj = service.as_object().expect("service result must be a JSON object");

    assert!(
        !host_obj.contains_key("macAddress"),
        "host result must omit macAddress when ARP/NDP did not provide one (got {host_obj:?})"
    );
    assert!(
        !service_obj.contains_key("macAddress"),
        "service result must omit macAddress when ARP/NDP did not provide one (got {service_obj:?})"
    );
}

#[test]
fn filter_matrix_covers_all_event_and_toggle_permutations() {
    struct EventCase {
        name: &'static str,
        event: ScannerEvent,
        expect_legacy: fn(bool, bool, bool, bool, bool) -> bool,
        expect_v1: fn(bool, bool, bool, bool, bool) -> bool,
    }

    fn ping_start(start: bool, _success: bool, _failure: bool, _tcp_failure: bool, include_hosts: bool) -> bool {
        start && include_hosts
    }

    fn ping_success(_start: bool, success: bool, _failure: bool, _tcp_failure: bool, include_hosts: bool) -> bool {
        success && include_hosts
    }

    fn ping_failure(_start: bool, _success: bool, failure: bool, _tcp_failure: bool, include_hosts: bool) -> bool {
        failure && include_hosts
    }

    fn host_only(_start: bool, _success: bool, _failure: bool, _tcp_failure: bool, include_hosts: bool) -> bool {
        include_hosts
    }

    fn service_success(_start: bool, _success: bool, _failure: bool, _tcp_failure: bool, _include_hosts: bool) -> bool {
        true
    }

    fn legacy_service_failure(
        _start: bool,
        _success: bool,
        _failure: bool,
        tcp_failure: bool,
        _include_hosts: bool,
    ) -> bool {
        tcp_failure
    }

    fn never(_start: bool, _success: bool, _failure: bool, _tcp_failure: bool, _include_hosts: bool) -> bool {
        false
    }

    let cases = vec![
        EventCase {
            name: "ping_start",
            event: ScannerEvent::Ping(PingEvent::Start {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
            }),
            expect_legacy: ping_start,
            expect_v1: ping_start,
        },
        EventCase {
            name: "ping_success",
            event: ScannerEvent::Ping(PingEvent::Success {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                time: 7,
            }),
            expect_legacy: ping_success,
            expect_v1: ping_success,
        },
        EventCase {
            name: "ping_failure",
            event: ScannerEvent::Ping(PingEvent::Failed {
                ip: "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                reason: PingFailedReason::TimedOut,
            }),
            expect_legacy: ping_failure,
            expect_v1: ping_failure,
        },
        EventCase {
            name: "broadcast_entry",
            event: ScannerEvent::Broadcast(BroadcastEvent::Entry {
                ip: "192.168.1.11".parse().expect("fixture IPv4 address should parse"),
                time: Some(3),
            }),
            expect_legacy: never,
            expect_v1: host_only,
        },
        EventCase {
            name: "dns_success",
            event: ScannerEvent::Dns(DnsEvent::Success {
                ip: "192.168.1.12".parse().expect("fixture IPv4 address should parse"),
                hostname: "host2".to_owned(),
            }),
            expect_legacy: host_only,
            expect_v1: host_only,
        },
        EventCase {
            name: "dns_failed",
            event: ScannerEvent::Dns(DnsEvent::Failed {
                ip: "192.168.1.12".parse().expect("fixture IPv4 address should parse"),
            }),
            expect_legacy: never,
            expect_v1: never,
        },
        EventCase {
            name: "netbios_success",
            event: ScannerEvent::NetBios(NetBiosEvent::Success {
                ip: "192.168.1.13".parse().expect("fixture IPv4 address should parse"),
                name: "host3".to_owned(),
                time: Some(2),
            }),
            expect_legacy: host_only,
            expect_v1: host_only,
        },
        EventCase {
            name: "mdns_service",
            event: ScannerEvent::Mdns(MdnsEvent::ServiceResolved {
                addr: "192.168.1.14".parse().expect("fixture IPv4 address should parse"),
                device_name: "host4".to_owned(),
                protocol: Some(ServiceType::Rdp),
                port: 3389,
                time: Some(11),
            }),
            expect_legacy: service_success,
            expect_v1: service_success,
        },
        EventCase {
            name: "tcp_success",
            event: ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                tcp_knock: TcpKnockEvent::Success {
                    ip: "192.168.1.15".parse().expect("fixture IPv4 address should parse"),
                    port: MaybeNamedPort::Named(NamedPort::Rdp),
                    time: 12,
                },
                host: Some("host5".to_owned()),
            }),
            expect_legacy: service_success,
            expect_v1: service_success,
        },
        EventCase {
            name: "tcp_failure",
            event: ScannerEvent::TcpKnockWithHost(TcpKnockWithHost {
                tcp_knock: TcpKnockEvent::Failed {
                    ip: "192.168.1.16".parse().expect("fixture IPv4 address should parse"),
                    port: MaybeNamedPort::Named(NamedPort::Rdp),
                    reason: PortScanFailedReason::Rejected,
                },
                host: None,
            }),
            // V1 now mirrors Legacy: failed TCP probes are emitted as
            // Service entries with `failureReason` populated when
            // `report_tcp_failure=true`; otherwise suppressed.
            expect_legacy: legacy_service_failure,
            expect_v1: legacy_service_failure,
        },
    ];
    let source = scanner_source();

    for response_format in [
        NetworkScanResponseFormat::Legacy,
        NetworkScanResponseFormat::NetworkScanResultV1,
    ] {
        for report_ping_start in [false, true] {
            for report_ping_success in [false, true] {
                for report_ping_failure in [false, true] {
                    for report_tcp_failure in [false, true] {
                        for include_host_results in [false, true] {
                            let filter = filter_with(
                                report_ping_start,
                                report_ping_success,
                                report_ping_failure,
                                report_tcp_failure,
                                include_host_results,
                                response_format,
                            );

                            for case in &cases {
                                let expected = match response_format {
                                    NetworkScanResponseFormat::Legacy => (case.expect_legacy)(
                                        report_ping_start,
                                        report_ping_success,
                                        report_ping_failure,
                                        report_tcp_failure,
                                        include_host_results,
                                    ),
                                    NetworkScanResponseFormat::NetworkScanResultV1 => (case.expect_v1)(
                                        report_ping_start,
                                        report_ping_success,
                                        report_ping_failure,
                                        report_tcp_failure,
                                        include_host_results,
                                    ),
                                };
                                let actual = filter
                                    .serialize_event(case.event.clone(), std::slice::from_ref(&source))
                                    .is_some();
                                assert_eq!(
                                    actual, expected,
                                    "case={} format={response_format:?} report_ping_start={report_ping_start} report_ping_success={report_ping_success} report_ping_failure={report_ping_failure} report_tcp_failure={report_tcp_failure} include_host_results={include_host_results}",
                                    case.name
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn scanner_source() -> ScannerSource {
    ScannerSource {
        interface_id: "eth0".to_owned(),
        interface_name: "Ethernet (IPv4)".to_owned(),
        interface_description: None,
        interface_index: None,
        mac_address: Some("00-11-22-33-44-55".to_owned()),
        is_up: Some(true),
        mtu: None,
        speed_mbps: None,
        link_type: LinkType::Unknown,
        address: "192.168.1.25".parse().expect("fixture IPv4 address should parse"),
        start_address: "192.168.1.0".parse().expect("fixture IPv4 address should parse"),
        end_address: "192.168.1.255".parse().expect("fixture IPv4 address should parse"),
        broadcast_address: Some("192.168.1.255".parse().expect("fixture IPv4 address should parse")),
        prefix_length: Some(24),
        capabilities: ScannerSourceCapabilities::default(),
    }
}
