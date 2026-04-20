#![allow(unused_crate_dependencies)]

use agent_tunnel_proto::{
    CertRenewalResult, ControlMessage, ControlStream, DomainAdvertisement, DomainName, MAX_CONTROL_MESSAGE_SIZE,
};

// ── DomainName::matches_hostname ──────────────────────────────────────

#[test]
fn matches_hostname_exact_match() {
    assert!(DomainName::new("contoso.local").matches_hostname("contoso.local"));
}

#[test]
fn matches_hostname_is_case_insensitive() {
    let d = DomainName::new("Contoso.LOCAL");
    assert!(d.matches_hostname("contoso.local"));
    assert!(d.matches_hostname("CONTOSO.LOCAL"));
    assert!(d.matches_hostname("Contoso.Local"));
}

#[test]
fn matches_hostname_suffix_match() {
    let d = DomainName::new("contoso.local");
    assert!(d.matches_hostname("dc01.contoso.local"));
    assert!(d.matches_hostname("finance.branch.contoso.local"));
}

#[test]
fn matches_hostname_rejects_partial_label() {
    // "fakecontoso.local" ends with "contoso.local" as a string, but the
    // preceding character isn't '.', so it's a different domain.
    let d = DomainName::new("contoso.local");
    assert!(!d.matches_hostname("fakecontoso.local"));
}

#[test]
fn matches_hostname_rejects_different_domain() {
    let d = DomainName::new("contoso.local");
    assert!(!d.matches_hostname("example.com"));
    assert!(!d.matches_hostname("local"));
    assert!(!d.matches_hostname(""));
}

#[test]
fn matches_hostname_rejects_parent_domain() {
    // The domain "finance.contoso.local" should not match the bare "contoso.local"
    // (bare name lacks the finance. prefix).
    let d = DomainName::new("finance.contoso.local");
    assert!(!d.matches_hostname("contoso.local"));
}

// ── Message roundtrips ────────────────────────────────────────────────

async fn roundtrip(msg: &ControlMessage) -> ControlMessage {
    let mut buf = Vec::new();
    let mut stream = ControlStream::new(&mut buf, &[][..]);
    stream.send(msg).await.expect("send should succeed");

    let mut stream = ControlStream::new(tokio::io::sink(), buf.as_slice());
    stream.recv().await.expect("recv should succeed")
}

#[tokio::test]
async fn roundtrip_route_advertise() {
    let msg = ControlMessage::route_advertise(
        42,
        vec![
            "10.0.0.0/8".parse().expect("valid CIDR"),
            "192.168.1.0/24".parse().expect("valid CIDR"),
        ],
        vec![],
    );
    assert_eq!(msg, roundtrip(&msg).await);
}

#[tokio::test]
async fn roundtrip_route_advertise_with_domains() {
    let msg = ControlMessage::route_advertise(
        42,
        vec!["10.0.0.0/8".parse().expect("valid CIDR")],
        vec![
            DomainAdvertisement {
                domain: DomainName::new("contoso.local"),
                auto_detected: false,
            },
            DomainAdvertisement {
                domain: DomainName::new("finance.contoso.local"),
                auto_detected: true,
            },
        ],
    );

    let decoded = roundtrip(&msg).await;
    assert_eq!(msg, decoded);

    match &decoded {
        ControlMessage::RouteAdvertise { domains, .. } => {
            assert_eq!(domains.len(), 2);
            assert_eq!(domains[0].domain.as_str(), "contoso.local");
            assert!(!domains[0].auto_detected);
            assert_eq!(domains[1].domain.as_str(), "finance.contoso.local");
            assert!(domains[1].auto_detected);
        }
        _ => panic!("expected RouteAdvertise"),
    }
}

#[tokio::test]
async fn roundtrip_route_advertise_empty_domains() {
    let msg = ControlMessage::route_advertise(1, vec!["192.168.1.0/24".parse().expect("valid CIDR")], vec![]);
    assert_eq!(msg, roundtrip(&msg).await);
}

#[tokio::test]
async fn roundtrip_heartbeat() {
    let msg = ControlMessage::heartbeat(1_700_000_000_000, 5);
    assert_eq!(msg, roundtrip(&msg).await);
}

#[tokio::test]
async fn roundtrip_heartbeat_ack() {
    let msg = ControlMessage::heartbeat_ack(1_700_000_000_000);
    assert_eq!(msg, roundtrip(&msg).await);
}

#[tokio::test]
async fn roundtrip_cert_renewal_request() {
    let msg = ControlMessage::cert_renewal_request(
        "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----".to_owned(),
    );
    assert_eq!(msg, roundtrip(&msg).await);
}

#[tokio::test]
async fn roundtrip_cert_renewal_response_success() {
    let msg = ControlMessage::cert_renewal_response(CertRenewalResult::Success {
        client_cert_pem: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----".to_owned(),
        gateway_ca_cert_pem: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----".to_owned(),
    });
    assert_eq!(msg, roundtrip(&msg).await);
}

#[tokio::test]
async fn roundtrip_cert_renewal_response_error() {
    let msg = ControlMessage::cert_renewal_response(CertRenewalResult::Error {
        reason: "CSR public key mismatch".to_owned(),
    });
    assert_eq!(msg, roundtrip(&msg).await);
}

#[tokio::test]
async fn reject_oversized_message() {
    let bad_len = (MAX_CONTROL_MESSAGE_SIZE + 1).to_be_bytes();
    let mut buf = bad_len.to_vec();
    buf.extend_from_slice(&[0u8; 32]);

    let mut stream = ControlStream::new(tokio::io::sink(), buf.as_slice());
    assert!(stream.recv().await.is_err());
}

// ── Property-based tests ──────────────────────────────────────────────

mod proptests {
    use agent_tunnel_proto::{
        CURRENT_PROTOCOL_VERSION, CertRenewalResult, ControlMessage, ControlStream, DomainAdvertisement, DomainName,
    };
    use ipnetwork::Ipv4Network;
    use proptest::prelude::*;

    fn arb_ipv4_network() -> impl Strategy<Value = Ipv4Network> {
        (any::<[u8; 4]>(), 0u8..=32).prop_map(|(octets, prefix)| {
            let ip = std::net::Ipv4Addr::from(octets);
            Ipv4Network::new(ip, prefix)
                .map(|n| Ipv4Network::new(n.network(), prefix).expect("normalized"))
                .unwrap_or_else(|_| Ipv4Network::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0"))
        })
    }

    fn arb_domain_advertisement() -> impl Strategy<Value = DomainAdvertisement> {
        ("[a-z]{3,10}\\.[a-z]{2,5}", any::<bool>()).prop_map(|(domain, auto_detected)| DomainAdvertisement {
            domain: DomainName::new(domain),
            auto_detected,
        })
    }

    fn arb_control_message() -> impl Strategy<Value = ControlMessage> {
        prop_oneof![
            (
                any::<u64>(),
                proptest::collection::vec(arb_ipv4_network(), 0..50),
                proptest::collection::vec(arb_domain_advertisement(), 0..5),
            )
                .prop_map(|(epoch, subnets, domains)| {
                    ControlMessage::RouteAdvertise {
                        protocol_version: CURRENT_PROTOCOL_VERSION,
                        epoch,
                        subnets,
                        domains,
                    }
                }),
            (any::<u64>(), any::<u32>()).prop_map(|(timestamp_ms, active_stream_count)| {
                ControlMessage::Heartbeat {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    timestamp_ms,
                    active_stream_count,
                }
            }),
            any::<u64>().prop_map(|timestamp_ms| ControlMessage::HeartbeatAck {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                timestamp_ms,
            }),
            "[a-zA-Z0-9/+=\n]{10,100}".prop_map(|csr_pem| ControlMessage::CertRenewalRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                csr_pem,
            }),
            prop_oneof![
                ("[a-zA-Z0-9/+=\n]{10,100}", "[a-zA-Z0-9/+=\n]{10,100}").prop_map(
                    |(client_cert_pem, gateway_ca_cert_pem)| {
                        ControlMessage::CertRenewalResponse {
                            protocol_version: CURRENT_PROTOCOL_VERSION,
                            result: CertRenewalResult::Success {
                                client_cert_pem,
                                gateway_ca_cert_pem,
                            },
                        }
                    }
                ),
                "[a-z ]{5,30}".prop_map(|reason| ControlMessage::CertRenewalResponse {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    result: CertRenewalResult::Error { reason },
                }),
            ],
        ]
    }

    proptest! {
        #[test]
        fn control_message_roundtrip(msg in arb_control_message()) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(async {
                let mut buf = Vec::new();
                let mut stream = ControlStream::new(&mut buf, &[][..]);
                stream.send(&msg).await.expect("send should succeed");

                let mut stream = ControlStream::new(tokio::io::sink(), buf.as_slice());
                let decoded = stream.recv().await.expect("recv should succeed");
                prop_assert_eq!(msg, decoded);
                Ok(())
            })?;
        }
    }
}
