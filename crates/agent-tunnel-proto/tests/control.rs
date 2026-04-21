#![allow(unused_crate_dependencies)]

use agent_tunnel_proto::{
    CertRenewalResult, ControlMessage, ControlStream, DomainAdvertisement, DomainName, MAX_CONTROL_MESSAGE_SIZE,
    ProtoError,
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

// ── Wire format lock-in ───────────────────────────────────────────────
//
// These tests pin the on-the-wire byte layout down. If anyone changes a
// tag value, a field's byte order, or the field order inside a variant,
// the assertion will fail loudly instead of being quietly absorbed by
// the roundtrip tests.

async fn send_control(msg: &ControlMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut stream = ControlStream::new(&mut buf, &[][..]);
    stream.send(msg).await.expect("send should succeed");
    buf
}

#[tokio::test]
async fn heartbeat_wire_format_is_stable() {
    let msg = ControlMessage::heartbeat(0x1234_5678_9ABC_DEF0, 42);
    let bytes = send_control(&msg).await;
    #[rustfmt::skip]
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x0F,                         // outer length = 15
        0x02,                                           // TAG_HEARTBEAT
        0x00, 0x01,                                     // protocol_version = 1
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // timestamp_ms
        0x00, 0x00, 0x00, 0x2A,                         // active_stream_count = 42
    ];
    assert_eq!(bytes, expected);
}

#[tokio::test]
async fn heartbeat_ack_wire_format_is_stable() {
    let msg = ControlMessage::heartbeat_ack(0x0102_0304_0506_0708);
    let bytes = send_control(&msg).await;
    #[rustfmt::skip]
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x0B,                         // outer length = 11
        0x03,                                           // TAG_HEARTBEAT_ACK
        0x00, 0x01,                                     // protocol_version = 1
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // timestamp_ms
    ];
    assert_eq!(bytes, expected);
}

// ── Negative decode paths ─────────────────────────────────────────────
//
// Build a malformed `[4B length][payload]` frame and assert that the
// decode pipeline surfaces the specific error variant we expect.

async fn recv_payload(payload: &[u8]) -> ProtoError {
    let len = u32::try_from(payload.len()).expect("test payload fits in u32");
    let mut buf = len.to_be_bytes().to_vec();
    buf.extend_from_slice(payload);
    let mut stream = ControlStream::new(tokio::io::sink(), buf.as_slice());
    stream.recv().await.expect_err("decode should fail")
}

#[tokio::test]
async fn decode_rejects_unknown_message_tag() {
    // Tag 0xFF is not assigned to any ControlMessage variant.
    let err = recv_payload(&[0xFF, 0x00, 0x01]).await;
    assert!(matches!(err, ProtoError::UnknownTag { tag: 0xFF }), "got {err:?}");
}

#[tokio::test]
async fn decode_rejects_truncated_heartbeat() {
    // TAG_HEARTBEAT then only 4 more bytes where 14 are needed.
    let err = recv_payload(&[0x02, 0x00, 0x01, 0x00, 0x00]).await;
    assert!(matches!(err, ProtoError::Truncated { .. }), "got {err:?}");
}

#[tokio::test]
async fn decode_rejects_invalid_utf8_in_string() {
    // TAG_CERT_RENEWAL_REQUEST + version + 3-byte string that isn't UTF-8.
    let mut payload = vec![0x04, 0x00, 0x01];
    payload.extend_from_slice(&3u32.to_be_bytes());
    payload.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
    let err = recv_payload(&payload).await;
    assert!(
        matches!(err, ProtoError::InvalidField { field: "string", .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn decode_rejects_invalid_ipv4_prefix() {
    // RouteAdvertise with a subnet whose prefix is 33 (valid range is 0..=32).
    let mut payload = vec![0x01]; // TAG_ROUTE_ADVERTISE
    payload.extend_from_slice(&1u16.to_be_bytes()); // protocol_version
    payload.extend_from_slice(&0u64.to_be_bytes()); // epoch
    payload.extend_from_slice(&1u32.to_be_bytes()); // subnet count = 1
    payload.extend_from_slice(&[10, 0, 0, 0]); // ipv4 octets
    payload.push(33); // invalid prefix
    payload.extend_from_slice(&0u32.to_be_bytes()); // domain count = 0
    let err = recv_payload(&payload).await;
    assert!(
        matches!(err, ProtoError::InvalidField { field: "subnet", .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn decode_rejects_unknown_cert_renewal_result_subtag() {
    // TAG_CERT_RENEWAL_RESPONSE + version + sub-tag 0xFF (neither Success nor Error).
    let err = recv_payload(&[0x05, 0x00, 0x01, 0xFF]).await;
    assert!(matches!(err, ProtoError::UnknownTag { tag: 0xFF }), "got {err:?}");
}

// ── Send-side size enforcement ────────────────────────────────────────

#[tokio::test]
async fn send_rejects_oversized_message() {
    // CertRenewalRequest carries an arbitrary-length string; pad it so the
    // encoded message blows past MAX_CONTROL_MESSAGE_SIZE.
    let huge = "A".repeat((MAX_CONTROL_MESSAGE_SIZE as usize) + 100);
    let msg = ControlMessage::cert_renewal_request(huge);

    let mut buf = Vec::new();
    let mut stream = ControlStream::new(&mut buf, &[][..]);
    let err = stream.send(&msg).await.expect_err("oversized send should fail");
    assert!(matches!(err, ProtoError::MessageTooLarge { .. }), "got {err:?}");
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
