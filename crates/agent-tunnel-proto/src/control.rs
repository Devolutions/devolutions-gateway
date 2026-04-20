use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use ipnetwork::Ipv4Network;

use crate::codec::{self, Decode, Encode};
use crate::error::ProtoError;
use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded message size (1 MiB) to prevent denial-of-service via oversized frames.
pub const MAX_CONTROL_MESSAGE_SIZE: u32 = 1024 * 1024;

// Wire format message type tags.
const TAG_ROUTE_ADVERTISE: u8 = 0x01;
const TAG_HEARTBEAT: u8 = 0x02;
const TAG_HEARTBEAT_ACK: u8 = 0x03;
const TAG_CERT_RENEWAL_REQUEST: u8 = 0x04;
const TAG_CERT_RENEWAL_RESPONSE: u8 = 0x05;

// CertRenewalResult sub-tags.
const TAG_CERT_SUCCESS: u8 = 0x00;
const TAG_CERT_ERROR: u8 = 0x01;

/// A normalized DNS domain name (lowercase).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct DomainName(String);

impl DomainName {
    pub fn new(domain: impl Into<String>) -> Self {
        Self(domain.into().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if `hostname` matches this domain via DNS suffix matching.
    ///
    /// Matches if `hostname == domain` (exact) or `hostname` ends with `.domain`.
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        let hostname = hostname.to_ascii_lowercase();
        hostname == self.0
            || (hostname.len() > self.0.len()
                && hostname.as_bytes()[hostname.len() - self.0.len() - 1] == b'.'
                && hostname.ends_with(&self.0))
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A DNS domain advertisement with its source.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainAdvertisement {
    /// The DNS domain (e.g., "contoso.local").
    pub domain: DomainName,
    /// Whether this domain was auto-detected (`true`) or explicitly configured (`false`).
    pub auto_detected: bool,
}

/// Control-plane messages exchanged over the dedicated control stream (stream ID 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Agent advertises subnets and domains it can reach.
    RouteAdvertise {
        protocol_version: u16,
        /// Monotonically increasing epoch within this agent process lifetime.
        epoch: u64,
        /// Reachable subnets (IPv4 and IPv6).
        subnets: Vec<Ipv4Network>,
        /// DNS domains this agent can resolve, with source tracking.
        domains: Vec<DomainAdvertisement>,
    },

    /// Periodic liveness probe.
    Heartbeat {
        protocol_version: u16,
        /// Milliseconds since UNIX epoch (sender's wall clock).
        timestamp_ms: u64,
        /// Number of currently active proxy streams on this connection.
        active_stream_count: u32,
    },

    /// Acknowledgement to a Heartbeat.
    HeartbeatAck {
        protocol_version: u16,
        /// Echoed timestamp from the corresponding Heartbeat.
        timestamp_ms: u64,
    },

    /// Agent requests certificate renewal (sends new CSR, key unchanged).
    CertRenewalRequest {
        protocol_version: u16,
        /// PEM-encoded Certificate Signing Request.
        csr_pem: String,
    },

    /// Gateway responds to a certificate renewal request.
    CertRenewalResponse {
        protocol_version: u16,
        result: CertRenewalResult,
    },
}

/// Result of a certificate renewal attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertRenewalResult {
    Success {
        /// PEM-encoded renewed client certificate.
        client_cert_pem: String,
        /// PEM-encoded gateway CA certificate.
        gateway_ca_cert_pem: String,
    },
    Error {
        reason: String,
    },
}

impl ControlMessage {
    /// Create a new RouteAdvertise with the current protocol version.
    pub fn route_advertise(epoch: u64, subnets: Vec<Ipv4Network>, domains: Vec<DomainAdvertisement>) -> Self {
        Self::RouteAdvertise {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            epoch,
            subnets,
            domains,
        }
    }

    /// Create a new Heartbeat with the current protocol version.
    pub fn heartbeat(timestamp_ms: u64, active_stream_count: u32) -> Self {
        Self::Heartbeat {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            timestamp_ms,
            active_stream_count,
        }
    }

    /// Create a new HeartbeatAck with the current protocol version.
    pub fn heartbeat_ack(timestamp_ms: u64) -> Self {
        Self::HeartbeatAck {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            timestamp_ms,
        }
    }

    /// Create a certificate renewal request with the current protocol version.
    pub fn cert_renewal_request(csr_pem: String) -> Self {
        Self::CertRenewalRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            csr_pem,
        }
    }

    /// Create a certificate renewal response with the current protocol version.
    pub fn cert_renewal_response(result: CertRenewalResult) -> Self {
        Self::CertRenewalResponse {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            result,
        }
    }

    /// Extract the protocol version from any variant.
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::RouteAdvertise { protocol_version, .. }
            | Self::Heartbeat { protocol_version, .. }
            | Self::HeartbeatAck { protocol_version, .. }
            | Self::CertRenewalRequest { protocol_version, .. }
            | Self::CertRenewalResponse { protocol_version, .. } => *protocol_version,
        }
    }
}

impl Encode for ControlMessage {
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::RouteAdvertise {
                protocol_version,
                epoch,
                subnets,
                domains,
            } => {
                buf.put_u8(TAG_ROUTE_ADVERTISE);
                buf.put_u16(*protocol_version);
                buf.put_u64(*epoch);
                encode_subnets(buf, subnets);
                encode_domains(buf, domains);
            }
            Self::Heartbeat {
                protocol_version,
                timestamp_ms,
                active_stream_count,
            } => {
                buf.put_u8(TAG_HEARTBEAT);
                buf.put_u16(*protocol_version);
                buf.put_u64(*timestamp_ms);
                buf.put_u32(*active_stream_count);
            }
            Self::HeartbeatAck {
                protocol_version,
                timestamp_ms,
            } => {
                buf.put_u8(TAG_HEARTBEAT_ACK);
                buf.put_u16(*protocol_version);
                buf.put_u64(*timestamp_ms);
            }
            Self::CertRenewalRequest {
                protocol_version,
                csr_pem,
            } => {
                buf.put_u8(TAG_CERT_RENEWAL_REQUEST);
                buf.put_u16(*protocol_version);
                codec::put_string(buf, csr_pem);
            }
            Self::CertRenewalResponse {
                protocol_version,
                result,
            } => {
                buf.put_u8(TAG_CERT_RENEWAL_RESPONSE);
                buf.put_u16(*protocol_version);
                encode_cert_renewal_result(buf, result);
            }
        }
    }
}

impl Decode for ControlMessage {
    fn decode(mut buf: Bytes) -> Result<Self, ProtoError> {
        codec::ensure_remaining(buf.remaining(), 1, "control message tag")?;
        let tag = buf.get_u8();

        match tag {
            TAG_ROUTE_ADVERTISE => {
                codec::ensure_remaining(buf.remaining(), 2 + 8, "RouteAdvertise header")?;
                let protocol_version = buf.get_u16();
                let epoch = buf.get_u64();
                let subnets = decode_subnets(&mut buf)?;
                let domains = decode_domains(&mut buf)?;
                Ok(Self::RouteAdvertise {
                    protocol_version,
                    epoch,
                    subnets,
                    domains,
                })
            }
            TAG_HEARTBEAT => {
                codec::ensure_remaining(buf.remaining(), 2 + 8 + 4, "Heartbeat")?;
                let protocol_version = buf.get_u16();
                let timestamp_ms = buf.get_u64();
                let active_stream_count = buf.get_u32();
                Ok(Self::Heartbeat {
                    protocol_version,
                    timestamp_ms,
                    active_stream_count,
                })
            }
            TAG_HEARTBEAT_ACK => {
                codec::ensure_remaining(buf.remaining(), 2 + 8, "HeartbeatAck")?;
                let protocol_version = buf.get_u16();
                let timestamp_ms = buf.get_u64();
                Ok(Self::HeartbeatAck {
                    protocol_version,
                    timestamp_ms,
                })
            }
            TAG_CERT_RENEWAL_REQUEST => {
                codec::ensure_remaining(buf.remaining(), 2, "CertRenewalRequest version")?;
                let protocol_version = buf.get_u16();
                let csr_pem = codec::get_string(&mut buf)?;
                Ok(Self::CertRenewalRequest {
                    protocol_version,
                    csr_pem,
                })
            }
            TAG_CERT_RENEWAL_RESPONSE => {
                codec::ensure_remaining(buf.remaining(), 2, "CertRenewalResponse version")?;
                let protocol_version = buf.get_u16();
                let result = decode_cert_renewal_result(&mut buf)?;
                Ok(Self::CertRenewalResponse {
                    protocol_version,
                    result,
                })
            }
            _ => Err(ProtoError::UnknownTag { tag }),
        }
    }
}

// ---------------------------------------------------------------------------
// Subnet encode/decode
// ---------------------------------------------------------------------------

// Each subnet is encoded as `[4B ipv4_octets][1B prefix]`. No family tag —
// if IPv6 is ever added, `protocol_version` bumps and the format can
// reintroduce a tag cleanly.
#[expect(
    clippy::cast_possible_truncation,
    reason = "count bounded by MAX_CONTROL_MESSAGE_SIZE"
)]
fn encode_subnets(buf: &mut BytesMut, subnets: &[Ipv4Network]) {
    buf.put_u32(subnets.len() as u32);
    for subnet in subnets {
        buf.put_slice(&subnet.ip().octets());
        buf.put_u8(subnet.prefix());
    }
}

fn decode_subnets(buf: &mut Bytes) -> Result<Vec<Ipv4Network>, ProtoError> {
    codec::ensure_remaining(buf.remaining(), 4, "subnet count")?;
    let count = buf.get_u32() as usize;
    let mut subnets = Vec::with_capacity(count);

    for _ in 0..count {
        codec::ensure_remaining(buf.remaining(), 4 + 1, "IPv4 subnet")?;
        let mut octets = [0u8; 4];
        buf.copy_to_slice(&mut octets);
        let prefix = buf.get_u8();
        let ip = std::net::Ipv4Addr::from(octets);
        let network = Ipv4Network::new(ip, prefix).map_err(|_| ProtoError::InvalidField {
            field: "subnet",
            reason: "invalid IPv4 prefix length",
        })?;
        subnets.push(network);
    }

    Ok(subnets)
}

// ---------------------------------------------------------------------------
// Domain encode/decode
// ---------------------------------------------------------------------------

#[expect(
    clippy::cast_possible_truncation,
    reason = "count bounded by MAX_CONTROL_MESSAGE_SIZE"
)]
fn encode_domains(buf: &mut BytesMut, domains: &[DomainAdvertisement]) {
    buf.put_u32(domains.len() as u32);
    for adv in domains {
        codec::put_string(buf, adv.domain.as_str());
        buf.put_u8(u8::from(adv.auto_detected));
    }
}

fn decode_domains(buf: &mut Bytes) -> Result<Vec<DomainAdvertisement>, ProtoError> {
    codec::ensure_remaining(buf.remaining(), 4, "domain count")?;
    let count = buf.get_u32() as usize;
    let mut domains = Vec::with_capacity(count);

    for _ in 0..count {
        let domain_str = codec::get_string(buf)?;
        codec::ensure_remaining(buf.remaining(), 1, "auto_detected flag")?;
        let auto_detected = buf.get_u8() != 0;
        domains.push(DomainAdvertisement {
            domain: DomainName::new(domain_str),
            auto_detected,
        });
    }

    Ok(domains)
}

// ---------------------------------------------------------------------------
// CertRenewalResult encode/decode
// ---------------------------------------------------------------------------

fn encode_cert_renewal_result(buf: &mut BytesMut, result: &CertRenewalResult) {
    match result {
        CertRenewalResult::Success {
            client_cert_pem,
            gateway_ca_cert_pem,
        } => {
            buf.put_u8(TAG_CERT_SUCCESS);
            codec::put_string(buf, client_cert_pem);
            codec::put_string(buf, gateway_ca_cert_pem);
        }
        CertRenewalResult::Error { reason } => {
            buf.put_u8(TAG_CERT_ERROR);
            codec::put_string(buf, reason);
        }
    }
}

fn decode_cert_renewal_result(buf: &mut Bytes) -> Result<CertRenewalResult, ProtoError> {
    codec::ensure_remaining(buf.remaining(), 1, "CertRenewalResult tag")?;
    let tag = buf.get_u8();
    match tag {
        TAG_CERT_SUCCESS => {
            let client_cert_pem = codec::get_string(buf)?;
            let gateway_ca_cert_pem = codec::get_string(buf)?;
            Ok(CertRenewalResult::Success {
                client_cert_pem,
                gateway_ca_cert_pem,
            })
        }
        TAG_CERT_ERROR => {
            let reason = codec::get_string(buf)?;
            Ok(CertRenewalResult::Error { reason })
        }
        _ => Err(ProtoError::UnknownTag { tag }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::ControlStream;

    // ── DomainName::matches_hostname ──────────────────────────────────

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

    // ── Message roundtrips ────────────────────────────────────────────

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
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;
    use crate::stream::ControlStream;
    use crate::version::CURRENT_PROTOCOL_VERSION;

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
