use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded message size (1 MiB) to prevent denial-of-service via oversized frames.
pub const MAX_CONTROL_MESSAGE_SIZE: u32 = 1024 * 1024;

/// A normalized DNS domain name (lowercase).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainAdvertisement {
    /// The DNS domain (e.g., "contoso.local").
    pub domain: DomainName,
    /// Whether this domain was auto-detected (`true`) or explicitly configured (`false`).
    pub auto_detected: bool,
}

/// Control-plane messages exchanged over the dedicated control stream (stream ID 0).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlMessage {
    /// Agent advertises subnets and domains it can reach.
    RouteAdvertise {
        protocol_version: u16,
        /// Monotonically increasing epoch within this agent process lifetime.
        epoch: u64,
        /// Reachable subnets (IPv4 and IPv6).
        subnets: Vec<IpNetwork>,
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
}

impl ControlMessage {
    /// Create a new RouteAdvertise with the current protocol version.
    pub fn route_advertise(epoch: u64, subnets: Vec<IpNetwork>, domains: Vec<DomainAdvertisement>) -> Self {
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

    /// Extract the protocol version from any variant.
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::RouteAdvertise { protocol_version, .. }
            | Self::Heartbeat { protocol_version, .. }
            | Self::HeartbeatAck { protocol_version, .. } => *protocol_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::ControlStream;

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

    fn arb_ip_network() -> impl Strategy<Value = IpNetwork> {
        (any::<[u8; 4]>(), 0u8..=32).prop_map(|(octets, prefix)| {
            let ip = std::net::Ipv4Addr::from(octets);
            ipnetwork::Ipv4Network::new(ip, prefix)
                .map(|n| IpNetwork::V4(ipnetwork::Ipv4Network::new(n.network(), prefix).expect("normalized")))
                .unwrap_or_else(|_| {
                    IpNetwork::V4(ipnetwork::Ipv4Network::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0"))
                })
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
                proptest::collection::vec(arb_ip_network(), 0..50),
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
