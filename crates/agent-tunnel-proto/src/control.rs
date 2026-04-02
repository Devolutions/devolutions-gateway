use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::error::ProtoError;
use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded message size (1 MiB) to prevent denial-of-service via oversized frames.
pub const MAX_CONTROL_MESSAGE_SIZE: u32 = 1024 * 1024;

/// A DNS domain advertisement with its source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainAdvertisement {
    /// The DNS domain (e.g., "contoso.local").
    pub domain: String,
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
        /// Reachable IPv4 subnets.
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

    /// Length-prefixed bincode encode and write to an async writer.
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), ProtoError> {
        let payload = bincode::serialize(self)?;
        let len = u32::try_from(payload.len()).map_err(|_| ProtoError::MessageTooLarge {
            size: u32::MAX,
            max: MAX_CONTROL_MESSAGE_SIZE,
        })?;
        if MAX_CONTROL_MESSAGE_SIZE < len {
            return Err(ProtoError::MessageTooLarge {
                size: len,
                max: MAX_CONTROL_MESSAGE_SIZE,
            });
        }
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&payload).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Read and decode a length-prefixed bincode message from an async reader.
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ProtoError> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);

        if MAX_CONTROL_MESSAGE_SIZE < len {
            return Err(ProtoError::MessageTooLarge {
                size: len,
                max: MAX_CONTROL_MESSAGE_SIZE,
            });
        }

        let mut payload = vec![0u8; len as usize];
        reader.read_exact(&mut payload).await?;
        let msg: Self = bincode::deserialize(&payload)?;
        Ok(msg)
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

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ControlMessage::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn roundtrip_route_advertise_with_domains() {
        let msg = ControlMessage::route_advertise(
            42,
            vec!["10.0.0.0/8".parse().expect("valid CIDR")],
            vec![
                DomainAdvertisement {
                    domain: "contoso.local".to_owned(),
                    auto_detected: false,
                },
                DomainAdvertisement {
                    domain: "finance.contoso.local".to_owned(),
                    auto_detected: true,
                },
            ],
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ControlMessage::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);

        match &decoded {
            ControlMessage::RouteAdvertise { domains, .. } => {
                assert_eq!(domains.len(), 2);
                assert_eq!(domains[0].domain, "contoso.local");
                assert!(!domains[0].auto_detected);
                assert_eq!(domains[1].domain, "finance.contoso.local");
                assert!(domains[1].auto_detected);
            }
            _ => panic!("expected RouteAdvertise"),
        }
    }

    #[tokio::test]
    async fn roundtrip_route_advertise_empty_domains() {
        let msg = ControlMessage::route_advertise(1, vec!["192.168.1.0/24".parse().expect("valid CIDR")], vec![]);

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ControlMessage::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn roundtrip_heartbeat() {
        let msg = ControlMessage::heartbeat(1_700_000_000_000, 5);

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ControlMessage::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn roundtrip_heartbeat_ack() {
        let msg = ControlMessage::heartbeat_ack(1_700_000_000_000);

        let mut buf = Vec::new();
        msg.encode(&mut buf).await.expect("encode should succeed");

        let decoded = ControlMessage::decode(&mut buf.as_slice())
            .await
            .expect("decode should succeed");

        assert_eq!(msg, decoded);
    }

    #[tokio::test]
    async fn reject_oversized_message() {
        // Craft a length prefix that exceeds the maximum
        let bad_len = (MAX_CONTROL_MESSAGE_SIZE + 1).to_be_bytes();
        let mut buf = bad_len.to_vec();
        buf.extend_from_slice(&[0u8; 32]); // dummy payload

        let result = ControlMessage::decode(&mut buf.as_slice()).await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;
    use crate::version::CURRENT_PROTOCOL_VERSION;

    fn arb_ipv4_network() -> impl Strategy<Value = Ipv4Network> {
        (any::<[u8; 4]>(), 0u8..=32).prop_map(|(octets, prefix)| {
            let ip = std::net::Ipv4Addr::from(octets);
            // Use network() to normalize the address for the given prefix
            Ipv4Network::new(ip, prefix)
                .map(|n| Ipv4Network::new(n.network(), prefix).expect("normalized network should be valid"))
                .unwrap_or_else(|_| Ipv4Network::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is valid"))
        })
    }

    fn arb_domain_advertisement() -> impl Strategy<Value = DomainAdvertisement> {
        ("[a-z]{3,10}\\.[a-z]{2,5}", any::<bool>())
            .prop_map(|(domain, auto_detected)| DomainAdvertisement { domain, auto_detected })
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
        ]
    }

    proptest! {
        #[test]
        fn control_message_roundtrip(msg in arb_control_message()) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(async {
                let mut buf = Vec::new();
                msg.encode(&mut buf).await.expect("encode should succeed");
                let decoded = ControlMessage::decode(&mut buf.as_slice()).await.expect("decode should succeed");
                prop_assert_eq!(msg, decoded);
                Ok(())
            })?;
        }
    }
}
