//! Control-plane message types.
//!
//! Encoding and decoding live in [`crate::control_codec`].

use ipnetwork::Ipv4Network;

use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded message size (1 MiB) to prevent denial-of-service via oversized frames.
pub const MAX_CONTROL_MESSAGE_SIZE: u32 = 1024 * 1024;

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
