use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ulid::Ulid;
use uuid::Uuid;

/// Transport protocol for the traffic item.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TransportProtocol {
    Tcp = 0,
    Udp = 1,
}

/// Classification of traffic item lifecycle outcome.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EventOutcome {
    /// Could not establish a transport to a concrete socket address.
    ConnectFailure = 0,
    /// Data path was established but the traffic item ended with an error.
    NormalTermination = 1,
    /// Data path was established and the traffic item ended cleanly.
    AbnormalTermination = 2,
}

/// Audit information for a single traffic item lifecycle.
///
/// Contains comprehensive metadata about a network traffic item's connection attempt,
/// data transfer, and termination. This represents the core event data that
/// will be stored in the audit repository.
#[derive(Clone, Debug)]
pub struct TrafficEvent {
    /// Unique identifier for the session/tunnel this traffic item belongs to
    pub session_id: Uuid,
    /// Classification of how the traffic item lifecycle ended
    pub outcome: EventOutcome,
    /// Transport protocol used for the connection attempt
    pub protocol: TransportProtocol,
    /// Original target host string before DNS resolution
    pub target_host: String,
    /// Concrete target IP address after resolution
    pub target_ip: IpAddr,
    /// Target port number for the connection
    pub target_port: u16,
    /// Timestamp when the connection attempt began (epoch milliseconds)
    pub connect_at_ms: i64,
    /// Timestamp when the traffic item was closed or connection failed (epoch milliseconds)
    pub disconnect_at_ms: i64,
    /// Total duration the traffic item was active (milliseconds)
    pub active_duration_ms: i64,
    /// Total bytes transmitted to the remote peer
    pub bytes_tx: u64,
    /// Total bytes received from the remote peer
    pub bytes_rx: u64,
}

/// A claimed event with its database ID for acknowledgment.
///
/// Returned by claim operations to allow consumers to acknowledge
/// processing completion by referencing the database row ID.
#[derive(Debug, Clone)]
pub struct ClaimedEvent {
    /// Database row ID for acknowledgment
    pub id: Ulid,
    /// The traffic event data
    pub event: TrafficEvent,
}

pub type DynTrafficAuditRepo = Arc<dyn TrafficAuditRepo>;

/// Storage-agnostic trait for traffic audit repository operations.
///
/// Provides at-least-once delivery semantics with lease-based claim/ack pattern
/// for multi-consumer scenarios. Events are enqueued once per traffic item and
/// are discarded after acknowledgment (no retention).
#[async_trait]
pub trait TrafficAuditRepo: Send + Sync {
    /// Performs initial setup required before using the repository.
    ///
    /// This function should be called first, before using any of the other functions.
    /// It handles database migrations, PRAGMA setup, and other initialization tasks.
    async fn setup(&self) -> anyhow::Result<()>;

    /// Pushes a new traffic event into the repository.
    ///
    /// Events are enqueued with the current timestamp and made available
    /// for claiming by consumers. This operation should be lightweight
    /// as it's called from the event callback context.
    async fn push(&self, event: TrafficEvent) -> anyhow::Result<()>;

    /// Claims available events for processing with lease-based locking.
    ///
    /// Returns at most `limit` events that are locked to the specified consumer
    /// for the lease duration. Events remain locked until acknowledged or the
    /// lease expires. Multiple consumers can claim disjoint sets concurrently.
    ///
    /// # Arguments
    /// * `consumer_id` - Unique identifier for this consumer instance
    /// * `lease_duration_ms` - How long to hold the lease (milliseconds)
    /// * `limit` - Maximum number of events to claim
    async fn claim(&self, consumer_id: &str, lease_duration_ms: u32, limit: usize)
    -> anyhow::Result<Vec<ClaimedEvent>>;

    /// Acknowledges processing completion and removes events from the repository.
    ///
    /// Events are permanently deleted after acknowledgment as we don't retain
    /// audit data after forwarding.
    async fn ack(&self, ids: &[Ulid]) -> anyhow::Result<u64>;

    /// Extends the lease on claimed events to prevent timeout.
    ///
    /// Useful for long-running processing operations that might exceed
    /// the original lease duration. Only the owning consumer can extend leases.
    async fn extend_lease(&self, ids: &[Ulid], consumer_id: &str, lease_duration_ms: i64) -> anyhow::Result<()>;

    /// Purges old unclaimed events from the repository.
    ///
    /// Removes events that were enqueued before the specified cutoff time and are not
    /// currently claimed by any consumer. This helps prevent unbounded growth when
    /// events are not being consumed or when consumers are down for extended periods.
    ///
    /// # Arguments
    /// * `cutoff_time_ms` - Events enqueued before this timestamp (epoch milliseconds) will be purged
    ///
    /// # Returns
    /// Number of events purged from the repository
    async fn purge(&self, cutoff_time_ms: i64) -> anyhow::Result<u64>;
}
