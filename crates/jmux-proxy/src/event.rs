//! JMUX traffic observation and audit event types.
//!
//! This module models one **traffic item** per JMUX channel lifecycle, regardless of
//! transport. For connection-oriented transports (e.g., TCP), a traffic item maps to a
//! single connection. For connectionless transports (e.g., UDP), a traffic item maps to
//! the lifetime of a JMUX-managed datagram channel.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Transport protocol for the traffic item.
///
/// `Udp` is included for protocol neutrality; current implementations may emit
/// only TCP events until UDP channels are introduced.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// How a traffic item's lifecycle ended.
///
/// This classification determines how to interpret timing and byte counts in
/// an audit event, and whether an error occurred.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EventOutcome {
    /// Could not establish a transport to a concrete socket address.
    ///
    /// Emitted when DNS resolution produced one or more addresses but every
    /// connect/open attempt failed (e.g., refused, timeout, unreachable). For
    /// multi-address hosts (Happy Eyeballs), this reflects the last address
    /// attempted.
    ///
    /// Not emitted for **DNS resolution failures** (no concrete IP); in that
    /// case, no event is produced.
    ///
    /// Characteristics:
    /// - `bytes_tx == 0` and `bytes_rx == 0`
    /// - `disconnect_at == connect_at` (same instant)
    /// - `active_duration == Duration::ZERO`
    ConnectFailure,

    /// Data path was established but the traffic item ended with an error.
    ///
    /// Examples:
    /// - TCP: connection reset, write/read error, timeout during active use
    /// - UDP: channel error or fatal I/O when the channel was open
    ///
    /// Characteristics:
    /// - `bytes_tx`/`bytes_rx` may be 0 or >0 (partial transfer is possible)
    /// - `active_duration >= Duration::ZERO` (the item was active)
    AbnormalTermination,

    /// Data path was established and the traffic item ended cleanly.
    ///
    /// Examples:
    /// - TCP: graceful shutdown or EOF→close sequence
    /// - UDP: whole datagram was transferred without error
    ///
    /// Characteristics:
    /// - `bytes_tx`/`bytes_rx` may be 0 or >0
    /// - `active_duration >= Duration::ZERO`
    NormalTermination,
}

/// Complete audit information for one traffic item's lifecycle.
///
/// A single `TrafficEvent` is emitted exactly once per JMUX traffic item when
/// it ends (successfully or with error).
///
/// # Timestamp semantics
///
/// - `connect_at`: **When the first connect/open attempt to a concrete `SocketAddr` began**
///   (i.e., after DNS resolution).
/// - `disconnect_at`: When the transport was closed or the connect/open attempt failed.
/// - `active_duration`: `disconnect_at - connect_at` (saturating at zero).
///
/// For `ConnectFailure`, `connect_at == disconnect_at` and `active_duration == 0`.
///
/// # Byte counting
///
/// - `bytes_tx`: total application payload bytes sent to the remote peer.
/// - `bytes_rx`: total application payload bytes received from the remote peer.
/// - JMUX framing and transport-layer overhead are **not** included.
/// - Always zero for `ConnectFailure`. May be zero for successful but idle items.
///
/// # Target information
///
/// - `target_host`: the raw host string from the request (pre-DNS). It can be a hostname
///   or an IP literal.
/// - `target_ip`: the concrete IP used:
///   - success: the peer's IP address (e.g., `peer_addr()` for TCP)
///   - connect failure: the last IP that was attempted
/// - `target_port`: the destination port.
///
/// DNS failures do **not** produce an event because `target_ip` is unknown.
#[derive(Clone, Debug)]
pub struct TrafficEvent {
    /// How the traffic item's lifecycle ended.
    pub outcome: EventOutcome,

    /// Transport protocol for this traffic item.
    pub protocol: TransportProtocol,

    /// Original target host string (pre-DNS).
    ///
    /// This is exactly what the requester supplied and may be:
    /// - an IP literal (e.g., `"192.168.1.1"`, `"::1"`)
    /// - a DNS hostname (e.g., `"example.com"`)
    /// - a service name, depending on the calling context
    pub target_host: String,

    /// Concrete target IP address (post-DNS / chosen address).
    ///
    /// - On success, this is the peer's IP address.
    /// - On connect failure, this is the last IP address attempted.
    ///
    /// Events are only emitted when this is known.
    pub target_ip: IpAddr,

    /// Destination port number.
    pub target_port: u16,

    /// When the first connect/open attempt to the chosen address began.
    pub connect_at: SystemTime,

    /// When the transport closed or the attempt failed.
    ///
    /// For `ConnectFailure`, this equals `connect_at`.
    pub disconnect_at: SystemTime,

    /// Total lifecycle duration: `disconnect_at - connect_at` (saturating).
    pub active_duration: Duration,

    /// Total application payload bytes sent to the remote peer.
    pub bytes_tx: u64,

    /// Total application payload bytes received from the remote peer.
    pub bytes_rx: u64,
}

/// Type-erased traffic audit callback.
///
/// Invoked exactly once per JMUX traffic item at end-of-lifecycle. The callback
/// itself is **synchronous**; perform any asynchronous work by spawning within
/// the callback (e.g., `tokio::spawn`) or by sending to an internal channel.
///
/// # Exactly-once
///
/// - Each traffic item yields exactly one event.
/// - Emitted at cleanup time, not during operation.
/// - Guarded to prevent duplicate emission.
/// - No aggregation—each event stands alone.
///
/// # Thread-safety
///
/// Must be `Send + Sync + 'static`. Keep the function lightweight to avoid
/// blocking JMUX tasks; offload heavy work to background tasks.
///
/// # Example
///
/// ```rust,ignore
/// let proxy = JmuxProxy::new(reader, writer)
///     .with_traffic_event_callback(|event| {
///         // Log quickly...
///         tracing::info!(
///             outcome = ?event.outcome,
///             host = %event.target_host,
///             ip = %event.target_ip,
///             port = event.target_port,
///             "traffic event"
///         );
///
///         // ...and/or offload I/O to an async task.
///         tokio::spawn(async move {
///             let _ = database.store_audit_event(event).await;
///         });
///     });
/// ```
pub(crate) type TrafficCallback = Arc<dyn Fn(TrafficEvent) + Send + Sync + 'static>;
