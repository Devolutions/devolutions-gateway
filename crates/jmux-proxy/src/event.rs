//! JMUX stream observation and audit event types.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Protocol used for the stream connection.
///
/// Represents the network protocol type for JMUX stream connections.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamProtocol {
    /// Transmission Control Protocol - reliable, ordered, connection-oriented
    Tcp,
    /// User Datagram Protocol - unreliable, connectionless
    Udp,
}

/// Classification of stream lifecycle outcome.
///
/// Determines how a JMUX stream's lifecycle ended, which affects the interpretation
/// of timing, byte counts, and error handling in audit events.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EventOutcome {
    /// Connection attempt failed before stream establishment.
    ///
    /// Triggered when:
    /// - DNS resolution succeeds but TCP socket connection fails
    /// - Examples: port refused, timeout, network unreachable, connection reset
    /// - Happy Eyeballs: emitted for the last failed address when all addresses fail
    ///
    /// **Not triggered for:**
    /// - DNS resolution failures (no concrete IP address available)
    ///
    /// Characteristics:
    /// - `bytes_tx` and `bytes_rx` are always 0
    /// - `connect_at` equals `disconnect_at` (same timestamp)
    /// - `active_duration` is `Duration::ZERO`
    ConnectFailure,

    /// Stream was established but terminated due to an error.
    ///
    /// Triggered when:
    /// - Connection reset by peer (TCP RST)
    /// - Network errors during data transfer
    /// - Unexpected connection drops
    /// - I/O errors that terminate the stream prematurely
    ///
    /// Characteristics:
    /// - `bytes_tx` and `bytes_rx` may be 0 or >0 (partial transfer possible)
    /// - `active_duration` >= `Duration::ZERO` (stream was active)
    /// - Indicates abnormal network conditions or peer behavior
    AbnormalTermination,

    /// Stream was established and terminated cleanly.
    ///
    /// Triggered when:
    /// - Clean EOF→Close sequence
    /// - Graceful shutdown by either peer
    /// - Normal completion of data transfer
    ///
    /// Characteristics:
    /// - `bytes_tx` and `bytes_rx` may be 0 or >0 (any amount of data)
    /// - `active_duration` >= `Duration::ZERO`
    /// - Indicates successful operation
    NormalTermination,
}

/// Complete audit information for a single JMUX stream lifecycle.
///
/// Contains comprehensive metadata about a network stream's connection attempt,
/// data transfer, and termination. Emitted exactly once per JMUX stream at the
/// end of its lifecycle through the configured stream callback.
///
/// # Timestamp Semantics
///
/// - `connect_at`: When the connection attempt started (before DNS resolution)
/// - `disconnect_at`: When the stream was closed or connection failed
/// - `active_duration`: Computed as `disconnect_at - connect_at`, represents
///   total time from connection attempt to final cleanup
///
/// For `ConnectFailure` events, `connect_at == disconnect_at` since no stream
/// was established.
///
/// # Byte Counting
///
/// - `bytes_tx`: Total bytes transmitted from local to remote peer
/// - `bytes_rx`: Total bytes received from remote to local peer
/// - Counts actual application data, not including protocol overhead
/// - Always 0 for `ConnectFailure` events
/// - May be 0 for successful connections with no data transfer
///
/// # Target Information
///
/// - `target_host`: Original host string from connection request (before DNS)
/// - `target_ip`: Concrete IP address (post-resolution or peer address)
/// - `target_port`: Target port number
///
/// DNS resolution failures result in no event emission since `target_ip`
/// cannot be determined. For multi-address hostnames (Happy Eyeballs),
/// ConnectFailure events use the IP of the last failed connection attempt.
#[derive(Clone, Debug)]
pub struct StreamEvent {
    /// Classification of how the stream lifecycle ended.
    pub outcome: EventOutcome,

    /// Network protocol used for the connection attempt.
    pub protocol: StreamProtocol,

    /// Original target host string before DNS resolution.
    ///
    /// This is the raw host string from the connection request, which could be:
    /// - An IP address literal (e.g., "192.168.1.1", "::1")
    /// - A DNS hostname (e.g., "example.com")
    /// - A service name (depending on the connection context)
    pub target_host: String,

    /// Concrete target IP address after resolution.
    ///
    /// For successful connections, this is the peer's IP address.
    /// For connection failures, this is the IP address that was attempted.
    /// Events are only emitted when this can be determined.
    pub target_ip: IpAddr,

    /// Target port number for the connection.
    pub target_port: u16,

    /// Timestamp when the connection attempt began.
    ///
    /// Captured before DNS resolution and socket connection. For all events,
    /// this represents the start of the stream's lifecycle.
    pub connect_at: SystemTime,

    /// Timestamp when the stream was closed or connection failed.
    ///
    /// For `ConnectFailure`: same as `connect_at` (immediate failure)
    /// For termination events: when cleanup and unregistration occurred
    pub disconnect_at: SystemTime,

    /// Total duration the stream was active.
    ///
    /// Computed as `disconnect_at.duration_since(connect_at)`. Represents
    /// the complete lifecycle duration from connection attempt to cleanup.
    /// Always `Duration::ZERO` for `ConnectFailure` events.
    pub active_duration: Duration,

    /// Total bytes transmitted to the remote peer.
    ///
    /// Counts application-level data bytes sent over the network.
    /// Does not include protocol framing or JMUX overhead.
    /// Always 0 for `ConnectFailure` events.
    pub bytes_tx: u64,

    /// Total bytes received from the remote peer.
    ///
    /// Counts application-level data bytes received from the network.
    /// Does not include protocol framing or JMUX overhead.
    /// Always 0 for `ConnectFailure` events.
    pub bytes_rx: u64,
}

/// Type-erased stream audit callback function.
///
/// This callback is invoked exactly once per JMUX stream at the end of its lifecycle
/// to emit audit events. The callback is synchronous - consumers are responsible for
/// handling any async work (e.g., database writes, network calls) by using patterns
/// like `tokio::spawn` or message passing within their callback implementation.
///
/// # Exactly-Once Semantics
///
/// - Each JMUX stream generates exactly one audit event
/// - Events are emitted at stream cleanup time, not during operation
/// - Protected by atomic guards to prevent duplicate emission
/// - No aggregation - each event represents a single stream
///
/// # Thread Safety
///
/// The callback must be `Send + Sync + 'static` as it may be invoked from any
/// JMUX task context. Implementations should be efficient to avoid blocking
/// the JMUX event loop.
///
/// # Example Usage
///
/// ```rust,ignore
/// let proxy = JmuxProxy::new(reader, writer)
///     .with_stream_event_callback(|event| {
///         // Log the event
///         log::info!("Stream {}: {} to {}:{}",
///             event.outcome, event.target_host, event.target_ip, event.port);
///         
///         // Handle async work in a spawned task
///         tokio::spawn(async move {
///             database.store_audit_event(event).await;
///         });
///     });
/// ```
pub(crate) type StreamCallback = Arc<dyn Fn(StreamEvent) + Send + Sync + 'static>;
