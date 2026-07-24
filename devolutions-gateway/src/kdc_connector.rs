//! Outbound dispatcher for KDC messages.
//!
//! Bundles the three inputs the agent-tunnel routing pipeline needs (`session_id`,
//! `explicit_agent_id`, `agent_tunnel_handle`) into a single value so callers do not
//! thread those primitives through every layer of CredSSP machinery — and so the
//! routing decision is always taken by `agent_tunnel::routing::try_route`, never
//! pre-decided by the caller.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use ironrdp_connector::sspi::generator::NetworkRequest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

use crate::http::{HttpError, HttpErrorBuilder};
use crate::target_addr::TargetAddr;
use crate::upstream::route_target_from_target_addr;

/// Maximum number of retries for a transient direct KDC failure.
///
/// The retry loop performs at most `KDC_MAX_RETRIES` retries after the initial attempt,
/// so `KDC_MAX_RETRIES + 1` attempts in total.
const KDC_MAX_RETRIES: usize = 3;

/// Sends Kerberos messages to a KDC, consulting the agent-tunnel routing pipeline.
///
/// All three fields are always passed to [`agent_tunnel::routing::try_route`]; the
/// routing pipeline decides whether to route via an agent, fail, or fall through to a
/// direct connection. Callers do not pre-decide between "direct" and "via tunnel".
///
/// Field semantics:
///
/// - `session_id` — tag sent to the agent for log correlation. RDP CredSSP/NLA callers
///   pass `claims.jet_aid` so KDC sub-traffic correlates with its parent RDP session;
///   the HTTP `/jet/KdcProxy` endpoint passes the KDC token's own `jti` (no parent).
///
/// - `explicit_agent_id` — the parent association token's `jet_agent_id`, if any. When
///   set, traffic must route via that specific agent (or fail). The routing pipeline
///   enforces this even when `agent_tunnel_handle` is `None`.
///
/// - `agent_tunnel_handle` — `Some` whenever the Gateway is running an agent tunnel
///   listener. Whether *this* particular request goes through it still depends on the
///   target matching an advertised agent route.
#[derive(Clone)]
pub struct KdcConnector {
    session_id: Uuid,
    explicit_agent_id: Option<Uuid>,
    agent_tunnel_handle: Option<Arc<agent_tunnel::AgentTunnelHandle>>,
}

impl KdcConnector {
    pub fn new(
        session_id: Uuid,
        explicit_agent_id: Option<Uuid>,
        agent_tunnel_handle: Option<Arc<agent_tunnel::AgentTunnelHandle>>,
    ) -> Self {
        Self {
            session_id,
            explicit_agent_id,
            agent_tunnel_handle,
        }
    }

    /// Send a Kerberos message to `kdc_addr` and return the reply bytes.
    pub async fn send(&self, kdc_addr: &TargetAddr, message: &[u8]) -> Result<Vec<u8>, HttpError> {
        let kdc_target = kdc_addr.as_addr();
        let route_target = route_target_from_target_addr(kdc_addr);

        let route_result = agent_tunnel::routing::try_route(
            self.agent_tunnel_handle.as_deref(),
            self.explicit_agent_id,
            &route_target,
            self.session_id,
            kdc_target,
        )
        .await
        .map_err(|e| HttpError::bad_gateway().build(format!("KDC routing through agent tunnel failed: {e:#}")))?;

        if let Some((mut stream, _)) = route_result {
            // The agent tunnel currently carries only TCP (`ConnectRequest::tcp`). If the
            // routing pipeline picked an agent for a udp:// KDC target — either by subnet
            // match or by explicit pin — we must reject explicitly. Silently falling
            // through to direct UDP here would bypass an explicit `jet_agent_id` pin and
            // bypass the routing decision in general.
            if kdc_addr.scheme().eq_ignore_ascii_case("udp") {
                return Err(HttpError::bad_gateway().build(
                    "agent tunnel does not yet support UDP; udp:// KDC requests cannot be routed through an agent",
                ));
            }

            info!(%kdc_addr, "Forwarding message to KDC server through agent tunnel");

            // Unlike the direct branch below, the agent-tunnel exchange is not retried.
            //
            // Retrying from here would mean re-running `try_route` to obtain a
            // fresh stream (a new substream, the agent re-dialing the KDC) and
            // replaying the whole exchange.
            //
            // Whether to add this remains an open question.
            stream.write_all(message).await.map_err(
                HttpError::bad_gateway()
                    .with_msg("unable to send KDC message through agent tunnel")
                    .err(),
            )?;

            return read_kdc_reply_message(&mut stream).await.map_err(
                HttpError::bad_gateway()
                    .with_msg("unable to read KDC reply through agent tunnel")
                    .err(),
            );
        } else {
            info!(%kdc_addr, "Forwarding message to KDC server");

            // Direct fallback. `try_route` returning `Ok(None)` means: no matching agent and
            // no explicit pin — the caller is allowed to direct-connect with the scheme it
            // chose. Transient connection drops (see `DirectSendError`) are retried a bounded
            // number of times.
            self.send_direct_with_retry(kdc_addr, message).await
        }
    }

    /// Drives [`Self::send_direct`] through a bounded retry loop.
    ///
    /// The KDC occasionally drops a successfully established connection instead of replying
    /// (suspected DC-side load: connection throttling, port exhaustion). Those failures
    /// surface as transient IO errors, most notably `UnexpectedEof` on the reply read. We
    /// retry them a few times, spacing attempts with jittered exponential backoff so a
    /// loaded KDC gets breathing room and concurrent retries do not synchronize into a
    /// storm. Permanent failures are surfaced on the first occurrence.
    async fn send_direct_with_retry(&self, kdc_addr: &TargetAddr, message: &[u8]) -> Result<Vec<u8>, HttpError> {
        use tokio_retry::RetryIf;
        use tokio_retry::strategy::ExponentialBackoff;

        // Exponential backoff yielding 1.2s, 2.4s and 4.8s before each retry,
        // passed through equal jitter to de-synchronize concurrent retries
        // against a loaded KDC. `take` bounds the loop to `KDC_MAX_RETRIES`
        // retries after the initial attempt.
        let backoff = ExponentialBackoff::from_millis(2)
            .factor(600)
            .max_delay(Duration::from_secs(10))
            .map(equal_jitter)
            .take(KDC_MAX_RETRIES);

        // Count transient failures so the log carries the attempt number. `RetryIf` evaluates
        // the condition on every failure, including the last one whose retry is never scheduled
        // (the backoff iterator is exhausted); the count reflects attempts made, not retries left.
        let mut attempt = 0;

        RetryIf::start(
            backoff,
            || self.send_direct(kdc_addr, message),
            |error: &DirectSendError| match error {
                DirectSendError::Transient(error) => {
                    attempt += 1;
                    debug!(%kdc_addr, %error, attempt, "Transient error while forwarding message to KDC server");
                    true
                }
                DirectSendError::Permanent(_) => false,
            },
        )
        .await
        .map_err(DirectSendError::into_http_error)
    }

    /// Performs a single direct KDC exchange (one connect+write+read for TCP, or one send+recv for UDP).
    async fn send_direct(&self, kdc_addr: &TargetAddr, message: &[u8]) -> Result<Vec<u8>, DirectSendError> {
        let protocol = kdc_addr.scheme();

        if protocol == "tcp" {
            let mut connection = TcpStream::connect(kdc_addr.as_addr()).await.map_err(|e| {
                error!(%kdc_addr, "failed to connect to KDC server");
                classify_io(e, unable_to_reach_kdc_server_err)
            })?;

            trace!("Connected! Forwarding KDC message...");

            connection.write_all(message).await.map_err(|e| {
                classify_io(
                    e,
                    HttpError::bad_gateway()
                        .with_msg("unable to send the message to the KDC server")
                        .err(),
                )
            })?;

            trace!("Reading KDC reply...");

            let reply = read_kdc_reply_message(&mut connection).await.map_err(|e| {
                classify_io(
                    e,
                    HttpError::bad_gateway()
                        .with_msg("unable to read KDC reply message")
                        .err(),
                )
            })?;

            Ok(reply)
        } else {
            let udp_payload = message.get(4..).ok_or_else(|| {
                DirectSendError::Permanent(
                    HttpError::bad_request().msg("KDC UDP message is too short to contain a length prefix"),
                )
            })?;

            let destination_addr = resolve_udp_destination(kdc_addr).await?;
            let bind_addr = udp_bind_addr_for(destination_addr);

            // We assume that ticket length is not bigger than 2048 bytes.
            let mut buf = [0; 2048];

            let udp_socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
                DirectSendError::Permanent(HttpError::internal().with_msg("unable to bind UDP socket").build(e))
            })?;

            let local_addr = udp_socket.local_addr().map_err(|e| {
                DirectSendError::Permanent(
                    HttpError::internal()
                        .with_msg("unable to get UDP socket address")
                        .build(e),
                )
            })?;

            trace!(%local_addr, %destination_addr, "Bound UDP listener, forwarding KDC message");

            // First 4 bytes contains message length. We don't need it for UDP.
            udp_socket
                .send_to(udp_payload, destination_addr)
                .await
                .map_err(|e| classify_io(e, unable_to_reach_kdc_server_err))?;

            trace!("Reading KDC reply...");

            let n = udp_socket.recv(&mut buf).await.map_err(|e| {
                classify_io(
                    e,
                    HttpError::bad_gateway()
                        .with_msg("unable to read reply from the KDC server")
                        .err(),
                )
            })?;

            let mut reply_buf = Vec::new();
            reply_buf.extend_from_slice(&u32::try_from(n).expect("n not too big").to_be_bytes());
            reply_buf.extend_from_slice(&buf[0..n]);

            Ok(reply_buf)
        }
    }

    /// Adapter for `sspi-rs` CredSSP: drain one `NetworkRequest` to its KDC and return the
    /// reply bytes as an `anyhow::Result`.
    ///
    /// Only handles real-network schemes (`tcp` / `udp`); credential-injection loopback
    /// requests are intercepted by `CredentialInjectionKdc` before reaching this point.
    ///
    /// TODO(sspi-rs#664): once sspi-rs ships a pluggable KDC dispatcher API, this adapter
    /// goes away entirely.
    pub async fn send_network_request(&self, request: &NetworkRequest) -> anyhow::Result<Vec<u8>> {
        match request.url.scheme() {
            "tcp" | "udp" => {
                let target_addr = TargetAddr::parse(request.url.as_str(), Some(88))?;

                self.send(&target_addr, &request.data)
                    .await
                    .map_err(|err| anyhow::anyhow!("failed to send KDC message: {err}"))
            }
            unsupported => anyhow::bail!("unsupported KDC request scheme: {unsupported}"),
        }
    }
}

/// A classified direct-KDC failure.
///
/// `Transient` failures (see [`is_transient_io_kind`]) are retried by
/// [`KdcConnector::send_direct_with_retry`]; `Permanent` failures are surfaced on the first
/// occurrence. Both variants carry the [`HttpError`] eventually returned to the caller.
enum DirectSendError {
    Transient(HttpError),
    Permanent(HttpError),
}

impl DirectSendError {
    fn into_http_error(self) -> HttpError {
        match self {
            DirectSendError::Transient(error) | DirectSendError::Permanent(error) => error,
        }
    }
}

/// Equal-jitter transform for a backoff delay.
///
/// Maps `duration` to `duration/2 + random(0, duration/2)`, i.e. a value in `[duration/2,
/// duration]`. Unlike full jitter (which can collapse to near-zero), this keeps half the delay
/// as a guaranteed floor so a loaded KDC still gets a minimum breather, while the random half
/// de-synchronizes concurrent retries. Follows the AWS "exponential backoff and jitter" guidance.
fn equal_jitter(duration: Duration) -> Duration {
    let half = duration / 2;
    half + half.mul_f64(rand::random::<f64>())
}

/// Whether an IO error kind is treated as a transient (retriable) KDC failure.
fn is_transient_io_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::TimedOut
    )
}

/// Classifies an IO error into a [`DirectSendError`], building the `HttpError` with `into_http_error`.
fn classify_io<F>(error: io::Error, into_http_error: F) -> DirectSendError
where
    F: FnOnce(io::Error) -> HttpError,
{
    let transient = is_transient_io_kind(error.kind());
    let http = into_http_error(error);

    if transient {
        DirectSendError::Transient(http)
    } else {
        DirectSendError::Permanent(http)
    }
}

async fn resolve_udp_destination(kdc_addr: &TargetAddr) -> Result<SocketAddr, DirectSendError> {
    let mut addrs = tokio::net::lookup_host(kdc_addr.as_addr())
        .await
        .map_err(|e| classify_io(e, unable_to_reach_kdc_server_err))?;

    addrs.next().ok_or_else(|| {
        DirectSendError::Permanent(unable_to_reach_kdc_server_err(io::Error::new(
            io::ErrorKind::NotFound,
            "KDC address resolved empty",
        )))
    })
}

fn udp_bind_addr_for(destination_addr: SocketAddr) -> SocketAddr {
    if destination_addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

/// Hard ceiling on the announced length of a TCP-framed KDC reply.
///
/// The KDC TCP transport prefixes its message with a 4-byte big-endian length.
/// A misbehaving (or malicious) peer can claim up to `u32::MAX` bytes, which
/// without a cap would have us pre-allocate ~4 GiB on a single reply. 64 KiB
/// is well above any realistic Kerberos reply size while keeping the worst
/// case bounded.
const MAX_KDC_REPLY_MESSAGE_LEN: u32 = 64 * 1024;

async fn read_kdc_reply_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u32().await?;

    if len > MAX_KDC_REPLY_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("KDC reply too large: announced {len} bytes, maximum is {MAX_KDC_REPLY_MESSAGE_LEN}"),
        ));
    }

    let total_len = len
        .checked_add(4)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "KDC reply length prefix overflowed"))?;

    let mut buf = vec![0; total_len];
    buf[0..4].copy_from_slice(&len.to_be_bytes());
    reader.read_exact(&mut buf[4..]).await?;
    Ok(buf)
}

#[track_caller]
fn unable_to_reach_kdc_server_err(error: io::Error) -> HttpError {
    use io::ErrorKind;

    let builder = match error.kind() {
        ErrorKind::TimedOut => HttpErrorBuilder::new(StatusCode::GATEWAY_TIMEOUT),
        ErrorKind::ConnectionRefused => HttpError::bad_gateway(),
        ErrorKind::ConnectionAborted => HttpError::bad_gateway(),
        ErrorKind::ConnectionReset => HttpError::bad_gateway(),
        ErrorKind::BrokenPipe => HttpError::bad_gateway(),
        ErrorKind::OutOfMemory => HttpError::internal(),
        _ => HttpError::bad_gateway(),
    };

    builder.with_msg("unable to reach KDC server").build(error)
}

#[cfg(test)]
mod tests {
    //! Behavioral contract of [`KdcConnector::send`].
    //!
    //! These tests pin down the routing decision matrix — see the table in the file-level
    //! docs. The success path (agent matched + connection succeeded) and the new UDP-via-
    //! agent guard cannot be reached without a live QUIC connection to a fake agent, so
    //! Only the two cases that don't require an [`AgentTunnelHandle`] are covered here:
    //! pin-without-tunnel (must error) and no-pin-no-tunnel (falls through to direct).
    //! The four cases that need a real handle (pin-with-missing-agent, no-match-falls-back,
    //! tunnel success, UDP-via-agent guard) are observable today only via integration tests
    //! that stand up an actual agent-tunnel listener — left as a follow-up.
    use std::sync::atomic::{AtomicUsize, Ordering};

    use uuid::Uuid;

    use super::*;

    fn udp_kdc_addr() -> TargetAddr {
        TargetAddr::parse("udp://127.0.0.1:88", Some(88)).expect("static target addr is valid")
    }

    /// No tunnel handle + explicit agent pin → must error.
    ///
    /// `jet_agent_id` declares a routing requirement; with no agent tunnel listener
    /// configured, falling back to a direct connection would silently bypass that
    /// requirement. `try_route` rejects this combination and we surface the error.
    #[tokio::test]
    async fn explicit_pin_without_tunnel_handle_errors() {
        let connector = KdcConnector::new(Uuid::new_v4(), Some(Uuid::new_v4()), None);
        // Routing rejects the pin before any dial, so this address is never actually connected to.
        let never_dialed = TargetAddr::parse("tcp://127.0.0.1:88", Some(88)).expect("static target addr is valid");
        let result = connector.send(&never_dialed, b"\x00\x00\x00\x00").await;
        let err = result.expect_err("explicit pin must reject when no tunnel handle is configured");
        assert!(
            format!("{err}").contains("requires agent tunnel routing"),
            "error message should explain the pin/tunnel mismatch, got: {err}",
        );
    }

    #[tokio::test]
    async fn udp_message_shorter_than_length_prefix_errors() {
        let connector = KdcConnector::new(Uuid::new_v4(), None, None);
        let result = connector.send(&udp_kdc_addr(), b"\x00\x01\x02").await;
        let err = result.expect_err("UDP message shorter than the TCP length prefix must be rejected");
        assert!(
            format!("{err}").contains("too short"),
            "error message should explain the malformed UDP payload, got: {err}",
        );
    }

    #[test]
    fn udp_bind_addr_matches_destination_family() {
        let v4_bind = udp_bind_addr_for(SocketAddr::from((Ipv4Addr::LOCALHOST, 88)));
        assert!(v4_bind.is_ipv4());
        assert_eq!(v4_bind.port(), 0);

        let v6_bind = udp_bind_addr_for(SocketAddr::from((Ipv6Addr::LOCALHOST, 88)));
        assert!(v6_bind.is_ipv6());
        assert_eq!(v6_bind.port(), 0);
    }

    #[test]
    fn equal_jitter_stays_within_bounds() {
        for millis in [0u64, 1, 250, 500, 1000, 2000] {
            let duration = Duration::from_millis(millis);
            let half = duration / 2;
            for _ in 0..16 {
                let jittered = equal_jitter(duration);
                assert!(
                    jittered >= half && jittered <= duration,
                    "equal_jitter({duration:?}) = {jittered:?} is outside [{half:?}, {duration:?}]",
                );
            }
        }
    }

    #[test]
    fn classify_io_splits_on_kind() {
        // The observed production failure: EOF on the reply read must be transient.
        let eof = classify_io(
            io::Error::new(io::ErrorKind::UnexpectedEof, "eof"),
            HttpError::bad_gateway()
                .with_msg("unable to read KDC reply message")
                .err(),
        );
        assert!(matches!(eof, DirectSendError::Transient(_)));

        let permanent = classify_io(
            io::Error::new(io::ErrorKind::InvalidData, "bad"),
            HttpError::bad_gateway()
                .with_msg("unable to read KDC reply message")
                .err(),
        );
        assert!(matches!(permanent, DirectSendError::Permanent(_)));
    }

    /// A configurable fake KDC: for each accepted connection it drains the request and then
    /// behaves according to the next entry of `behaviors` (falling back to `Drop` once the
    /// iterator is exhausted). Returns the bound address and a shared counter of how many
    /// connections were accepted, so tests can assert the exact number of attempts the retry
    /// loop made.
    enum FakeKdcBehavior {
        /// Accept then close without replying — surfaces as `UnexpectedEof` (transient).
        Drop,
        /// Reply with a valid 4-byte-framed KDC message (`payload`).
        Reply,
        /// Reply with an oversized length prefix — surfaces as `InvalidData` (permanent).
        ReplyTooLarge,
    }

    /// The framed reply bytes a `Reply` behavior sends and a successful `send` returns.
    const FAKE_KDC_REPLY: &[u8] = &[0, 0, 0, 4, b'd', b'a', b't', b'a'];

    async fn spawn_fake_kdc(behaviors: Vec<FakeKdcBehavior>) -> (SocketAddr, Arc<AtomicUsize>) {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake KDC");
        let addr = listener.local_addr().expect("fake KDC local addr");

        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_in_task = Arc::clone(&accepted);

        tokio::spawn(async move {
            let mut behaviors = behaviors.into_iter();

            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                accepted_in_task.fetch_add(1, Ordering::SeqCst);

                // Drain whatever the client wrote before acting on it.
                let mut discard = [0u8; 64];
                let _ = stream.read(&mut discard).await;

                match behaviors.next().unwrap_or(FakeKdcBehavior::Drop) {
                    FakeKdcBehavior::Drop => drop(stream),
                    FakeKdcBehavior::Reply => {
                        let _ = stream.write_all(FAKE_KDC_REPLY).await;
                        let _ = stream.flush().await;
                    }
                    FakeKdcBehavior::ReplyTooLarge => {
                        let _ = stream.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).await;
                        let _ = stream.flush().await;
                        drop(stream);
                    }
                }
            }
        });

        (addr, accepted)
    }

    async fn send_to_fake_kdc(addr: SocketAddr) -> (Result<Vec<u8>, HttpError>, KdcConnector) {
        let target = TargetAddr::parse(&format!("tcp://{addr}"), Some(88)).expect("valid target addr");
        let connector = KdcConnector::new(Uuid::new_v4(), None, None);
        let result = connector.send(&target, b"\x00\x00\x00\x04test").await;
        (result, connector)
    }

    /// A transient failure that later clears is retried and the eventual success is returned.
    ///
    /// `start_paused` keeps the backoff sleeps from costing real wall-clock time; the fake KDC
    /// drops the first two connections (transient `UnexpectedEof`) and replies on the third.
    #[tokio::test(start_paused = true)]
    async fn transient_failure_is_retried_then_recovers() {
        let (addr, accepted) = spawn_fake_kdc(vec![
            FakeKdcBehavior::Drop,
            FakeKdcBehavior::Drop,
            FakeKdcBehavior::Reply,
        ])
        .await;

        let (result, _connector) = send_to_fake_kdc(addr).await;

        let reply = match result {
            Ok(reply) => reply,
            Err(error) => panic!("the send should recover once the KDC stops dropping: {error}"),
        };
        assert_eq!(
            reply, FAKE_KDC_REPLY,
            "the successful reply bytes should be returned verbatim"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            3,
            "two transient drops plus one success is exactly three attempts",
        );
    }

    /// A KDC that always drops is retried exactly `KDC_MAX_RETRIES` times (for
    /// `KDC_MAX_RETRIES + 1` attempts total) before the error is surfaced.
    #[tokio::test(start_paused = true)]
    async fn transient_failure_is_retried_until_exhausted() {
        let (addr, accepted) = spawn_fake_kdc(Vec::new()).await;

        let (result, _connector) = send_to_fake_kdc(addr).await;

        let err = result.expect_err("a KDC that never replies must surface an error");
        assert!(
            format!("{err}").contains("unable to read KDC reply message"),
            "should surface the reply-read failure, got: {err}",
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            KDC_MAX_RETRIES + 1,
            "the send should be attempted KDC_MAX_RETRIES + 1 times",
        );
    }

    /// A permanent failure stops immediately, with no retry.
    ///
    /// The fake KDC replies with an oversized length prefix, which `read_kdc_reply_message`
    /// rejects as `InvalidData` — classified permanent, so the loop must not attempt again.
    #[tokio::test(start_paused = true)]
    async fn permanent_failure_is_not_retried() {
        let (addr, accepted) = spawn_fake_kdc(vec![FakeKdcBehavior::ReplyTooLarge]).await;

        let (result, _connector) = send_to_fake_kdc(addr).await;

        result.expect_err("an oversized reply length is a permanent failure");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a permanent failure must not be retried",
        );
    }
}
