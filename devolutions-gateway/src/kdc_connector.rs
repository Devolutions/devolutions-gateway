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

use axum::http::StatusCode;
use ironrdp_connector::sspi::generator::NetworkRequest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

use crate::http::{HttpError, HttpErrorBuilder};
use crate::target_addr::TargetAddr;
use crate::upstream::route_target_from_target_addr;

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

        if let Some((mut stream, _agent)) = route_result {
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
        }

        // Direct fallback. `try_route` returning `Ok(None)` means: no matching agent and
        // no explicit pin — the caller is allowed to direct-connect with the scheme it
        // chose.
        let protocol = kdc_addr.scheme();

        debug!("Connecting to KDC server located at {kdc_addr} using protocol {protocol}...");

        if protocol == "tcp" {
            #[allow(clippy::redundant_closure)] // We get a better caller location for the error by using a closure.
            let mut connection = TcpStream::connect(kdc_addr.as_addr()).await.map_err(|e| {
                error!(%kdc_addr, "failed to connect to KDC server");
                unable_to_reach_kdc_server_err(e)
            })?;

            trace!("Connected! Forwarding KDC message...");

            connection.write_all(message).await.map_err(
                HttpError::bad_gateway()
                    .with_msg("unable to send the message to the KDC server")
                    .err(),
            )?;

            trace!("Reading KDC reply...");

            Ok(read_kdc_reply_message(&mut connection).await.map_err(
                HttpError::bad_gateway()
                    .with_msg("unable to read KDC reply message")
                    .err(),
            )?)
        } else {
            let udp_payload = message.get(4..).ok_or_else(|| {
                HttpError::bad_request().msg("KDC UDP message is too short to contain a length prefix")
            })?;

            let destination_addr = resolve_udp_destination(kdc_addr).await?;
            let bind_addr = udp_bind_addr_for(destination_addr);

            // We assume that ticket length is not bigger than 2048 bytes.
            let mut buf = [0; 2048];

            let udp_socket = UdpSocket::bind(bind_addr)
                .await
                .map_err(HttpError::internal().with_msg("unable to bind UDP socket").err())?;

            let local_addr = udp_socket
                .local_addr()
                .map_err(HttpError::internal().with_msg("unable to get UDP socket address").err())?;

            trace!(%local_addr, %destination_addr, "Bound UDP listener, forwarding KDC message");

            // First 4 bytes contains message length. We don't need it for UDP.
            #[allow(clippy::redundant_closure)] // We get a better caller location for the error by using a closure.
            udp_socket
                .send_to(udp_payload, destination_addr)
                .await
                .map_err(|e| unable_to_reach_kdc_server_err(e))?;

            trace!("Reading KDC reply...");

            let n = udp_socket.recv(&mut buf).await.map_err(
                HttpError::bad_gateway()
                    .with_msg("unable to read reply from the KDC server")
                    .err(),
            )?;

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

async fn resolve_udp_destination(kdc_addr: &TargetAddr) -> Result<SocketAddr, HttpError> {
    let mut addrs = tokio::net::lookup_host(kdc_addr.as_addr())
        .await
        .map_err(unable_to_reach_kdc_server_err)?;

    addrs.next().ok_or_else(|| {
        unable_to_reach_kdc_server_err(io::Error::new(io::ErrorKind::NotFound, "KDC address resolved empty"))
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
    use uuid::Uuid;

    use super::*;

    fn unreachable_kdc_addr() -> TargetAddr {
        // Loopback + a port that is not listening produces ConnectionRefused on every supported
        // platform, which `unable_to_reach_kdc_server_err` maps to a bad-gateway `HttpError`.
        // Avoids a real network round-trip while still exercising the direct-connect branch.
        TargetAddr::parse("tcp://127.0.0.1:1", Some(88)).expect("static target addr is valid")
    }

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
        let result = connector.send(&unreachable_kdc_addr(), b"\x00\x00\x00\x00").await;
        let err = result.expect_err("explicit pin must reject when no tunnel handle is configured");
        assert!(
            format!("{err}").contains("requires agent tunnel routing"),
            "error message should explain the pin/tunnel mismatch, got: {err}",
        );
    }

    /// No tunnel handle, no pin → falls through to direct connect.
    ///
    /// We point at an unreachable loopback port; the only thing the test asserts is that
    /// we *got* to the direct-connect path (any error from there shape-matches the
    /// "unable to reach KDC server" wrapping).
    #[tokio::test]
    async fn no_pin_no_tunnel_handle_attempts_direct() {
        let connector = KdcConnector::new(Uuid::new_v4(), None, None);
        let result = connector.send(&unreachable_kdc_addr(), b"\x00\x00\x00\x00").await;
        let err = result.expect_err("loopback:1 should be unreachable");
        assert!(
            format!("{err}").contains("unable to reach KDC server"),
            "should have reached the direct-connect branch, got: {err}",
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
}
