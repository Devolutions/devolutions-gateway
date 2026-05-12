use std::io;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use picky_krb::messages::KdcProxyMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

use crate::DgwState;
use crate::credential_injection_kdc::{
    CredentialInjectionKdcInterception, CredentialInjectionKdcRequest, CredentialInjectionKdcResolveError,
    kdc_proxy_message_realm,
};
use crate::extract::KdcToken;
use crate::http::{HttpError, HttpErrorBuilder};
use crate::target_addr::TargetAddr;
use crate::token::{KdcDestination, KdcTokenClaims};

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new().route("/{token}", post(kdc_proxy)).with_state(state)
}

async fn kdc_proxy(
    State(DgwState {
        conf_handle,
        credentials,
        agent_tunnel_handle,
        ..
    }): State<DgwState>,
    KdcToken {
        claims: KdcTokenClaims { destination },
        jti: token_jti,
    }: KdcToken,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, HttpError> {
    let conf = conf_handle.get_conf();

    let kdc_proxy_message = KdcProxyMessage::from_raw(&body).map_err(HttpError::bad_request().err())?;

    trace!(?kdc_proxy_message, "Received KDC message");
    debug!(
        ?kdc_proxy_message.target_domain,
        ?kdc_proxy_message.dclocator_hint,
        "KDC message",
    );

    match destination {
        KdcDestination::Inject { jti } => {
            enforce_credential_injection_enabled(jti, conf.debug.enable_unstable)?;

            let kdc = credentials.kdc_for(jti).map_err(credential_injection_resolve_error)?;

            debug!(
                jti = %kdc.jti(),
                "Proxy-based credential injection with Kerberos. Processing KdcProxy message internally"
            );

            match kdc
                .handle_kdc_proxy_request(CredentialInjectionKdcRequest::from_token(kdc_proxy_message))
                .map_err(HttpError::internal().err())?
            {
                CredentialInjectionKdcInterception::Intercepted(reply) => Ok(reply),
                CredentialInjectionKdcInterception::NotInjectionRealm(mismatch) => {
                    Err(HttpError::bad_request()
                        .with_msg("requested domain is not allowed")
                        .err()(mismatch))
                }
                CredentialInjectionKdcInterception::NotInjectionRequest => {
                    Err(HttpError::internal().msg("credential-injection KDC did not handle the KDC proxy request"))
                }
            }
        }
        KdcDestination::Real { krb_realm, krb_kdc } => {
            let envelope_realm = kdc_proxy_message_realm(&kdc_proxy_message);
            forward_to_real_kdc(
                kdc_proxy_message,
                envelope_realm,
                &krb_realm,
                &krb_kdc,
                conf.debug.override_kdc.as_ref(),
                conf.debug.disable_token_validation,
                agent_tunnel_handle.as_deref(),
                token_jti,
            )
            .await
        }
    }
}

fn credential_injection_resolve_error(error: CredentialInjectionKdcResolveError) -> HttpError {
    match error {
        CredentialInjectionKdcResolveError::BuildKdcConfig { .. } => HttpError::internal()
            .with_msg("credential-injection KDC could not be initialized")
            .build(error),
        _ => HttpError::bad_request()
            .with_msg("credential-injection state is not available")
            .build(error),
    }
}

// Forwards the request to the real KDC indicated by the token (or by the debug override) and
// returns the response wrapped as a `KdcProxyMessage`.
//
// The forward path requires the envelope realm to be set: there is no fallback since this is
// not a credential-injection session. After resolving, validates the realm against the
// token's `krb_realm` claim before forwarding anything.
#[expect(clippy::too_many_arguments)]
async fn forward_to_real_kdc(
    kdc_proxy_message: KdcProxyMessage,
    envelope_realm: Option<String>,
    token_realm: &str,
    token_kdc_addr: &TargetAddr,
    override_kdc: Option<&TargetAddr>,
    bypass_realm_check: bool,
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
    // The HTTP /jet/KdcProxy endpoint has no parent association token, so we use the KDC
    // token's own `jti` for log/agent-side correlation. It is persistent for the lifetime of
    // the KDC token (which can be reused) rather than per-request, but it is the most stable
    // identifier we have here. The RDP CredSSP/NLA caller (rdp_proxy.rs::send_network_request)
    // passes `claims.jet_aid` instead so KDC sub-traffic correlates with its RDP session.
    session_id: Uuid,
) -> Result<Vec<u8>, HttpError> {
    let realm = envelope_realm.ok_or_else(|| HttpError::bad_request().msg("realm is missing from KDC request"))?;
    debug!(resolved_realm = %realm, "Forward-to-real-KDC realm resolved");
    enforce_realm_token_match(token_realm, &realm, bypass_realm_check)?;

    let kdc_addr = match override_kdc {
        Some(override_addr) => {
            warn!(%override_addr, "**DEBUG OPTION** KDC address has been overridden");
            override_addr
        }
        None => token_kdc_addr,
    };

    // No parent association token here, so no `jet_agent_id` to enforce. The HTTP
    // /jet/KdcProxy endpoint stands on its own — let the routing pipeline pick any
    // matching agent (or fall back to direct connect).
    let explicit_agent_id = None;

    let kdc_reply_bytes = send_krb_message(
        kdc_addr,
        &kdc_proxy_message.kerb_message.0.0,
        agent_tunnel_handle,
        session_id,
        explicit_agent_id,
    )
    .await?;

    let reply = KdcProxyMessage::from_raw_kerb_message(&kdc_reply_bytes)
        .map_err(HttpError::internal().with_msg("couldn't create KDC proxy reply").err())?;

    trace!(?reply, "Sending back KDC reply");

    reply.to_vec().map_err(HttpError::internal().err())
}

fn enforce_credential_injection_enabled(jet_cred_id: Uuid, enable_unstable: bool) -> Result<(), HttpError> {
    if enable_unstable {
        return Ok(());
    }

    warn!(
        %jet_cred_id,
        "Credential-injection KDC token rejected because unstable Kerberos injection is disabled"
    );
    Err(HttpError::bad_request().msg("credential-injection KDC proxy is not enabled"))
}

/// Refuses to forward a KDC request whose realm disagrees with the realm the token was issued for.
///
/// `bypass=true` (only when `__debug__.disable_token_validation` is on) downgrades the mismatch
/// to a warning. Production never opts into this.
fn enforce_realm_token_match(token_realm: &str, request_realm: &str, bypass: bool) -> Result<(), HttpError> {
    if token_realm.eq_ignore_ascii_case(request_realm) {
        return Ok(());
    }

    if bypass {
        warn!(
            %token_realm,
            %request_realm,
            "**DEBUG OPTION** Allowed a KDC request towards a KDC whose Kerberos realm differs from what's inside the KDC token"
        );
        return Ok(());
    }

    Err(HttpError::bad_request()
        .with_msg("requested domain is not allowed")
        .err()(format!("expected: {token_realm}, got: {request_realm}")))
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
        // FIXME: once stabilized use new IO error variants
        // - https://github.com/rust-lang/rust/pull/106375
        // - https://github.com/rust-lang/rust/issues/86442
        // ErrorKind::NetworkDown => HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE),
        // ErrorKind::NetworkUnreachable => HttpError::bad_gateway(),
        // ErrorKind::HostUnreachable => HttpError::bad_gateway(),
        // TODO: When the above is applied, we can return an internal error in the fallback branch.
        _ => HttpError::bad_gateway(),
    };

    builder.with_msg("unable to reach KDC server").build(error)
}

/// Sends the Kerberos message to the specified KDC address.
///
/// Uses the same routing pipeline as connection forwarding:
/// if an agent claims the KDC's domain/subnet, traffic goes through the tunnel.
/// Falls back to direct connect when no agent matches.
///
/// `session_id` is forwarded to the agent as the QUIC stream's session ID for
/// log correlation. Callers that have a parent association (RDP CredSSP) should
/// pass the parent's `jet_aid`; the HTTP `/jet/KdcProxy` endpoint passes the KDC
/// token's own `jti` (no parent association exists for that path).
///
/// `explicit_agent_id` honors the same routing contract as every other proxy path:
/// when the parent association token pins the session to a specific agent via
/// `jet_agent_id`, that pin is enforced here too (route via that agent or fail —
/// do **not** silently fall back to another agent or to direct connect).
/// Callers with no parent association (HTTP `/jet/KdcProxy`) pass `None`.
pub async fn send_krb_message(
    kdc_addr: &TargetAddr,
    message: &[u8],
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
    session_id: Uuid,
    explicit_agent_id: Option<Uuid>,
) -> Result<Vec<u8>, HttpError> {
    // Route through agent tunnel using the SAME pipeline as connection forwarding,
    // but only for `tcp` KDC targets. The agent tunnel currently has a single
    // `ConnectRequest::tcp` shape, so a `udp://` KDC routed this way would be
    // delivered to the agent as a TCP target — wrong protocol semantics that can
    // silently break UDP Kerberos deployments. Fall through to the direct path
    // (which honors the scheme) until an explicit UDP tunnel hop exists.
    //
    // `as_addr()` returns `host:port` (with IPv6 brackets), which is what the agent
    // tunnel target parser expects — unlike `to_string()` which includes the scheme.
    let kdc_target = kdc_addr.as_addr();
    let tunnel_handle = if kdc_addr.scheme().eq_ignore_ascii_case("tcp") {
        agent_tunnel_handle
    } else {
        None
    };

    let route_target = match kdc_addr.host_ip() {
        Some(ip) => agent_tunnel::routing::RouteTarget::ip(ip),
        None => agent_tunnel::routing::RouteTarget::hostname(kdc_addr.host()),
    };

    if let Some((mut stream, _agent)) =
        agent_tunnel::routing::try_route(tunnel_handle, explicit_agent_id, &route_target, session_id, kdc_target)
            .await
            .map_err(|e| HttpError::bad_gateway().build(format!("KDC routing through agent tunnel failed: {e:#}")))?
    {
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
        // We assume that ticket length is not bigger than 2048 bytes.
        let mut buf = [0; 2048];

        let udp_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(HttpError::internal().with_msg("unable to bind UDP socket").err())?;

        let port = udp_socket
            .local_addr()
            .map_err(HttpError::internal().with_msg("unable to get UDP socket address").err())?
            .port();

        trace!("Binded UDP listener to 127.0.0.1:{port}, forwarding KDC message...");

        // First 4 bytes contains message length. We don't need it for UDP.
        #[allow(clippy::redundant_closure)] // We get a better caller location for the error by using a closure.
        udp_socket
            .send_to(&message[4..], kdc_addr.as_addr())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforce_realm_match_accepts_case_insensitive_match() {
        assert!(enforce_realm_token_match("ad.example", "AD.EXAMPLE", false).is_ok());
    }

    #[test]
    fn enforce_realm_mismatch_rejects_without_bypass() {
        assert!(enforce_realm_token_match("ad.example", "evil.example", false).is_err());
    }

    #[test]
    fn enforce_realm_mismatch_passes_under_bypass() {
        // `bypass=true` is the `__debug__.disable_token_validation` downgrade. CBenoit asked
        // for explicit coverage of this branch because it is the only place the realm
        // authorization is intentionally weakened, and slipping the gate (e.g. by inverting the
        // condition) would only surface in production.
        assert!(enforce_realm_token_match("ad.example", "evil.example", true).is_ok());
    }

    #[test]
    fn credential_injection_gate_allows_jet_cred_id_when_enabled() {
        assert!(enforce_credential_injection_enabled(Uuid::new_v4(), true).is_ok());
    }

    #[test]
    fn credential_injection_gate_rejects_jet_cred_id_when_disabled() {
        assert!(enforce_credential_injection_enabled(Uuid::new_v4(), false).is_err());
    }
}
