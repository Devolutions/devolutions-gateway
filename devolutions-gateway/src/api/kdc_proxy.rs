use std::io;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use picky_krb::messages::KdcProxyMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::DgwState;
use crate::credential_injection_kdc::{
    CredentialInjectionKdc, CredentialInjectionKdcInterception, CredentialInjectionKdcRequest,
    CredentialInjectionKdcResolveError, kdc_proxy_message_realm,
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
        credential_store,
        kerberos_session_store,
        ..
    }): State<DgwState>,
    KdcToken(KdcTokenClaims { destination }): KdcToken,
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

            let resolution = CredentialInjectionKdc::resolve(Some(jti), &credential_store, &kerberos_session_store)
                .map_err(credential_injection_resolve_error)?;
            let kdc = resolution
                .ok_or_else(|| HttpError::internal().msg("credential-injection KDC resolution returned no state"))?;

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
async fn forward_to_real_kdc(
    kdc_proxy_message: KdcProxyMessage,
    envelope_realm: Option<String>,
    token_realm: &str,
    token_kdc_addr: &TargetAddr,
    override_kdc: Option<&TargetAddr>,
    bypass_realm_check: bool,
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

    let kdc_reply_bytes = send_krb_message(kdc_addr, &kdc_proxy_message.kerb_message.0.0).await?;

    let reply = KdcProxyMessage::from_raw_kerb_message(&kdc_reply_bytes)
        .map_err(HttpError::internal().with_msg("couldn't create KDC proxy reply").err())?;

    trace!(?reply, "Sending back KDC reply");

    reply.to_vec().map_err(HttpError::internal().err())
}

fn enforce_credential_injection_enabled(jet_cred_id: uuid::Uuid, enable_unstable: bool) -> Result<(), HttpError> {
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

async fn read_kdc_reply_message(connection: &mut TcpStream) -> io::Result<Vec<u8>> {
    let len = connection.read_u32().await?;
    let mut buf = vec![0; (len + 4).try_into().expect("u32-to-usize")];
    buf[0..4].copy_from_slice(&(len.to_be_bytes()));
    connection.read_exact(&mut buf[4..]).await?;
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
pub async fn send_krb_message(kdc_addr: &TargetAddr, message: &[u8]) -> Result<Vec<u8>, HttpError> {
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
        assert!(enforce_credential_injection_enabled(uuid::Uuid::new_v4(), true).is_ok());
    }

    #[test]
    fn credential_injection_gate_rejects_jet_cred_id_when_disabled() {
        assert!(enforce_credential_injection_enabled(uuid::Uuid::new_v4(), false).is_err());
    }
}
