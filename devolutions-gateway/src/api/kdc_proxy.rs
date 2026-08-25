use axum::Router;
use axum::extract::State;
use axum::routing::post;
use picky_krb::messages::KdcProxyMessage;

use crate::DgwState;
use crate::credential_injection::{
    CredentialInjectionKdcInterception, CredentialInjectionKdcRequest, kdc_proxy_message_realm,
};
use crate::extract::KdcToken;
use crate::http::HttpError;
use crate::kdc_connector::KdcConnector;
use crate::target_addr::TargetAddr;
use crate::token::{KdcDestination, KdcTokenClaims};

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new().route("/{token}", post(kdc_proxy)).with_state(state)
}

async fn kdc_proxy(
    State(DgwState {
        conf_handle,
        synthetic_kdc_registry,
        agent_tunnel_handle,
        ..
    }): State<DgwState>,
    KdcToken(KdcTokenClaims {
        destination,
        jti: token_jti,
    }): KdcToken,
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
            let kdc = synthetic_kdc_registry
                .get(jti)
                .ok_or_else(|| HttpError::bad_request().msg("no live synthetic KDC published for this session"))?;

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

            // session_id: the HTTP /jet/KdcProxy endpoint has no parent association token, so we
            // use the KDC token's own `jti` for log correlation (the RDP CredSSP/NLA caller
            // passes `claims.jet_aid` so KDC sub-traffic correlates with its parent RDP session).
            // explicit_agent_id: HTTP has no parent association, hence no `jet_agent_id` pin.
            let kdc_connector = KdcConnector::new(token_jti, None, agent_tunnel_handle);

            forward_to_real_kdc(
                kdc_proxy_message,
                envelope_realm,
                &krb_realm,
                &krb_kdc,
                conf.debug.override_kdc.as_ref(),
                conf.debug.disable_token_validation,
                &kdc_connector,
            )
            .await
        }
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
    kdc_connector: &KdcConnector,
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

    let kdc_reply_bytes = kdc_connector
        .send(kdc_addr, &kdc_proxy_message.kerb_message.0.0)
        .await?;

    let reply = KdcProxyMessage::from_raw_kerb_message(&kdc_reply_bytes)
        .map_err(HttpError::internal().with_msg("couldn't create KDC proxy reply").err())?;

    trace!(?reply, "Sending back KDC reply");

    reply.to_vec().map_err(HttpError::internal().err())
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
        // `bypass=true` is the `__debug__.disable_token_validation` downgrade.
        // This is the only branch where realm authorization is intentionally weakened, so pin it
        // explicitly to catch an inverted gate.
        assert!(enforce_realm_token_match("ad.example", "evil.example", true).is_ok());
    }
}
