//! In-memory Kerberos KDC used by proxy-based credential injection.
//!
//! This module owns the Kerberos side of credential injection end-to-end:
//! per-session fake-KDC material, the session store, KDC proxy handling, and the
//! in-process KDC requests emitted by the server-side CredSSP acceptor.
//! Callers should only decide whether credential injection applies; once it does, this
//! component owns the Kerberos-specific behavior.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore as _;
use devolutions_gateway_task::{ShutdownSignal, Task};
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::NetworkRequest;
use parking_lot::Mutex;
use picky_krb::messages::KdcProxyMessage;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::credential::{AppCredential, AppCredentialMapping, ArcCredentialEntry, CredentialStoreHandle};

// The reserved `.invalid` TLD (RFC 6761) lets sspi-rs CredSSP server emit "KDC requests" that
// never leave the process: `intercept_network_request` recognises this hostname and dispatches
// the message into the in-process `kdc` server below.
//
// TODO(sspi-rs#664): replace this URL-trampoline with a pluggable KDC dispatcher trait once
// sspi-rs ships the API — see https://github.com/Devolutions/sspi-rs/issues/664.
const IN_PROCESS_KDC_HOST: &str = "cred.invalid";

pub(crate) struct CredentialInjectionKdc {
    jti: Uuid,
    raw_token: String,
    credential_mapping: AppCredentialMapping,
    target_hostname: String,
    session: Arc<CredentialInjectionKdcSession>,
    // The KDC crate models users with plaintext passwords, so this object owns those secrets
    // for the lifetime of the credential-injection KDC. Keep Debug redacted.
    kdc_config: kdc::config::KerberosServer,
}

#[derive(Debug, Error)]
pub(crate) enum CredentialInjectionKdcResolveError {
    #[error("credential-injection state is not available for {jti}")]
    MissingCredential { jti: Uuid },
    #[error("credential-injection state for {jti} has expired")]
    ExpiredCredential { jti: Uuid },
    #[error("credential-injection state is not available for {jti}")]
    NonInjectionCredential { jti: Uuid },
    #[error("credential-injection KDC config could not be initialized for {jti}")]
    BuildKdcConfig {
        jti: Uuid,
        #[source]
        source: anyhow::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RealmMismatch {
    pub(crate) expected: String,
    pub(crate) actual: String,
}

impl fmt::Display for RealmMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected: {}, got: {}", self.expected, self.actual)
    }
}

impl std::error::Error for RealmMismatch {}

#[derive(Debug)]
pub(crate) enum CredentialInjectionKdcInterception {
    Intercepted(Vec<u8>),
    NotInjectionRequest,
    NotInjectionRealm(RealmMismatch),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialInjectionClientAcceptorProtocol {
    Kerberos,
    Ntlm,
}

pub(crate) struct CredentialInjectionKdcRequest {
    message: KdcProxyMessage,
}

impl CredentialInjectionKdcRequest {
    pub(crate) fn from_token(message: KdcProxyMessage) -> Self {
        Self { message }
    }

    fn in_process(message: KdcProxyMessage) -> Self {
        Self { message }
    }
}

impl fmt::Debug for CredentialInjectionKdc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInjectionKdc")
            .field("jti", &self.jti)
            .field("target_hostname", &self.target_hostname)
            .field("realm", &self.session.realm)
            .field("kdc_config", &"<redacted>")
            .finish()
    }
}

impl CredentialInjectionKdc {
    fn from_parts(
        jti: Uuid,
        credential_entry: ArcCredentialEntry,
        target_hostname: String,
        session: Arc<CredentialInjectionKdcSession>,
    ) -> anyhow::Result<Self> {
        let mapping = credential_entry
            .mapping
            .as_ref()
            .context("credential entry has no credential-injection mapping")?;
        anyhow::ensure!(
            jti == session.jti,
            "credential entry JTI does not match credential-injection KDC session JTI",
        );

        let kdc_config = build_kdc_config(&session, &mapping.proxy)?;

        Ok(Self {
            jti,
            raw_token: credential_entry.token.clone(),
            credential_mapping: mapping.clone(),
            target_hostname,
            session,
            kdc_config,
        })
    }

    pub(crate) fn jti(&self) -> Uuid {
        self.jti
    }

    pub(crate) fn raw_token(&self) -> &str {
        &self.raw_token
    }

    pub(crate) fn proxy_credential(&self) -> &AppCredential {
        &self.credential_mapping.proxy
    }

    pub(crate) fn target_credential(&self) -> &AppCredential {
        &self.credential_mapping.target
    }

    /// Selects the CredSSP acceptor backend Gateway should present to the RDP client.
    ///
    /// The acceptor side must mirror the target-side auth package.
    /// Domainless target credentials cannot acquire Kerberos tickets.
    /// Enabling the Kerberos acceptor for those sessions would make incoming NTLMSSP tokens fail in Kerberos parsing.
    pub(crate) fn client_acceptor_protocol(&self) -> anyhow::Result<CredentialInjectionClientAcceptorProtocol> {
        let target_username = sspi::Username::parse(app_credential_username(self.target_credential()))
            .context("invalid target credential username")?;

        if target_username.domain_name().is_some() {
            Ok(CredentialInjectionClientAcceptorProtocol::Kerberos)
        } else {
            Ok(CredentialInjectionClientAcceptorProtocol::Ntlm)
        }
    }

    pub(crate) fn server_kerberos_config(&self, client_addr: SocketAddr) -> anyhow::Result<sspi::KerberosServerConfig> {
        let user = sspi::CredentialsBuffers::AuthIdentity(sspi::AuthIdentityBuffers::from_utf8(
            &self.session.acceptor.principal_name,
            &self.session.realm,
            self.session.acceptor.password.expose_secret(),
        ));

        let kdc_url = self.in_process_kdc_url()?;

        // The SPN that the client puts on its AP-REQ ticket is the one for the target RDP
        // server (`TERMSRV/<target>`). Gateway-as-CredSSP-server is impersonating that target,
        // so ServerProperties must claim the same SPN or sspi-rs rejects the ticket.
        Ok(sspi::KerberosServerConfig {
            kerberos_config: sspi::KerberosConfig {
                kdc_url: Some(kdc_url),
                client_computer_name: Some(client_addr.to_string()),
            },
            server_properties: sspi::kerberos::ServerProperties::new(
                &["TERMSRV", &self.target_hostname],
                Some(user),
                Duration::from_secs(300),
                Some(self.session.acceptor.long_term_key.expose_secret().clone()),
            )?,
        })
    }

    pub(crate) fn intercept_network_request(
        &self,
        request: &NetworkRequest,
    ) -> anyhow::Result<CredentialInjectionKdcInterception> {
        if request.url.host_str() != Some(IN_PROCESS_KDC_HOST) {
            return Ok(CredentialInjectionKdcInterception::NotInjectionRequest);
        }

        let url_jti = request
            .url
            .path()
            .trim_start_matches('/')
            .parse::<Uuid>()
            .context("malformed in-process KDC URL")?;
        anyhow::ensure!(
            url_jti == self.jti,
            "in-process KDC URL JTI does not match current CredSSP session",
        );

        debug!(
            jti = %self.jti,
            scheme = %request.url.scheme(),
            "Credential-injection KDC intercepted in-process request"
        );

        let kdc_message = KdcProxyMessage::from_raw(&request.data).context("malformed in-process KDC proxy payload")?;
        self.handle_kdc_proxy_request(CredentialInjectionKdcRequest::in_process(kdc_message))
    }

    pub(crate) fn handle_kdc_proxy_request(
        &self,
        request: CredentialInjectionKdcRequest,
    ) -> anyhow::Result<CredentialInjectionKdcInterception> {
        let request_realm = self.resolve_message_realm(&request.message);
        debug!(
            jti = %self.jti,
            resolved_realm = %request_realm,
            "Credential-injection KDC realm resolved"
        );

        if let Some(mismatch) = realm_mismatch(&self.session.realm, &request_realm) {
            return Ok(CredentialInjectionKdcInterception::NotInjectionRealm(mismatch));
        }

        let reply = self.handle_message(request.message)?;
        Ok(CredentialInjectionKdcInterception::Intercepted(reply))
    }

    fn in_process_kdc_url(&self) -> anyhow::Result<Url> {
        Url::parse(&format!("http://{}/{}", IN_PROCESS_KDC_HOST, self.jti)).context("build in-process KDC URL")
    }

    fn resolve_message_realm(&self, kdc_proxy_message: &KdcProxyMessage) -> String {
        kdc_proxy_message_realm(kdc_proxy_message).unwrap_or_else(|| self.session.realm.clone())
    }

    fn handle_message(&self, kdc_proxy_message: KdcProxyMessage) -> anyhow::Result<Vec<u8>> {
        let reply = kdc::handle_kdc_proxy_message(kdc_proxy_message, &self.kdc_config, &self.target_hostname)
            .context("handle credential-injection KDC message")?;

        reply.to_vec().context("encode credential-injection KDC reply")
    }
}

fn app_credential_username(credential: &AppCredential) -> &str {
    match credential {
        AppCredential::UsernamePassword { username, password: _ } => username,
    }
}

pub(crate) fn kdc_proxy_message_realm(kdc_proxy_message: &KdcProxyMessage) -> Option<String> {
    kdc_proxy_message
        .target_domain
        .0
        .as_ref()
        .map(|realm| realm.0.to_string())
        .filter(|realm| !realm.is_empty())
}

fn realm_mismatch(expected: &str, actual: &str) -> Option<RealmMismatch> {
    if expected.eq_ignore_ascii_case(actual) {
        return None;
    }

    Some(RealmMismatch {
        expected: expected.to_owned(),
        actual: actual.to_owned(),
    })
}

/// Per-session Kerberos material for proxy-based credential injection.
///
/// The key material and the acceptor PA-ENC-TIMESTAMP password are wrapped in [`SecretBox`] /
/// [`SecretString`] so they cannot be accidentally written to logs through structured tracing.
/// Access requires an explicit `expose_secret()` call, which is greppable and reviewable.
struct CredentialInjectionKdcSession {
    jti: Uuid,
    realm: String,
    kdc: CredentialInjectionKdcState,
    acceptor: CredentialInjectionAcceptorState,
}

struct CredentialInjectionKdcState {
    krbtgt_key: SecretBox<Vec<u8>>,
}

struct CredentialInjectionAcceptorState {
    principal_name: String,
    password: SecretString,
    long_term_key: SecretBox<Vec<u8>>,
}

impl fmt::Debug for CredentialInjectionKdcSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInjectionKdcSession")
            .field("jti", &self.jti)
            .field("realm", &self.realm)
            .field("kdc", &self.kdc)
            .field("acceptor", &self.acceptor)
            .finish()
    }
}

impl fmt::Debug for CredentialInjectionKdcState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInjectionKdcState")
            .field("krbtgt_key", &"<32 bytes redacted>")
            .finish()
    }
}

impl fmt::Debug for CredentialInjectionAcceptorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInjectionAcceptorState")
            .field("principal_name", &self.principal_name)
            .field("password", &"<redacted>")
            .field("long_term_key", &"<32 bytes redacted>")
            .finish()
    }
}

/// Derive per-session Kerberos material from the proxy username and the association token's JTI.
///
/// The proxy username's optional `@realm` suffix selects the realm DVLS supplied; otherwise
/// fall back to a per-session synthetic realm derived from the JTI. The two sides agree
/// because DVLS derives the synthetic value the same way.
fn derive_credential_injection_kdc_session(proxy_username: &str, jti: Uuid) -> CredentialInjectionKdcSession {
    let realm = proxy_username
        .split_once('@')
        .map(|(_, realm)| realm)
        .filter(|realm| !realm.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| synthetic_realm(jti));

    CredentialInjectionKdcSession {
        jti,
        realm,
        kdc: CredentialInjectionKdcState {
            krbtgt_key: SecretBox::new(Box::new(random_32_bytes())),
        },
        acceptor: CredentialInjectionAcceptorState {
            principal_name: "jet".to_owned(),
            password: SecretString::from(hex::encode(random_32_bytes())),
            long_term_key: SecretBox::new(Box::new(random_32_bytes())),
        },
    }
}

fn build_kdc_config(
    session: &CredentialInjectionKdcSession,
    proxy_credential: &AppCredential,
) -> anyhow::Result<kdc::config::KerberosServer> {
    let realm = &session.realm;
    let (proxy_user_name, proxy_password) = proxy_credential.decrypt_password()?;
    let proxy_user_name = principal_for_realm(&proxy_user_name, realm);
    let acceptor_principal_name = principal_for_realm(&session.acceptor.principal_name, realm);

    let acceptor_password = session.acceptor.password.expose_secret().to_owned();
    Ok(kdc::config::KerberosServer {
        realm: realm.to_owned(),
        users: vec![
            kdc::config::DomainUser {
                username: proxy_user_name.clone(),
                password: proxy_password.expose_secret().to_owned(),
                salt: kerberos_salt(realm, &proxy_user_name),
            },
            kdc::config::DomainUser {
                username: acceptor_principal_name.clone(),
                password: acceptor_password.clone(),
                salt: kerberos_salt(realm, &acceptor_principal_name),
            },
        ],
        max_time_skew: 300,
        krbtgt_key: session.kdc.krbtgt_key.expose_secret().clone(),
        ticket_decryption_key: Some(session.acceptor.long_term_key.expose_secret().clone()),
        service_user: Some(kdc::config::DomainUser {
            username: acceptor_principal_name.clone(),
            password: acceptor_password,
            salt: kerberos_salt(realm, &acceptor_principal_name),
        }),
    })
}

fn principal_for_realm(user_name: &str, realm: &str) -> String {
    if user_name.contains('@') {
        user_name.to_owned()
    } else {
        format!("{user_name}@{realm}")
    }
}

fn kerberos_salt(realm: &str, principal: &str) -> String {
    let local_name = principal.split('@').next().unwrap_or(principal);
    format!("{}{local_name}", realm.to_ascii_uppercase())
}

fn synthetic_realm(jti: Uuid) -> String {
    format!("CRED-{}.INVALID", jti.simple()).to_ascii_uppercase()
}

fn random_32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// One-stop service for credential storage and credential-injection KDC state.
///
/// Wraps the protocol-neutral [`CredentialStoreHandle`] and adds a Kerberos session cache keyed by
/// association-token JTI. The credential store remains the single source of truth for entry
/// lifetime; the session cache piggybacks on it (Arc-cloned credentials at lookup time, with stale
/// sessions evicted on insert-replacement and by a periodic sweep).
///
/// All credential reads/writes — provision-credentials, RDP mode detection, KDC dispatch — go
/// through this service, so callers see one handle instead of coordinating a store and a registry.
#[derive(Debug, Clone)]
pub struct CredentialService {
    hostname: String,
    credentials: CredentialStoreHandle,
    sessions: Arc<Mutex<HashMap<Uuid, Arc<CredentialInjectionKdcSession>>>>,
}

impl CredentialService {
    pub fn new(hostname: String) -> Self {
        Self {
            hostname,
            credentials: CredentialStoreHandle::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Insert (or replace) a credential entry keyed by the token's JTI.
    ///
    /// Any previously-cached Kerberos session for the same JTI is dropped: it was derived from
    /// the prior provisioning and is no longer valid for the new entry. We invalidate even when
    /// `CredentialStoreHandle::insert` reports no replacement, because the prior entry may have
    /// already been evicted by `credential::CleanupTask` while its session cache entry was still
    /// awaiting the next `sweep_orphans` tick — without an unconditional drop here, a fresh
    /// provisioning under the same JTI would reuse stale key material.
    pub fn insert(
        &self,
        token: String,
        mapping: Option<crate::credential::CleartextAppCredentialMapping>,
        time_to_live: time::Duration,
    ) -> Result<Option<ArcCredentialEntry>, crate::credential::InsertError> {
        // Snapshot the JTI from the new token so we can invalidate the matching session entry
        // regardless of whether the credential store reports a replacement. `CredentialStore::insert`
        // re-extracts internally; both calls go through the same code path, so an invalid token
        // here will surface as the same `InvalidToken` error downstream.
        let jti = crate::token::extract_jti(&token)
            .context("failed to extract token ID")
            .map_err(crate::credential::InsertError::InvalidToken)?;
        let previous = self.credentials.insert(token, mapping, time_to_live)?;
        self.sessions.lock().remove(&jti);
        Ok(previous)
    }

    /// Look up a credential entry by its association-token JTI.
    pub fn get(&self, jti: Uuid) -> Option<ArcCredentialEntry> {
        self.credentials.get(jti)
    }

    /// Borrow the inner [`CredentialStoreHandle`] for plumbing that genuinely needs the
    /// protocol-neutral primitive (e.g. wiring the background expiry task).
    pub fn credential_store(&self) -> &CredentialStoreHandle {
        &self.credentials
    }

    /// Resolve the credential-injection KDC bound to the given association-token JTI.
    ///
    /// Returns the per-call KDC view; the underlying Kerberos session (krbtgt key, acceptor
    /// long-term key, acceptor password) is cached so the in-process KDC and the CredSSP acceptor
    /// see identical key material for the lifetime of the provisioned credentials.
    pub(crate) fn kdc_for(&self, jti: Uuid) -> Result<CredentialInjectionKdc, CredentialInjectionKdcResolveError> {
        let credential_entry = self.credentials.get(jti).ok_or_else(|| {
            warn!(%jti, "KDC token references missing credential-injection state");
            CredentialInjectionKdcResolveError::MissingCredential { jti }
        })?;

        // `CredentialStoreHandle::get` does not enforce expiry — entries are evicted asynchronously
        // by the credential cleanup task. Treat a stale entry as already gone so we never build a
        // KDC against expired credentials.
        if time::OffsetDateTime::now_utc() >= credential_entry.expires_at {
            warn!(%jti, "KDC token references expired credential-injection state");
            self.sessions.lock().remove(&jti);
            return Err(CredentialInjectionKdcResolveError::ExpiredCredential { jti });
        }

        let mapping = credential_entry.mapping.as_ref().ok_or_else(|| {
            warn!(%jti, "KDC token references non-injection credential state");
            CredentialInjectionKdcResolveError::NonInjectionCredential { jti }
        })?;

        let proxy_username = app_credential_username(&mapping.proxy).to_owned();
        // Atomic get-or-insert: holds the lock long enough to guarantee a single Arc<Session>
        // wins for this JTI even under concurrent `kdc_for` calls. The derivation is fast (a few
        // hundred bytes of OsRng) so doing it under the lock is acceptable.
        let session = {
            let mut sessions = self.sessions.lock();
            let session = sessions
                .entry(jti)
                .or_insert_with(|| Arc::new(derive_credential_injection_kdc_session(&proxy_username, jti)));
            Arc::clone(session)
        };

        CredentialInjectionKdc::from_parts(jti, credential_entry, self.hostname.clone(), session)
            .map_err(|source| CredentialInjectionKdcResolveError::BuildKdcConfig { jti, source })
    }

    fn sweep_orphans(&self) {
        let stale_jtis: Vec<Uuid> = {
            let sessions = self.sessions.lock();
            sessions
                .keys()
                .copied()
                .filter(|jti| self.credentials.get(*jti).is_none())
                .collect()
        };

        if stale_jtis.is_empty() {
            return;
        }

        let mut sessions = self.sessions.lock();
        for jti in stale_jtis {
            sessions.remove(&jti);
        }
    }
}

pub struct CleanupTask {
    pub service: CredentialService,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "credential injection kdc cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.service, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(service: CredentialService, mut shutdown_signal: ShutdownSignal) {
    use tokio::time::{Duration, sleep};

    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15 minutes

    debug!("Task started");

    loop {
        tokio::select! {
            _ = sleep(TASK_INTERVAL) => {}
            _ = shutdown_signal.wait() => {
                break;
            }
        }

        service.sweep_orphans();
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ironrdp_connector::sspi::network_client::NetworkProtocol;
    use secrecy::SecretString;

    use super::*;
    use crate::credential::{CleartextAppCredential, CleartextAppCredentialMapping};

    fn cleartext_mapping_with_target_username(target_username: &str) -> CleartextAppCredentialMapping {
        CleartextAppCredentialMapping {
            proxy: CleartextAppCredential::UsernamePassword {
                username: "proxy@example.invalid".to_owned(),
                password: SecretString::from("pwd"),
            },
            target: CleartextAppCredential::UsernamePassword {
                username: target_username.to_owned(),
                password: SecretString::from("pwd"),
            },
        }
    }

    fn unsigned_jws(payload: serde_json::Value) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"RS256"}"#);
        let payload = engine.encode(serde_json::to_vec(&payload).expect("payload serializes"));
        let signature = engine.encode(b"signature");
        format!("{header}.{payload}.{signature}")
    }

    fn association_token(jti: Uuid) -> String {
        unsigned_jws(serde_json::json!({
            "jti": jti,
            "dst_hst": "target.example:3389"
        }))
    }

    fn dummy_entry_with_target_username(jti: Uuid, target_username: &str) -> ArcCredentialEntry {
        let store = CredentialStoreHandle::new();
        store
            .insert(
                association_token(jti),
                Some(cleartext_mapping_with_target_username(target_username)),
                time::Duration::minutes(5),
            )
            .expect("credential entry inserts");

        store.get(jti).expect("credential entry is indexed by JTI")
    }

    fn dummy_entry(jti: Uuid) -> ArcCredentialEntry {
        dummy_entry_with_target_username(jti, "target")
    }

    fn dummy_kdc(jti: Uuid) -> CredentialInjectionKdc {
        let entry = dummy_entry(jti);
        let session = Arc::new(derive_credential_injection_kdc_session("proxy@example.invalid", jti));
        CredentialInjectionKdc::from_parts(jti, entry, "target.example".to_owned(), session)
            .expect("valid credential-injection KDC")
    }

    fn dummy_kdc_with_target_username(jti: Uuid, target_username: &str) -> CredentialInjectionKdc {
        let entry = dummy_entry_with_target_username(jti, target_username);
        let session = Arc::new(derive_credential_injection_kdc_session("proxy@example.invalid", jti));
        CredentialInjectionKdc::from_parts(jti, entry, "target.example".to_owned(), session)
            .expect("valid credential-injection KDC")
    }

    fn network_request(url: &str) -> NetworkRequest {
        NetworkRequest {
            protocol: NetworkProtocol::Http,
            url: Url::parse(url).expect("test URL parses"),
            data: Vec::new(),
        }
    }

    #[test]
    fn proxy_user_at_realm_is_used_as_realm() {
        let session = derive_credential_injection_kdc_session("proxy@example.invalid", Uuid::new_v4());
        assert_eq!(session.realm, "example.invalid");
    }

    #[test]
    fn bare_proxy_username_yields_synthetic_realm() {
        let jti = Uuid::new_v4();
        let session = derive_credential_injection_kdc_session("just-a-uuid", jti);
        assert_eq!(session.realm, synthetic_realm(jti));
        assert!(!session.realm.is_empty());
    }

    #[test]
    fn service_kdc_for_rejects_expired_credential_entry() {
        let service = CredentialService::new("dgateway.localhost.com".to_owned());
        let jti = Uuid::new_v4();

        // Negative TTL: entry is born already expired. `CredentialStoreHandle::get` does not
        // filter on expiry, so the service's own check is what guarantees we never build a KDC
        // over stale credentials.
        service
            .insert(
                association_token(jti),
                Some(cleartext_mapping_with_target_username("target")),
                time::Duration::seconds(-1),
            )
            .expect("credential entry inserts");

        assert!(
            matches!(
                service.kdc_for(jti),
                Err(CredentialInjectionKdcResolveError::ExpiredCredential { .. })
            ),
            "expired credentials must not yield a KDC"
        );
    }

    #[test]
    fn service_kdc_for_returns_same_session_under_concurrent_calls() {
        let service = CredentialService::new("dgateway.localhost.com".to_owned());
        let jti = Uuid::new_v4();

        service
            .insert(
                association_token(jti),
                Some(cleartext_mapping_with_target_username("target")),
                time::Duration::minutes(5),
            )
            .expect("credential entry inserts");

        let first = service.kdc_for(jti).expect("first call resolves");
        let second = service.kdc_for(jti).expect("second call resolves");

        // The Kerberos session is the piece that must be stable across calls; the per-call KDC
        // view rebuilds the rest. Compare via the long-term acceptor key as a session-identity
        // probe.
        let first_key = first.session.acceptor.long_term_key.expose_secret().clone();
        let second_key = second.session.acceptor.long_term_key.expose_secret().clone();
        assert_eq!(
            first_key, second_key,
            "concurrent kdc_for must share one cached session per JTI"
        );
    }

    #[test]
    fn service_insert_drops_stale_session_even_without_credential_replacement() {
        let service = CredentialService::new("dgateway.localhost.com".to_owned());
        let jti = Uuid::new_v4();

        // Simulate the race called out by Codex: a previous provisioning's session is still
        // cached, but the credential entry has already been evicted (e.g. by
        // `credential::cleanup_task`) and `sweep_orphans` has not run yet. A fresh provisioning
        // under the same JTI must drop the stale session regardless of whether
        // `CredentialStoreHandle::insert` reports a replacement, otherwise the next `kdc_for`
        // would reuse the old key material.
        let stale_session = Arc::new(derive_credential_injection_kdc_session("proxy@example.invalid", jti));
        service.sessions.lock().insert(jti, Arc::clone(&stale_session));

        let previous = service
            .insert(
                association_token(jti),
                Some(cleartext_mapping_with_target_username("target")),
                time::Duration::minutes(5),
            )
            .expect("credential entry inserts");
        assert!(previous.is_none(), "test precondition: no credential replacement");

        assert!(
            !service.sessions.lock().contains_key(&jti),
            "insert must drop stale session even when no credential replacement occurred"
        );
    }

    #[test]
    fn service_insert_replacement_drops_cached_kerberos_material() {
        let service = CredentialService::new("dgateway.localhost.com".to_owned());
        let jti = Uuid::new_v4();

        service
            .insert(
                association_token(jti),
                Some(cleartext_mapping_with_target_username("target")),
                time::Duration::minutes(5),
            )
            .expect("credential entry inserts");

        let first = service.kdc_for(jti).expect("first call resolves");
        let first_key = first.session.acceptor.long_term_key.expose_secret().clone();

        // Re-insert under the same JTI: the cached session for the previous entry must be evicted
        // automatically, otherwise the new KDC would carry stale key material that the freshly
        // provisioned credentials no longer match.
        service
            .insert(
                association_token(jti),
                Some(cleartext_mapping_with_target_username("target")),
                time::Duration::minutes(5),
            )
            .expect("credential entry re-inserts");

        let second = service.kdc_for(jti).expect("second call resolves with fresh session");
        let second_key = second.session.acceptor.long_term_key.expose_secret().clone();

        assert_ne!(
            first_key, second_key,
            "insert-replacement must force a fresh session derivation"
        );
    }

    #[test]
    fn service_sweep_orphans_drops_sessions_with_no_credential_entry() {
        let service = CredentialService::new("dgateway.localhost.com".to_owned());
        let jti = Uuid::new_v4();

        service
            .insert(
                association_token(jti),
                Some(cleartext_mapping_with_target_username("target")),
                time::Duration::minutes(5),
            )
            .expect("credential entry inserts");

        service.kdc_for(jti).expect("kdc_for populates session cache");
        assert!(service.sessions.lock().contains_key(&jti), "session cached");

        // Simulate credential store eviction: build a parallel service whose credential store is
        // empty but whose session cache is shared with the original. A more faithful test would
        // drive `credential::cleanup_task` to expire the entry, but it sleeps for 15 minutes
        // between ticks. Swapping the inner store is the deterministic equivalent.
        let orphaned_service = CredentialService {
            hostname: "dgateway.localhost.com".to_owned(),
            credentials: CredentialStoreHandle::new(),
            sessions: Arc::clone(&service.sessions),
        };

        orphaned_service.sweep_orphans();
        assert!(
            !orphaned_service.sessions.lock().contains_key(&jti),
            "sweep must drop sessions whose JTI is no longer in credential_store"
        );
    }

    #[test]
    fn client_acceptor_protocol_is_ntlm_for_domainless_target_credential() {
        let kdc = dummy_kdc_with_target_username(Uuid::new_v4(), "Administrator");

        assert_eq!(
            kdc.client_acceptor_protocol().expect("protocol selected"),
            CredentialInjectionClientAcceptorProtocol::Ntlm
        );
    }

    #[test]
    fn client_acceptor_protocol_is_kerberos_for_upn_target_credential() {
        let kdc = dummy_kdc_with_target_username(Uuid::new_v4(), "administrator@example.invalid");

        assert_eq!(
            kdc.client_acceptor_protocol().expect("protocol selected"),
            CredentialInjectionClientAcceptorProtocol::Kerberos
        );
    }

    #[test]
    fn client_acceptor_protocol_is_kerberos_for_downlevel_target_credential() {
        let kdc = dummy_kdc_with_target_username(Uuid::new_v4(), "EXAMPLE\\Administrator");

        assert_eq!(
            kdc.client_acceptor_protocol().expect("protocol selected"),
            CredentialInjectionClientAcceptorProtocol::Kerberos
        );
    }

    #[test]
    fn from_parts_rejects_mismatched_entry_and_session_jti() {
        let entry_jti = Uuid::new_v4();
        let session_jti = Uuid::new_v4();
        assert_ne!(entry_jti, session_jti);

        let entry = dummy_entry(entry_jti);
        let session = Arc::new(derive_credential_injection_kdc_session(
            "proxy@example.invalid",
            session_jti,
        ));

        let err = CredentialInjectionKdc::from_parts(entry_jti, entry, "target.example".to_owned(), session)
            .expect_err("mismatched entry/session JTI must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("credential entry JTI does not match credential-injection KDC session JTI"),
            "actual: {msg}"
        );
    }

    #[test]
    fn service_kdc_for_rejects_unknown_jti() {
        let service = CredentialService::new("dgateway.localhost.com".to_owned());

        assert!(
            matches!(
                service.kdc_for(Uuid::new_v4()),
                Err(CredentialInjectionKdcResolveError::MissingCredential { .. })
            ),
            "KDC tokens with jet_cred_id must not fall back to real-KDC forwarding"
        );
    }

    #[test]
    fn service_kdc_for_rejects_non_injection_entry() {
        let service = CredentialService::new("dgateway.localhost.com".to_owned());
        let jti = Uuid::new_v4();

        service
            .insert(association_token(jti), None, time::Duration::minutes(5))
            .expect("provision-token entry inserts");

        assert!(
            matches!(
                service.kdc_for(jti),
                Err(CredentialInjectionKdcResolveError::NonInjectionCredential { .. })
            ),
            "KDC tokens with jet_cred_id must require provision-credentials state"
        );
    }

    #[test]
    fn intercept_ignores_non_loopback_host() {
        let jti = Uuid::new_v4();
        let kdc = dummy_kdc(jti);

        let request = network_request("http://kdc.real.example/path");
        let result = kdc
            .intercept_network_request(&request)
            .expect("non-loopback request dispatches");

        assert!(matches!(
            result,
            CredentialInjectionKdcInterception::NotInjectionRequest
        ));
    }

    #[test]
    fn intercept_rejects_malformed_url_path() {
        let jti = Uuid::new_v4();
        let kdc = dummy_kdc(jti);

        let request = network_request("http://cred.invalid/not-a-uuid");
        let err = kdc
            .intercept_network_request(&request)
            .expect_err("non-UUID path must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("malformed in-process KDC URL"), "actual: {msg}");
    }

    #[test]
    fn intercept_rejects_mismatched_jti() {
        let entry_jti = Uuid::new_v4();
        let other_jti = Uuid::new_v4();
        assert_ne!(entry_jti, other_jti);

        let kdc = dummy_kdc(entry_jti);

        let request = network_request(&format!("http://cred.invalid/{}", other_jti));
        let err = kdc
            .intercept_network_request(&request)
            .expect_err("JTI mismatch must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("does not match current CredSSP session"), "actual: {msg}");
    }

    #[test]
    fn intercept_accepts_matching_url_path_before_payload_decode() {
        let jti = Uuid::new_v4();
        let kdc = dummy_kdc(jti);

        let request = network_request(&format!("http://cred.invalid/{jti}"));
        let err = kdc
            .intercept_network_request(&request)
            .expect_err("empty KDC payload must fail after URL/JTI validation");
        let msg = format!("{err:#}");
        assert!(msg.contains("malformed in-process KDC proxy payload"), "actual: {msg}");
    }

    #[test]
    fn realm_mismatch_is_reported_as_not_injection_realm() {
        let mismatch =
            realm_mismatch("cred-session.invalid", "evil.example").expect("different realms produce a mismatch");
        assert_eq!(mismatch.expected, "cred-session.invalid");
        assert_eq!(mismatch.actual, "evil.example");
    }

    #[test]
    fn missing_kdc_proxy_envelope_realm_falls_back_to_session_realm() {
        let jti = Uuid::new_v4();
        let kdc = dummy_kdc(jti);
        let message = KdcProxyMessage::from_raw_kerb_message(&[]).expect("KDC proxy wrapper builds");

        assert_eq!(kdc.resolve_message_realm(&message), "example.invalid");
    }
}
