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

use crate::credential::{
    AppCredential, AppCredentialMapping, ArcCredentialEntry, CredentialStoreHandle, InjectionState,
};

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

pub(crate) type CredentialInjectionKdcResolution = Option<Box<CredentialInjectionKdc>>;

#[derive(Debug, Error)]
pub(crate) enum CredentialInjectionKdcResolveError {
    #[error("credential-injection state is not available for {jti}")]
    MissingCredential { jti: Uuid },
    #[error("credential-injection state is not available for {jti}")]
    NonInjectionCredential { jti: Uuid },
    #[error("credential-injection Kerberos state is not available for {jti}")]
    MissingKerberosSession { jti: Uuid },
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
    pub(crate) fn from_parts(
        credential_entry: ArcCredentialEntry,
        session: Arc<CredentialInjectionKdcSession>,
    ) -> anyhow::Result<Self> {
        let InjectionState {
            mapping,
            target_hostname,
        } = credential_entry
            .injection
            .as_ref()
            .context("credential entry has no credential-injection state")?;
        anyhow::ensure!(
            credential_entry.jti == session.jti,
            "credential entry JTI does not match credential-injection KDC session JTI",
        );

        let kdc_config = build_kdc_config(&session, &mapping.proxy)?;

        Ok(Self {
            jti: credential_entry.jti,
            raw_token: credential_entry.token.clone(),
            credential_mapping: mapping.clone(),
            target_hostname: target_hostname.clone(),
            session,
            kdc_config,
        })
    }

    pub(crate) fn resolve(
        jet_cred_id: Option<Uuid>,
        credential_store: &CredentialStoreHandle,
        session_store: &CredentialInjectionKdcSessionStoreHandle,
    ) -> Result<CredentialInjectionKdcResolution, CredentialInjectionKdcResolveError> {
        let Some(jti) = jet_cred_id else {
            return Ok(None);
        };

        let credential_entry = credential_store.get(jti).ok_or_else(|| {
            warn!(%jti, "KDC token references missing credential-injection state");
            CredentialInjectionKdcResolveError::MissingCredential { jti }
        })?;

        if credential_entry.injection.is_none() {
            warn!(%jti, "KDC token references non-injection credential state");
            return Err(CredentialInjectionKdcResolveError::NonInjectionCredential { jti });
        }

        let session = session_store.get(jti).ok_or_else(|| {
            warn!(%jti, "KDC token references missing credential-injection Kerberos state");
            CredentialInjectionKdcResolveError::MissingKerberosSession { jti }
        })?;

        let kdc = Self::from_parts(credential_entry, session)
            .map_err(|source| CredentialInjectionKdcResolveError::BuildKdcConfig { jti, source })?;

        Ok(Some(Box::new(kdc)))
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
        let target_username =
            sspi::Username::parse(self.target_credential().username()).context("invalid target credential username")?;

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
pub(crate) struct CredentialInjectionKdcSession {
    jti: Uuid,
    pub(crate) realm: String,
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
pub(crate) fn derive_credential_injection_kdc_session(
    proxy_username: &str,
    jti: Uuid,
) -> CredentialInjectionKdcSession {
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

pub(crate) fn synthetic_realm(jti: Uuid) -> String {
    format!("CRED-{}.INVALID", jti.simple()).to_ascii_uppercase()
}

fn random_32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Parallel store of [`CredentialInjectionKdcSession`] entries keyed by association-token JTI.
///
/// Pairs 1:1 with [`crate::credential::CredentialStoreHandle`]: a credential entry provisioned
/// with `provision-credentials` has a matching entry here under the same JTI. The two stores
/// share neither lock nor map so that the credential store stays Kerberos-unaware.
#[derive(Debug, Clone, Default)]
pub struct CredentialInjectionKdcSessionStoreHandle(Arc<Mutex<HashMap<Uuid, Entry>>>);

#[derive(Debug)]
struct Entry {
    session: Arc<CredentialInjectionKdcSession>,
    expires_at: time::OffsetDateTime,
}

impl CredentialInjectionKdcSessionStoreHandle {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    pub(crate) fn insert(&self, session: CredentialInjectionKdcSession, time_to_live: time::Duration) {
        let jti = session.jti;
        let entry = Entry {
            session: Arc::new(session),
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
        };
        self.0.lock().insert(jti, entry);
    }

    pub(crate) fn get(&self, jti: Uuid) -> Option<Arc<CredentialInjectionKdcSession>> {
        // Lookup-time TTL enforcement mirrors `CredentialStoreHandle::get`: the cleanup task is
        // best-effort, and we don't want to hand out Kerberos material whose paired credential
        // entry has already expired.
        self.0
            .lock()
            .get(&jti)
            .filter(|entry| time::OffsetDateTime::now_utc() < entry.expires_at)
            .map(|entry| Arc::clone(&entry.session))
    }
}

pub struct CleanupTask {
    pub handle: CredentialInjectionKdcSessionStoreHandle,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "credential injection kdc cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.handle, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(handle: CredentialInjectionKdcSessionStoreHandle, mut shutdown_signal: ShutdownSignal) {
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

        let now = time::OffsetDateTime::now_utc();
        handle.0.lock().retain(|_, entry| now < entry.expires_at);
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests {
    use ironrdp_connector::sspi::network_client::NetworkProtocol;
    use secrecy::SecretString;

    use super::*;
    use crate::credential::{
        AppCredentialMapping, CleartextAppCredential, CleartextAppCredentialMapping, CredentialEntry,
    };

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

    fn dummy_entry_with_target_username(jti: Uuid, target_username: &str) -> ArcCredentialEntry {
        let mapping: AppCredentialMapping = cleartext_mapping_with_target_username(target_username)
            .encrypt()
            .expect("encrypt mapping");
        Arc::new(CredentialEntry {
            jti,
            token: "raw-token".to_owned(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
            injection: Some(InjectionState {
                mapping,
                target_hostname: "target.example".to_owned(),
            }),
        })
    }

    fn dummy_entry(jti: Uuid) -> ArcCredentialEntry {
        dummy_entry_with_target_username(jti, "target")
    }

    fn dummy_kdc(jti: Uuid) -> CredentialInjectionKdc {
        let entry = dummy_entry(jti);
        let session = Arc::new(derive_credential_injection_kdc_session("proxy@example.invalid", jti));
        CredentialInjectionKdc::from_parts(entry, session).expect("valid credential-injection KDC")
    }

    fn dummy_kdc_with_target_username(jti: Uuid, target_username: &str) -> CredentialInjectionKdc {
        let entry = dummy_entry_with_target_username(jti, target_username);
        let session = Arc::new(derive_credential_injection_kdc_session("proxy@example.invalid", jti));
        CredentialInjectionKdc::from_parts(entry, session).expect("valid credential-injection KDC")
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
    fn store_lookup_filters_expired_entries() {
        let store = CredentialInjectionKdcSessionStoreHandle::new();
        let jti = Uuid::new_v4();
        let session = derive_credential_injection_kdc_session("proxy@example.invalid", jti);

        // Negative TTL: entry is born already expired.
        store.insert(session, time::Duration::seconds(-1));

        assert!(store.get(jti).is_none(), "expired entry must not be returned");
    }

    #[test]
    fn store_returns_fresh_entry() {
        let store = CredentialInjectionKdcSessionStoreHandle::new();
        let jti = Uuid::new_v4();
        let session = derive_credential_injection_kdc_session("proxy@example.invalid", jti);

        store.insert(session, time::Duration::minutes(5));

        assert_eq!(store.get(jti).expect("fresh entry returned").realm, "example.invalid");
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
    fn resolve_with_no_jet_cred_id_forwards_to_real_kdc() {
        let credential_store = CredentialStoreHandle::new();
        let session_store = CredentialInjectionKdcSessionStoreHandle::new();

        let dispatch = CredentialInjectionKdc::resolve(None, &credential_store, &session_store)
            .expect("plain KDC token should dispatch");

        assert!(dispatch.is_none());
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

        let err = CredentialInjectionKdc::from_parts(entry, session)
            .expect_err("mismatched entry/session JTI must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("credential entry JTI does not match credential-injection KDC session JTI"),
            "actual: {msg}"
        );
    }

    #[test]
    fn resolve_with_missing_jet_cred_id_fails_closed() {
        let credential_store = CredentialStoreHandle::new();
        let session_store = CredentialInjectionKdcSessionStoreHandle::new();

        assert!(
            CredentialInjectionKdc::resolve(Some(Uuid::new_v4()), &credential_store, &session_store).is_err(),
            "KDC tokens with jet_cred_id must not fall back to real-KDC forwarding"
        );
    }

    #[test]
    fn resolve_with_non_injection_entry_fails_closed() {
        let credential_store = CredentialStoreHandle::new();
        let session_store = CredentialInjectionKdcSessionStoreHandle::new();
        let jti = Uuid::new_v4();

        credential_store
            .insert(jti, "raw-token".to_owned(), None, time::Duration::minutes(5))
            .expect("provision-token entry inserts");

        assert!(
            CredentialInjectionKdc::resolve(Some(jti), &credential_store, &session_store).is_err(),
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
}
