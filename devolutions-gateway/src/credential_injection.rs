//! Credential-injection runtime: groceries → dish → synthetic KDC pass window.
//!
//! - Provisioned data lives in [`crate::provisioning::ProvisioningStore`] (supermarket).
//! - [`CredentialInjection`] is built by the RDP path from those groceries (chef).
//! - [`SyntheticKdcRegistry`] is the pass window: RDP publishes, `/jet/KdcProxy` looks up only.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore as _;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::NetworkRequest;
use parking_lot::Mutex;
use picky_krb::messages::KdcProxyMessage;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::credential::{AppCredential, AppCredentialMapping};
use crate::provisioning::ProvisioningEntry;
#[cfg(test)]
use crate::provisioning::ProvisioningStore;
use crate::target_addr::TargetAddr;

// The reserved `.invalid` TLD (RFC 6761) lets sspi-rs CredSSP server emit "KDC requests" that
// never leave the process: `intercept_network_request` recognises this hostname and dispatches
// the message into the in-process `kdc` server below.
//
// TODO(sspi-rs#664): replace this URL-trampoline with a pluggable KDC dispatcher trait once
// sspi-rs ships the API — see https://github.com/Devolutions/sspi-rs/issues/664.
const IN_PROCESS_KDC_HOST: &str = "cred.invalid";

/// In-process synthetic KDC for one Kerberos credential-injection session.
///
/// Published to [`SyntheticKdcRegistry`] for `/jet/KdcProxy`. Holds only what the fake KDC and
/// CredSSP server-leg intercept need — not proxy/target passwords or routing bags.
pub(crate) struct CredentialInjectionKdc {
    jti: Uuid,
    target_hostname: String,
    realm: String,
    acceptor_principal_name: String,
    acceptor_password: SecretString,
    acceptor_long_term_key: SecretBox<Vec<u8>>,
    // Built once from acceptor + proxy material; kdc crate API takes this by ref on each message.
    kdc_config: kdc::config::KerberosServer,
}

#[derive(Debug, Error)]
pub(crate) enum CredentialInjectionKdcResolveError {
    #[error("credential-injection state is not available for {jti}")]
    NonInjectionCredential { jti: Uuid },
    #[error("association token for {jti} is not valid for credential injection")]
    InvalidAssociationToken {
        jti: Uuid,
        #[source]
        source: anyhow::Error,
    },
    #[error("credential-injection KDC config could not be initialized for {jti}")]
    BuildKdcConfig {
        jti: Uuid,
        #[source]
        source: anyhow::Error,
    },
    #[error("Kerberos credential injection requires target connection option krb_kdc for {jti}")]
    MissingKrbKdc { jti: Uuid },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("expected: {expected}, got: {actual}")]
pub(crate) struct RealmMismatch {
    pub(crate) expected: String,
    pub(crate) actual: String,
}

#[derive(Debug)]
pub(crate) enum CredentialInjectionKdcInterception {
    Intercepted(Vec<u8>),
    NotInjectionRequest,
    NotInjectionRealm(RealmMismatch),
}

/// Session-scoped credential injection. Holding [`CredentialInjection::Kerberos`] proves the
/// synthetic KDC is registered in [`SyntheticKdcRegistry`] for this connection.
///
/// Build path: [`CredentialInjection::from_provisioned`] → [`PreparedCredentialInjection`] →
/// [`PreparedCredentialInjection::register_if_kerberos`].
pub(crate) enum CredentialInjection {
    Kerberos(
        KerberosCredentialInjection,
        #[expect(dead_code, reason = "RAII lease: Drop unpublishes the synthetic KDC")] SyntheticKdcRegistration,
    ),
    Ntlm(NtlmCredentialInjection),
}

/// Kerberos dish: credentials + real KDC address + shared synthetic KDC.
pub(crate) struct KerberosCredentialInjection {
    credential_mapping: AppCredentialMapping,
    target_kdc: TargetAddr,
    synthetic: Arc<CredentialInjectionKdc>,
}

/// Chef output: protocol chosen; synthetic KDC built if needed, not yet published.
#[derive(Debug)]
pub(crate) enum PreparedCredentialInjection {
    Kerberos(KerberosCredentialInjection),
    Ntlm(NtlmCredentialInjection),
}

impl PreparedCredentialInjection {
    /// Publish the synthetic KDC when this is Kerberos; NTLM is a no-op pass-through.
    pub(crate) fn register_if_kerberos(self, registry: &SyntheticKdcRegistry) -> CredentialInjection {
        match self {
            Self::Kerberos(injection) => {
                let registration = registry.register(Arc::clone(&injection.synthetic));
                debug!(
                    jti = %injection.synthetic.jti(),
                    "registered synthetic KDC for credential-injection session"
                );
                CredentialInjection::Kerberos(injection, registration)
            }
            Self::Ntlm(injection) => CredentialInjection::Ntlm(injection),
        }
    }
}

impl KerberosCredentialInjection {
    pub(crate) fn synthetic_kdc(&self) -> &CredentialInjectionKdc {
        &self.synthetic
    }

    pub(crate) fn target_kdc(&self) -> &TargetAddr {
        &self.target_kdc
    }
}

impl fmt::Debug for KerberosCredentialInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KerberosCredentialInjection")
            .field("target_kdc", &self.target_kdc)
            .field("synthetic", &self.synthetic)
            .finish_non_exhaustive()
    }
}

/// NTLM injection carries credentials only — no synthetic KDC is published.
#[derive(Debug)]
pub(crate) struct NtlmCredentialInjection {
    jti: Uuid,
    credential_mapping: AppCredentialMapping,
}

impl NtlmCredentialInjection {
    pub(crate) fn jti(&self) -> Uuid {
        self.jti
    }

    pub(crate) fn proxy_credential(&self) -> &AppCredential {
        &self.credential_mapping.proxy
    }

    pub(crate) fn target_credential(&self) -> &AppCredential {
        &self.credential_mapping.target
    }
}

impl CredentialInjection {
    pub(crate) fn jti(&self) -> Uuid {
        match self {
            Self::Kerberos(k, _) => k.synthetic.jti(),
            Self::Ntlm(ntlm) => ntlm.jti(),
        }
    }

    pub(crate) fn proxy_credential(&self) -> &AppCredential {
        match self {
            Self::Kerberos(k, _) => &k.credential_mapping.proxy,
            Self::Ntlm(ntlm) => ntlm.proxy_credential(),
        }
    }

    pub(crate) fn target_credential(&self) -> &AppCredential {
        match self {
            Self::Kerberos(k, _) => &k.credential_mapping.target,
            Self::Ntlm(ntlm) => ntlm.target_credential(),
        }
    }

    pub(crate) fn as_kerberos(&self) -> Option<&KerberosCredentialInjection> {
        match self {
            Self::Kerberos(k, _) => Some(k),
            Self::Ntlm(_) => None,
        }
    }

    pub(crate) fn uses_kerberos(&self) -> bool {
        matches!(self, Self::Kerberos(_, _))
    }

    /// RDP chef: owned groceries → prepared dish. Does not touch the registry.
    pub(crate) fn from_provisioned(
        jti: Uuid,
        credential_entry: ProvisioningEntry,
        kerberos_enabled: bool,
    ) -> Result<PreparedCredentialInjection, CredentialInjectionKdcResolveError> {
        let ProvisioningEntry {
            token,
            mapping,
            connection_options,
        } = credential_entry;

        let mapping = mapping.ok_or_else(|| {
            warn!(%jti, "credential-injection state has no mapping");
            CredentialInjectionKdcResolveError::NonInjectionCredential { jti }
        })?;

        let target_hostname = crate::token::extract_credential_injection_target_hostname(&token).map_err(|source| {
            warn!(
                %jti,
                error = format!("{source:#}"),
                "invalid credential-injection association token"
            );
            CredentialInjectionKdcResolveError::InvalidAssociationToken { jti, source }
        })?;

        let target_username = match sspi::Username::parse(app_credential_username(&mapping.target)) {
            Ok(u) => u,
            Err(error) => {
                warn!(%jti, error = format!("{error:#}"), "invalid target credential username");
                return Err(CredentialInjectionKdcResolveError::BuildKdcConfig {
                    jti,
                    source: anyhow::anyhow!("invalid target credential username: {error}"),
                });
            }
        };

        let wants_kerberos = kerberos_enabled && target_username.domain_name().is_some();
        if !wants_kerberos {
            return Ok(PreparedCredentialInjection::Ntlm(NtlmCredentialInjection {
                jti,
                credential_mapping: mapping,
            }));
        }

        let target_kdc = connection_options
            .as_ref()
            .and_then(|o| o.krb_kdc())
            .cloned()
            .ok_or_else(|| {
                warn!(%jti, "Kerberos credential injection requires krb_kdc");
                CredentialInjectionKdcResolveError::MissingKrbKdc { jti }
            })?;

        let proxy_username = app_credential_username(&mapping.proxy).to_owned();
        let synthetic = CredentialInjectionKdc::new(jti, target_hostname, &proxy_username, &mapping.proxy)
            .map_err(|source| CredentialInjectionKdcResolveError::BuildKdcConfig { jti, source })?;

        Ok(PreparedCredentialInjection::Kerberos(KerberosCredentialInjection {
            credential_mapping: mapping,
            target_kdc,
            synthetic: Arc::new(synthetic),
        }))
    }
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
            .field("realm", &self.realm)
            .field("kdc_config", &"<redacted>")
            .finish()
    }
}

impl CredentialInjectionKdc {
    fn new(
        jti: Uuid,
        target_hostname: String,
        proxy_username: &str,
        proxy_credential: &AppCredential,
    ) -> anyhow::Result<Self> {
        let realm = realm_from_proxy_username(proxy_username, jti);
        let acceptor_principal_name = "jet".to_owned();
        let acceptor_password = SecretString::from(hex::encode(random_32_bytes()));
        let acceptor_long_term_key = SecretBox::new(Box::new(random_32_bytes()));
        let krbtgt_key = random_32_bytes();

        let kdc_config = build_kdc_config(
            &realm,
            proxy_credential,
            &acceptor_principal_name,
            acceptor_password.expose_secret(),
            &krbtgt_key,
            acceptor_long_term_key.expose_secret(),
        )?;

        Ok(Self {
            jti,
            target_hostname,
            realm,
            acceptor_principal_name,
            acceptor_password,
            acceptor_long_term_key,
            kdc_config,
        })
    }

    pub(crate) fn jti(&self) -> Uuid {
        self.jti
    }

    pub(crate) fn server_kerberos_config(&self, client_addr: SocketAddr) -> anyhow::Result<sspi::KerberosServerConfig> {
        let user = sspi::CredentialsBuffers::AuthIdentity(sspi::AuthIdentityBuffers::from_utf8(
            &self.acceptor_principal_name,
            &self.realm,
            self.acceptor_password.expose_secret(),
        ));

        let kdc_url = self.in_process_kdc_url()?;

        // The SPN that the client puts on its AP-REQ ticket is the one for the target RDP
        // server (`TERMSRV/<target>`). Gateway-as-CredSSP-server is impersonating that target,
        // so ServerProperties must claim the same SPN or sspi-rs rejects the ticket.
        Ok(sspi::KerberosServerConfig {
            kerberos_config: sspi::KerberosConfig {
                kdc_url: Some(kdc_url),
                client_computer_name: client_addr.to_string(),
            },
            server_properties: sspi::kerberos::ServerProperties::new(
                &["TERMSRV", &self.target_hostname],
                Some(user),
                Duration::from_secs(300),
                Some(sspi::Secret::new(self.acceptor_long_term_key.expose_secret().clone())),
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

        if let Some(mismatch) = realm_mismatch(&self.realm, &request_realm) {
            return Ok(CredentialInjectionKdcInterception::NotInjectionRealm(mismatch));
        }

        let reply = self.handle_message(request.message)?;
        Ok(CredentialInjectionKdcInterception::Intercepted(reply))
    }

    fn in_process_kdc_url(&self) -> anyhow::Result<Url> {
        Url::parse(&format!("http://{}/{}", IN_PROCESS_KDC_HOST, self.jti)).context("build in-process KDC URL")
    }

    fn resolve_message_realm(&self, kdc_proxy_message: &KdcProxyMessage) -> String {
        kdc_proxy_message_realm(kdc_proxy_message).unwrap_or_else(|| self.realm.clone())
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
        None
    } else {
        Some(RealmMismatch {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

fn realm_from_proxy_username(proxy_username: &str, jti: Uuid) -> String {
    proxy_username
        .split_once('@')
        .map(|(_, realm)| realm)
        .filter(|realm| !realm.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| synthetic_realm(jti))
}

fn build_kdc_config(
    realm: &str,
    proxy_credential: &AppCredential,
    acceptor_principal_name: &str,
    acceptor_password: &str,
    krbtgt_key: &[u8],
    acceptor_long_term_key: &[u8],
) -> anyhow::Result<kdc::config::KerberosServer> {
    let (proxy_user_name, proxy_password) = proxy_credential.decrypt_password()?;
    let proxy_user_name = principal_for_realm(&proxy_user_name, realm);
    let acceptor_principal_name = principal_for_realm(acceptor_principal_name, realm);

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
                password: acceptor_password.to_owned(),
                salt: kerberos_salt(realm, &acceptor_principal_name),
            },
        ],
        max_time_skew: 300,
        krbtgt_key: krbtgt_key.to_vec(),
        ticket_decryption_key: Some(acceptor_long_term_key.to_vec()),
        service_user: Some(kdc::config::DomainUser {
            username: acceptor_principal_name.clone(),
            password: acceptor_password.to_owned(),
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

/// Live synthetic KDCs published by active RDP credential-injection sessions.
///
/// Pass window between handlers:
/// - RDP path publishes when it starts a Kerberos injection
/// - `/jet/KdcProxy` only looks up; it never builds a KDC from provisioned groceries
///
/// Entries are connection-scoped via [`SyntheticKdcRegistration`]. Reconnects `register` again
/// (replace + bump generation); a late drop of an older registration is a no-op.
#[derive(Debug, Clone)]
pub struct SyntheticKdcRegistry {
    inner: Arc<Mutex<RegistryInner>>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    live: HashMap<Uuid, PublishedSyntheticKdc>,
    /// Registry-wide monotonic counter (not per-JTI) so generations stay unique without leaking map entries.
    next_generation: u64,
}

#[derive(Debug, Clone)]
struct PublishedSyntheticKdc {
    generation: u64,
    kdc: Arc<CredentialInjectionKdc>,
}

/// RAII lease for a published synthetic KDC. Dropping it unpublishes only this generation.
pub(crate) struct SyntheticKdcRegistration {
    registry: SyntheticKdcRegistry,
    jti: Uuid,
    generation: u64,
}

impl Drop for SyntheticKdcRegistration {
    fn drop(&mut self) {
        let mut inner = self.registry.inner.lock();
        let Some(current) = inner.live.get(&self.jti) else {
            return;
        };
        if current.generation == self.generation {
            inner.live.remove(&self.jti);
            debug!(jti = %self.jti, generation = self.generation, "unpublished synthetic KDC");
        }
    }
}

impl Default for SyntheticKdcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SyntheticKdcRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RegistryInner::default())),
        }
    }

    fn allocate_generation(inner: &mut RegistryInner) -> u64 {
        inner.next_generation = inner.next_generation.wrapping_add(1);
        inner.next_generation
    }

    pub(crate) fn register(&self, kdc: Arc<CredentialInjectionKdc>) -> SyntheticKdcRegistration {
        let jti = kdc.jti();
        let mut inner = self.inner.lock();
        let generation = Self::allocate_generation(&mut inner);
        inner.live.insert(jti, PublishedSyntheticKdc { generation, kdc });
        debug!(%jti, generation, "published synthetic KDC");
        SyntheticKdcRegistration {
            registry: self.clone(),
            jti,
            generation,
        }
    }

    pub(crate) fn get(&self, jti: Uuid) -> Option<Arc<CredentialInjectionKdc>> {
        self.inner.lock().live.get(&jti).map(|e| Arc::clone(&e.kdc))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ironrdp_connector::sspi::network_client::NetworkProtocol;
    use secrecy::SecretString;

    use super::*;
    use crate::credential::{CleartextAppCredential, CleartextAppCredentialMapping};
    use crate::target_connection_options::TargetConnectionOptions;

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

    fn kdc_options() -> TargetConnectionOptions {
        serde_json::from_value(serde_json::json!({ "krb_kdc": "tcp://dc.example:88" })).expect("options")
    }

    fn stock_with_mapping(jti: Uuid, target_username: &str) -> ProvisioningStore {
        let store = ProvisioningStore::new();
        store
            .insert_credentials(
                association_token(jti),
                Some(cleartext_mapping_with_target_username(target_username)),
                time::Duration::minutes(5),
            )
            .expect("insert");
        store
    }

    fn dummy_entry(jti: Uuid, target_username: &str) -> ProvisioningEntry {
        stock_with_mapping(jti, target_username).take(jti).expect("entry")
    }

    fn dummy_kdc(jti: Uuid) -> CredentialInjectionKdc {
        let entry = dummy_entry(jti, "target");
        let mapping = entry.mapping.expect("mapping");
        CredentialInjectionKdc::new(
            jti,
            "target.example".to_owned(),
            app_credential_username(&mapping.proxy),
            &mapping.proxy,
        )
        .expect("valid KDC")
    }

    fn network_request(url: &str) -> NetworkRequest {
        NetworkRequest {
            protocol: NetworkProtocol::Http,
            url: Url::parse(url).expect("url"),
            data: Vec::new(),
        }
    }

    #[test]
    fn proxy_user_at_realm_is_used_as_realm() {
        assert_eq!(
            realm_from_proxy_username("proxy@example.invalid", Uuid::new_v4()),
            "example.invalid"
        );
    }

    #[test]
    fn bare_proxy_username_yields_synthetic_realm() {
        let jti = Uuid::new_v4();
        assert_eq!(realm_from_proxy_username("just-a-uuid", jti), synthetic_realm(jti));
    }

    #[test]
    fn from_provisioned_selects_ntlm_when_kerberos_disabled() {
        let jti = Uuid::new_v4();
        let entry = dummy_entry(jti, "administrator@example.invalid");
        let registry = SyntheticKdcRegistry::new();
        let injection = CredentialInjection::from_provisioned(jti, entry, false)
            .expect("prepared")
            .register_if_kerberos(&registry);
        assert!(!injection.uses_kerberos());
        assert!(registry.get(jti).is_none());
    }

    #[test]
    fn from_provisioned_selects_ntlm_for_domainless_target() {
        let jti = Uuid::new_v4();
        let entry = dummy_entry(jti, "Administrator");
        let registry = SyntheticKdcRegistry::new();
        let injection = CredentialInjection::from_provisioned(jti, entry, true)
            .expect("prepared")
            .register_if_kerberos(&registry);
        assert!(!injection.uses_kerberos());
    }

    #[test]
    fn from_provisioned_requires_krb_kdc_for_kerberos() {
        let jti = Uuid::new_v4();
        let entry = dummy_entry(jti, "administrator@example.invalid");
        let err = CredentialInjection::from_provisioned(jti, entry, true).expect_err("kdc");
        assert!(matches!(err, CredentialInjectionKdcResolveError::MissingKrbKdc { .. }));
    }

    #[test]
    fn from_provisioned_publishes_synthetic_kdc_for_kerberos() {
        let jti = Uuid::new_v4();
        let store = stock_with_mapping(jti, "administrator@example.invalid");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let entry = store.take(jti).expect("entry");
        assert!(store.take(jti).is_none(), "take consumes groceries");
        let registry = SyntheticKdcRegistry::new();
        let prepared = CredentialInjection::from_provisioned(jti, entry, true).expect("prepared");
        assert!(registry.get(jti).is_none(), "not published until register_if_kerberos");
        let injection = prepared.register_if_kerberos(&registry);
        assert!(injection.uses_kerberos());
        assert!(registry.get(jti).is_some());
        assert_eq!(
            registry.get(jti).expect("live kdc").jti(),
            injection.as_kerberos().expect("kerberos").synthetic_kdc().jti()
        );
    }

    #[test]
    fn registry_replace_and_guarded_drop_keeps_successor() {
        let registry = SyntheticKdcRegistry::new();
        let jti = Uuid::new_v4();
        let first = Arc::new(dummy_kdc(jti));
        let first_reg = registry.register(Arc::clone(&first));
        assert!(Arc::ptr_eq(&registry.get(jti).expect("first"), &first));
        let second = Arc::new(dummy_kdc(jti));
        let second_reg = registry.register(Arc::clone(&second));
        assert!(Arc::ptr_eq(&registry.get(jti).expect("second"), &second));
        drop(first_reg);
        assert!(Arc::ptr_eq(&registry.get(jti).expect("still second"), &second));
        drop(second_reg);
        assert!(registry.get(jti).is_none());
    }

    #[test]
    fn kdc_proxy_cannot_invent_from_groceries() {
        let jti = Uuid::new_v4();
        let _store = stock_with_mapping(jti, "administrator@example.invalid");
        let registry = SyntheticKdcRegistry::new();
        assert!(registry.get(jti).is_none());
    }

    #[test]
    fn new_kdc_uses_jti_in_in_process_url() {
        let jti = Uuid::new_v4();
        let kdc = dummy_kdc(jti);
        let url = kdc.in_process_kdc_url().expect("url");
        assert!(url.path().contains(&jti.to_string()));
    }

    #[test]
    fn intercept_ignores_non_injection_host() {
        let kdc = dummy_kdc(Uuid::new_v4());
        let result = kdc
            .intercept_network_request(&network_request("http://kdc.real.example/path"))
            .expect("intercept");
        assert!(matches!(
            result,
            CredentialInjectionKdcInterception::NotInjectionRequest
        ));
    }

    #[test]
    fn intercept_rejects_malformed_url_path() {
        let kdc = dummy_kdc(Uuid::new_v4());
        let err = kdc
            .intercept_network_request(&network_request("http://cred.invalid/not-a-uuid"))
            .expect_err("malformed path");
        assert!(format!("{err:#}").contains("malformed in-process KDC URL"));
    }
}
