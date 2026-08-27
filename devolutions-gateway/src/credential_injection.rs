//! Credential-injection runtime for RDP.
//!
//! - Provisioned mappings live in [`crate::provisioning::ProvisioningStore`].
//! - [`CredentialInjection::from_provisioned`] builds a session-scoped injection plan.
//! - Kerberos sessions reuse one synthetic KDC per provisioning generation, then publish a
//!   [`CredentialInjectionKdc`] into [`SyntheticKdcRegistry`] for the connection.
//! - `/jet/KdcProxy` resolves only that registry (not the provisioning store).

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
use tokio::sync::Notify;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::credential::{AppCredential, AppCredentialMapping};
use crate::provisioning::{ProvisioningEntry, ProvisioningStore};

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

/// Kerberos injection: credentials, target KDC URL, and the session synthetic KDC.
pub(crate) struct KerberosCredentialInjection {
    credential_mapping: AppCredentialMapping,
    session: KerberosSessionMaterial,
}

#[derive(Debug, Clone)]
struct KerberosSessionMaterial {
    target_kdc: Url,
    synthetic: Arc<CredentialInjectionKdc>,
}

/// Protocol chosen; synthetic KDC built when Kerberos, not yet published to the registry.
#[derive(Debug)]
pub(crate) enum PreparedCredentialInjection {
    Kerberos(KerberosCredentialInjection),
    Ntlm(NtlmCredentialInjection),
}

impl PreparedCredentialInjection {
    /// Publish the synthetic KDC when this is Kerberos; NTLM is a no-op pass-through.
    pub(crate) fn register_if_kerberos(
        self,
        registry: &SyntheticKdcRegistry,
        provision_generation: u64,
    ) -> CredentialInjection {
        match self {
            Self::Kerberos(injection) => {
                let registration = registry.register(Arc::clone(&injection.session.synthetic), provision_generation);
                debug!(
                    jti = %injection.session.synthetic.jti(),
                    "Registered synthetic KDC for credential-injection session"
                );
                CredentialInjection::Kerberos(injection, registration)
            }
            Self::Ntlm(injection) => CredentialInjection::Ntlm(injection),
        }
    }
}

impl KerberosCredentialInjection {
    pub(crate) fn synthetic_kdc(&self) -> &CredentialInjectionKdc {
        &self.session.synthetic
    }

    pub(crate) fn target_kdc(&self) -> &Url {
        &self.session.target_kdc
    }
}

impl fmt::Debug for KerberosCredentialInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KerberosCredentialInjection")
            .field("target_kdc", &self.session.target_kdc)
            .field("synthetic", &self.session.synthetic)
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
    pub(crate) fn checkout(
        provisioning: &ProvisioningStore,
        registry: &SyntheticKdcRegistry,
        jti: Uuid,
        token: &str,
        kerberos_enabled: bool,
    ) -> anyhow::Result<Self> {
        let entry = provisioning
            .get_mapping(jti, token)
            .with_context(|| format!("checkout credential-injection material for {jti}"))?;
        let generation = entry.generation;
        let kdc_expires_at = entry.kdc_expires_at;
        registry.discard_stale_session_kdc(jti, generation);
        let session = registry.session_kerberos_material(jti, generation);
        let prepared = Self::from_provisioned_with_session(jti, entry, kerberos_enabled, session)?;
        let prepared = match prepared {
            PreparedCredentialInjection::Kerberos(mut injection) => {
                let expires_at = kdc_expires_at.context("mapped Kerberos row has no token deadline")?;
                injection.session = registry.intern_session_kerberos(jti, generation, expires_at, injection.session);
                PreparedCredentialInjection::Kerberos(injection)
            }
            ntlm @ PreparedCredentialInjection::Ntlm(_) => ntlm,
        };
        Ok(prepared.register_if_kerberos(registry, generation))
    }

    pub(crate) fn jti(&self) -> Uuid {
        match self {
            Self::Kerberos(k, _) => k.session.synthetic.jti(),
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

    /// Build a session injection plan from a checked-out provisioning entry.
    ///
    /// Does not publish to [`SyntheticKdcRegistry`]; call
    /// [`PreparedCredentialInjection::register_if_kerberos`] next.
    #[cfg(test)]
    pub(crate) fn from_provisioned(
        jti: Uuid,
        credential_entry: ProvisioningEntry,
        kerberos_enabled: bool,
    ) -> anyhow::Result<PreparedCredentialInjection> {
        Self::from_provisioned_with_session(jti, credential_entry, kerberos_enabled, None)
    }

    fn from_provisioned_with_session(
        jti: Uuid,
        credential_entry: ProvisioningEntry,
        kerberos_enabled: bool,
        session: Option<KerberosSessionMaterial>,
    ) -> anyhow::Result<PreparedCredentialInjection> {
        let ProvisioningEntry {
            token,
            mapping,
            connection_options,
            generation: _,
            kdc_expires_at: _,
        } = credential_entry;

        let mapping = mapping.context("credential-injection state has no mapping")?;

        let target_hostname = crate::token::extract_credential_injection_target_hostname(&token)
            .with_context(|| format!("association token for {jti} is not valid for credential injection"))?;

        let target_username = app_credential_username(&mapping.target);
        if !select_kerberos_for_target(kerberos_enabled, target_username) {
            return Ok(PreparedCredentialInjection::Ntlm(NtlmCredentialInjection {
                jti,
                credential_mapping: mapping,
            }));
        }

        if let Some(session) = session {
            return Ok(PreparedCredentialInjection::Kerberos(KerberosCredentialInjection {
                credential_mapping: mapping,
                session,
            }));
        }

        // Kerberos path: username must parse (select_kerberos_for_target already required a domain).
        sspi::Username::parse(target_username)
            .with_context(|| format!("invalid target credential username for credential-injection session {jti}"))?;

        let target_kdc = connection_options
            .as_ref()
            .and_then(|o| o.krb_kdc())
            .cloned()
            .with_context(|| {
                format!("Kerberos credential injection requires target connection option krb_kdc for {jti}")
            })?;

        let proxy_username = app_credential_username(&mapping.proxy).to_owned();
        let synthetic = CredentialInjectionKdc::new(jti, target_hostname, &proxy_username, &mapping.proxy)
            .with_context(|| format!("credential-injection KDC config could not be initialized for {jti}"))?;

        Ok(PreparedCredentialInjection::Kerberos(KerberosCredentialInjection {
            credential_mapping: mapping,
            session: KerberosSessionMaterial {
                target_kdc,
                synthetic: Arc::new(synthetic),
            },
        }))
    }
}

/// Whether the target username should use Kerberos injection (otherwise NTLM).
pub(crate) fn select_kerberos_for_target(kerberos_enabled: bool, target_username: &str) -> bool {
    if !kerberos_enabled {
        return false;
    }
    sspi::Username::parse(target_username)
        .ok()
        .is_some_and(|username| username.domain_name().is_some())
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

impl Drop for CredentialInjectionKdc {
    fn drop(&mut self) {
        zeroize_kdc_config(&mut self.kdc_config);
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
        let krbtgt_key = SecretBox::new(Box::new(random_32_bytes()));

        let kdc_config = build_kdc_config(
            &realm,
            proxy_credential,
            &acceptor_principal_name,
            acceptor_password.expose_secret(),
            krbtgt_key.expose_secret(),
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

    /// Session destination host from association `dst_hst` (not Gateway `conf.hostname`).
    ///
    /// Supported clients retain this logical destination when forming their `TERMSRV` SPN, even
    /// when the transport endpoint is a Gateway listener.
    /// Clients that derive the SPN from the Gateway transport hostname are not supported by the
    /// unstable Kerberos credential-injection path.
    pub(crate) fn target_hostname(&self) -> &str {
        &self.target_hostname
    }

    pub(crate) fn server_kerberos_config(&self, client_addr: SocketAddr) -> anyhow::Result<sspi::KerberosServerConfig> {
        let user = sspi::CredentialsBuffers::AuthIdentity(sspi::AuthIdentityBuffers::from_utf8(
            &self.acceptor_principal_name,
            &self.realm,
            self.acceptor_password.expose_secret(),
        ));

        let kdc_url = self.in_process_kdc_url()?;

        // Client AP-REQ SPN is TERMSRV/<dst_hst>. Gateway-as-CredSSP-server impersonates that
        // session destination, so ServerProperties must claim the same SPN.
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

fn zeroize_kdc_config(config: &mut kdc::config::KerberosServer) {
    for user in &mut config.users {
        user.password.zeroize();
    }
    config.krbtgt_key.zeroize();
    if let Some(key) = &mut config.ticket_decryption_key {
        key.zeroize();
    }
    if let Some(user) = &mut config.service_user {
        user.password.zeroize();
    }
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
/// - The RDP path registers when a Kerberos injection session starts.
/// - `/jet/KdcProxy` only looks up published entries; it never builds a KDC from
///   [`crate::provisioning::ProvisioningStore`].
///
/// Connection leases publish to `/jet/KdcProxy`. The same provisioning generation is
/// reference-counted; a newer generation replaces an older one. An older lease cannot unpublish
/// or overwrite a newer generation.
#[derive(Debug, Clone)]
pub struct SyntheticKdcRegistry {
    inner: Arc<Mutex<RegistryInner>>,
    cleanup_notify: Arc<Notify>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    live: HashMap<Uuid, PublishedSyntheticKdc>,
    session: HashMap<Uuid, SessionKerberosEntry>,
}

#[derive(Debug, Clone)]
struct PublishedSyntheticKdc {
    provision_generation: u64,
    leases: u32,
    kdc: Arc<CredentialInjectionKdc>,
}

#[derive(Debug, Clone)]
struct SessionKerberosEntry {
    provision_generation: u64,
    expires_at: time::OffsetDateTime,
    material: KerberosSessionMaterial,
}

fn generation_is_newer(candidate: u64, than: u64) -> bool {
    candidate != than && candidate.wrapping_sub(than) < than.wrapping_sub(candidate)
}

/// RAII lease for a published synthetic KDC.
pub(crate) struct SyntheticKdcRegistration {
    registry: SyntheticKdcRegistry,
    jti: Uuid,
    provision_generation: u64,
}

impl Drop for SyntheticKdcRegistration {
    fn drop(&mut self) {
        let mut inner = self.registry.inner.lock();
        let Some(current) = inner.live.get_mut(&self.jti) else {
            return;
        };
        if current.provision_generation != self.provision_generation {
            return;
        }
        current.leases = current.leases.saturating_sub(1);
        if current.leases == 0 {
            inner.live.remove(&self.jti);
            debug!(
                jti = %self.jti,
                provision_generation = self.provision_generation,
                "Unpublished synthetic KDC"
            );
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
            cleanup_notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn register(
        &self,
        kdc: Arc<CredentialInjectionKdc>,
        provision_generation: u64,
    ) -> SyntheticKdcRegistration {
        let jti = kdc.jti();
        let mut inner = self.inner.lock();
        match inner.live.get_mut(&jti) {
            Some(current) if current.provision_generation == provision_generation => {
                current.leases = current.leases.saturating_add(1);
            }
            Some(current) if generation_is_newer(current.provision_generation, provision_generation) => {}
            _ => {
                inner.live.insert(
                    jti,
                    PublishedSyntheticKdc {
                        provision_generation,
                        leases: 1,
                        kdc,
                    },
                );
                debug!(%jti, provision_generation, "Published synthetic KDC");
            }
        }
        SyntheticKdcRegistration {
            registry: self.clone(),
            jti,
            provision_generation,
        }
    }

    pub(crate) fn get(&self, jti: Uuid) -> Option<Arc<CredentialInjectionKdc>> {
        self.inner.lock().live.get(&jti).map(|entry| Arc::clone(&entry.kdc))
    }

    /// Drop an interned KDC older than this provisioning generation.
    pub(crate) fn discard_stale_session_kdc(&self, jti: Uuid, provision_generation: u64) {
        let mut inner = self.inner.lock();
        if inner
            .session
            .get(&jti)
            .is_some_and(|entry| generation_is_newer(provision_generation, entry.provision_generation))
        {
            inner.session.remove(&jti);
            self.cleanup_notify.notify_one();
        }
    }

    fn session_kerberos_material(&self, jti: Uuid, provision_generation: u64) -> Option<KerberosSessionMaterial> {
        let now = time::OffsetDateTime::now_utc();
        let mut inner = self.inner.lock();
        let entry = inner.session.get(&jti)?;
        if now >= entry.expires_at {
            inner.session.remove(&jti);
            self.cleanup_notify.notify_one();
            return None;
        }
        (entry.provision_generation == provision_generation).then(|| entry.material.clone())
    }

    /// Reuse the Kerberos session material for this provisioning generation until `expires_at`.
    ///
    /// A later `provision-credentials` bumps the generation and replaces the cached KDC.
    /// An older generation never overwrites a newer interned KDC.
    fn intern_session_kerberos(
        &self,
        jti: Uuid,
        provision_generation: u64,
        expires_at: time::OffsetDateTime,
        material: KerberosSessionMaterial,
    ) -> KerberosSessionMaterial {
        let now = time::OffsetDateTime::now_utc();
        let mut inner = self.inner.lock();
        if inner.session.get(&jti).is_some_and(|entry| now >= entry.expires_at) {
            inner.session.remove(&jti);
        }
        if now >= expires_at {
            if inner
                .session
                .get(&jti)
                .is_some_and(|entry| entry.provision_generation == provision_generation)
            {
                inner.session.remove(&jti);
                self.cleanup_notify.notify_one();
            }
            return material;
        }
        if let Some(existing) = inner.session.get(&jti) {
            if existing.provision_generation == provision_generation {
                return existing.material.clone();
            }
            if generation_is_newer(existing.provision_generation, provision_generation) {
                return material;
            }
        }
        inner.session.insert(
            jti,
            SessionKerberosEntry {
                provision_generation,
                expires_at,
                material: material.clone(),
            },
        );
        self.cleanup_notify.notify_one();
        material
    }

    fn remove_expired_session_kdcs(&self, now: time::OffsetDateTime) {
        self.inner.lock().session.retain(|_, entry| now < entry.expires_at);
    }

    fn next_session_expiry(&self) -> Option<time::OffsetDateTime> {
        self.inner.lock().session.values().map(|entry| entry.expires_at).min()
    }

    #[cfg(test)]
    pub(crate) fn session_kdc_live(&self, jti: Uuid) -> bool {
        self.interned_kdc(jti).is_some()
    }

    #[cfg(test)]
    fn interned_kdc(&self, jti: Uuid) -> Option<Arc<CredentialInjectionKdc>> {
        let now = time::OffsetDateTime::now_utc();
        self.inner
            .lock()
            .session
            .get(&jti)
            .and_then(|entry| (now < entry.expires_at).then(|| Arc::clone(&entry.material.synthetic)))
    }
}

pub struct CleanupTask {
    pub handle: SyntheticKdcRegistry,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "synthetic KDC cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.handle, shutdown_signal).await;
        Ok(())
    }
}

#[tracing::instrument(skip_all)]
async fn cleanup_task(handle: SyntheticKdcRegistry, mut shutdown_signal: ShutdownSignal) {
    tracing::debug!("Task started");

    loop {
        let now = time::OffsetDateTime::now_utc();
        handle.remove_expired_session_kdcs(now);

        match handle.next_session_expiry() {
            Some(deadline) => {
                let delay = (deadline - now).try_into().unwrap_or_default();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = handle.cleanup_notify.notified() => {}
                    _ = shutdown_signal.wait() => break,
                }
            }
            None => {
                tokio::select! {
                    _ = handle.cleanup_notify.notified() => {}
                    _ = shutdown_signal.wait() => break,
                }
            }
        }
    }

    tracing::debug!("Task terminated");
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
            "dst_hst": "target.example:3389",
            "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 3600
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

    fn kerberos_material(kdc: Arc<CredentialInjectionKdc>) -> KerberosSessionMaterial {
        KerberosSessionMaterial {
            target_kdc: Url::parse("tcp://dc.example:88").expect("url"),
            synthetic: kdc,
        }
    }

    fn network_request(url: &str) -> NetworkRequest {
        NetworkRequest {
            protocol: NetworkProtocol::Http,
            url: Url::parse(url).expect("url"),
            data: Vec::new(),
        }
    }

    #[test]
    fn select_kerberos_for_target_matrix() {
        assert!(!select_kerberos_for_target(false, "user@CORP.EXAMPLE"));
        assert!(!select_kerberos_for_target(true, "Administrator"));
        assert!(!select_kerberos_for_target(true, ""));
        assert!(select_kerberos_for_target(true, "user@CORP.EXAMPLE"));
        assert!(select_kerberos_for_target(true, r"CORP\user"));
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
            .register_if_kerberos(&registry, 1);
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
            .register_if_kerberos(&registry, 1);
        assert!(!injection.uses_kerberos());
    }

    #[test]
    fn from_provisioned_requires_krb_kdc_for_kerberos() {
        let jti = Uuid::new_v4();
        let entry = dummy_entry(jti, "administrator@example.invalid");
        let err = CredentialInjection::from_provisioned(jti, entry, true).expect_err("kdc");
        assert!(format!("{err:#}").contains("requires target connection option krb_kdc"));
    }

    #[test]
    fn from_provisioned_publishes_synthetic_kdc_for_kerberos() {
        let jti = Uuid::new_v4();
        let store = stock_with_mapping(jti, "administrator@example.invalid");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let entry = store.take(jti).expect("entry");
        assert!(store.take(jti).is_none(), "test helper take removes the row");
        let registry = SyntheticKdcRegistry::new();
        let prepared = CredentialInjection::from_provisioned(jti, entry, true).expect("prepared");
        assert!(registry.get(jti).is_none(), "not published until register_if_kerberos");
        let injection = prepared.register_if_kerberos(&registry, 1);
        assert!(injection.uses_kerberos());
        assert!(registry.get(jti).is_some());
        assert_eq!(
            registry.get(jti).expect("live kdc").jti(),
            injection.as_kerberos().expect("kerberos").synthetic_kdc().jti()
        );
    }

    #[test]
    fn checkout_reuses_synthetic_kdc_for_the_same_generation() {
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        let store = ProvisioningStore::new();
        store
            .insert_credentials(
                token.clone(),
                Some(cleartext_mapping_with_target_username("administrator@example.invalid")),
                time::Duration::minutes(5),
            )
            .expect("insert");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let registry = SyntheticKdcRegistry::new();

        let first = CredentialInjection::checkout(&store, &registry, jti, &token, true).expect("first");
        let first_ptr = std::ptr::from_ref(first.as_kerberos().expect("kerberos").synthetic_kdc());
        drop(first);

        let second = CredentialInjection::checkout(&store, &registry, jti, &token, true).expect("second");
        let second_ptr = std::ptr::from_ref(second.as_kerberos().expect("kerberos").synthetic_kdc());
        assert_eq!(first_ptr, second_ptr);

        store
            .insert_credentials(
                token.clone(),
                Some(cleartext_mapping_with_target_username("administrator@example.invalid")),
                time::Duration::minutes(5),
            )
            .expect("re-provision");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let third = CredentialInjection::checkout(&store, &registry, jti, &token, true).expect("third");
        let third_ptr = std::ptr::from_ref(third.as_kerberos().expect("kerberos").synthetic_kdc());
        assert_ne!(first_ptr, third_ptr);
    }

    #[test]
    fn checkout_reuses_kerberos_session_after_connection_options_expire() {
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        let store = ProvisioningStore::new();
        store
            .insert_credentials(
                token.clone(),
                Some(cleartext_mapping_with_target_username("administrator@example.invalid")),
                time::Duration::minutes(5),
            )
            .expect("insert");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let registry = SyntheticKdcRegistry::new();

        let first_injection = CredentialInjection::checkout(&store, &registry, jti, &token, true).expect("first");
        let first = first_injection.as_kerberos().expect("kerberos");
        let first_kdc = std::ptr::from_ref(first.synthetic_kdc());
        let first_target_kdc = first.target_kdc().clone();
        drop(first_injection);

        store.insert_connection_options(
            jti,
            TargetConnectionOptions::new(Some("tcp://replacement.example:88")).expect("options"),
            time::Duration::seconds(-1),
        );

        let second = CredentialInjection::checkout(&store, &registry, jti, &token, true).expect("reconnect");
        let second = second.as_kerberos().expect("kerberos");
        assert_eq!(std::ptr::from_ref(second.synthetic_kdc()), first_kdc);
        assert_eq!(second.target_kdc(), &first_target_kdc);
    }

    #[test]
    fn interned_kdc_is_not_kept_past_deadline() {
        let jti = Uuid::new_v4();
        let registry = SyntheticKdcRegistry::new();
        let kdc = Arc::new(dummy_kdc(jti));
        let deadline = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
        registry.intern_session_kerberos(jti, 1, deadline, kerberos_material(kdc));
        registry.remove_expired_session_kdcs(deadline + time::Duration::seconds(1));
        assert!(!registry.session_kdc_live(jti));
    }

    #[test]
    fn session_cache_expiry_keeps_active_registration() {
        let jti = Uuid::new_v4();
        let registry = SyntheticKdcRegistry::new();
        let kdc = Arc::new(dummy_kdc(jti));
        let deadline = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
        registry.intern_session_kerberos(jti, 1, deadline, kerberos_material(Arc::clone(&kdc)));
        let registration = registry.register(Arc::clone(&kdc), 1);

        registry.remove_expired_session_kdcs(deadline + time::Duration::seconds(1));

        assert!(!registry.session_kdc_live(jti));
        assert!(Arc::ptr_eq(&registry.get(jti).expect("active KDC"), &kdc));
        drop(registration);
        assert!(registry.get(jti).is_none());
    }

    #[test]
    fn zeroize_kdc_config_clears_secret_copies() {
        let mut kdc = dummy_kdc(Uuid::new_v4());
        assert!(kdc.kdc_config.users.iter().any(|user| !user.password.is_empty()));
        assert!(!kdc.kdc_config.krbtgt_key.is_empty());
        assert!(
            kdc.kdc_config
                .ticket_decryption_key
                .as_ref()
                .is_some_and(|key| !key.is_empty())
        );
        assert!(
            kdc.kdc_config
                .service_user
                .as_ref()
                .is_some_and(|user| !user.password.is_empty())
        );

        zeroize_kdc_config(&mut kdc.kdc_config);

        assert!(kdc.kdc_config.users.iter().all(|user| user.password.is_empty()));
        assert!(kdc.kdc_config.krbtgt_key.is_empty());
        assert!(kdc.kdc_config.ticket_decryption_key.as_ref().is_some_and(Vec::is_empty));
        assert!(
            kdc.kdc_config
                .service_user
                .as_ref()
                .is_some_and(|user| user.password.is_empty())
        );
    }

    #[test]
    fn ntlm_checkout_discards_previous_generation_kdc() {
        let jti = Uuid::new_v4();
        let token = association_token(jti);
        let store = ProvisioningStore::new();
        store
            .insert_credentials(
                token.clone(),
                Some(cleartext_mapping_with_target_username("administrator@example.invalid")),
                time::Duration::minutes(5),
            )
            .expect("insert");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let registry = SyntheticKdcRegistry::new();
        let _kerberos = CredentialInjection::checkout(&store, &registry, jti, &token, true).expect("kerberos");
        assert!(registry.session_kdc_live(jti));

        store
            .insert_credentials(
                token.clone(),
                Some(cleartext_mapping_with_target_username("Administrator")),
                time::Duration::minutes(5),
            )
            .expect("ntlm re-provision");
        let _ntlm = CredentialInjection::checkout(&store, &registry, jti, &token, true).expect("ntlm");
        assert!(!registry.session_kdc_live(jti));
    }

    #[test]
    fn provisioned_krb_kdc_is_carried_on_kerberos_injection() {
        // Pins provision → from_provisioned → target_kdc for the CredSSP client leg.
        let jti = Uuid::new_v4();
        let store = stock_with_mapping(jti, "administrator@example.invalid");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let entry = store.take(jti).expect("entry");
        let injection = CredentialInjection::from_provisioned(jti, entry, true)
            .expect("prepared")
            .register_if_kerberos(&SyntheticKdcRegistry::new(), 1);

        assert_eq!(
            injection.as_kerberos().expect("kerberos").target_kdc().as_str(),
            "tcp://dc.example:88",
            "provisioned krb_kdc must be the URL CredSSP will use as kdc_proxy_url",
        );
    }

    #[test]
    fn from_provisioned_uses_association_dst_hst_for_synthetic_kdc() {
        // Destination is dynamic per token. conf.hostname is Gateway identity only and must not
        // drive synthetic KDC SPN / service host (deliberate correction of #1856).
        let jti = Uuid::new_v4();
        let store = ProvisioningStore::new();
        store
            .insert_credentials(
                unsigned_jws(serde_json::json!({
                    "jti": jti,
                    "dst_hst": "it-help-dc.corp.example:3389",
                    "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 3600
                })),
                Some(cleartext_mapping_with_target_username("administrator@example.invalid")),
                time::Duration::minutes(5),
            )
            .expect("insert");
        store.insert_connection_options(jti, kdc_options(), time::Duration::minutes(5));
        let entry = store.take(jti).expect("entry");
        let injection = CredentialInjection::from_provisioned(jti, entry, true)
            .expect("prepared")
            .register_if_kerberos(&SyntheticKdcRegistry::new(), 1);

        assert_eq!(
            injection
                .as_kerberos()
                .expect("kerberos")
                .synthetic_kdc()
                .target_hostname(),
            "it-help-dc.corp.example",
        );
    }

    #[test]
    fn older_registration_drop_keeps_reprovisioned_successor() {
        let registry = SyntheticKdcRegistry::new();
        let jti = Uuid::new_v4();
        let first = Arc::new(dummy_kdc(jti));
        let first_registration = registry.register(Arc::clone(&first), 1);
        assert!(Arc::ptr_eq(&registry.get(jti).expect("first"), &first));

        let second = Arc::new(dummy_kdc(jti));
        let second_registration = registry.register(Arc::clone(&second), 2);
        drop(first_registration);
        assert!(Arc::ptr_eq(&registry.get(jti).expect("successor"), &second));

        drop(second_registration);
        assert!(registry.get(jti).is_none());
    }

    #[test]
    fn same_generation_leases_unpublish_on_last_drop() {
        let registry = SyntheticKdcRegistry::new();
        let jti = Uuid::new_v4();
        let kdc = Arc::new(dummy_kdc(jti));
        let first = registry.register(Arc::clone(&kdc), 1);
        let second = registry.register(Arc::clone(&kdc), 1);
        drop(first);
        assert!(registry.get(jti).is_some());
        drop(second);
        assert!(registry.get(jti).is_none());
    }

    #[test]
    fn stale_generation_does_not_replace_interned_kdc() {
        let jti = Uuid::new_v4();
        let registry = SyntheticKdcRegistry::new();
        let newer = Arc::new(dummy_kdc(jti));
        let older = Arc::new(dummy_kdc(jti));
        let deadline = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
        let interned = registry.intern_session_kerberos(jti, 2, deadline, kerberos_material(Arc::clone(&newer)));
        assert!(Arc::ptr_eq(&interned.synthetic, &newer));
        let rejected = registry.intern_session_kerberos(jti, 1, deadline, kerberos_material(Arc::clone(&older)));
        assert!(Arc::ptr_eq(&rejected.synthetic, &older));
        assert!(Arc::ptr_eq(&registry.interned_kdc(jti).expect("kept"), &newer));
        registry.discard_stale_session_kdc(jti, 1);
        assert!(Arc::ptr_eq(&registry.interned_kdc(jti).expect("still kept"), &newer));
    }

    #[test]
    fn kdc_proxy_cannot_invent_from_provisioning_store() {
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
