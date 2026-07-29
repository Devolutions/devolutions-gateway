//! Proxy-based credential injection using Kerberos or NTLM.
//!
//! This module selects the authentication protocol and owns the credentials used by the proxy.
//! For Kerberos, it also owns per-session fake-KDC material, the registry of live sessions,
//! KDC proxy handling, and in-process KDC requests from the server-side CredSSP acceptor.

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
use url::Url;
use uuid::Uuid;

use crate::credential::{AppCredential, AppCredentials};
use crate::provisioning::ProvisionedConnection;
use crate::target_addr::TargetAddr;

// The reserved `.invalid` TLD (RFC 6761) lets sspi-rs CredSSP server emit "KDC requests" that
// never leave the process: `intercept_network_request` recognises this hostname and dispatches
// the message into the in-process `kdc` server below.
//
// TODO(sspi-rs#664): replace this URL-trampoline with a pluggable KDC dispatcher trait once
// sspi-rs ships the API — see https://github.com/Devolutions/sspi-rs/issues/664.
const IN_PROCESS_KDC_HOST: &str = "cred.invalid";

pub(crate) enum CredentialInjection {
    // The registration proves the synthetic KDC is published in the registry: holding a
    // `Kerberos` value means the KDC is live for the client's KKDCP lookups. It unpublishes on
    // drop, so it rides inside the value that the RDP proxy owns for the whole session.
    Kerberos(
        KerberosCredentialInjection,
        #[expect(
            dead_code,
            reason = "held only for its RAII Drop, which unpublishes the KDC at session end"
        )]
        SyntheticKdcRegistration,
    ),
    Ntlm(NtlmCredentialInjection),
}

pub(crate) struct KerberosCredentialInjection {
    jti: Uuid,
    credentials: AppCredentials,
    target_kdc: TargetAddr,
    synthetic_kdc: Arc<SyntheticKdcSession>,
}

impl KerberosCredentialInjection {
    pub(crate) fn synthetic_kdc(&self) -> Arc<SyntheticKdcSession> {
        Arc::clone(&self.synthetic_kdc)
    }
}

pub(crate) struct NtlmCredentialInjection {
    jti: Uuid,
    credentials: AppCredentials,
}

pub(crate) struct SyntheticKdcSession {
    jti: Uuid,
    target_hostname: String,
    realm: String,
    acceptor_principal_name: String,
    acceptor_password: SecretString,
    acceptor_long_term_key: SecretBox<Vec<u8>>,
    // The KDC crate models users with plaintext passwords, so this object owns those secrets
    // for the lifetime of the credential-injection KDC. Keep Debug redacted.
    kdc_config: kdc::config::KerberosServer,
}

impl fmt::Debug for SyntheticKdcSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntheticKdcSession")
            .field("jti", &self.jti)
            .field("target_hostname", &self.target_hostname)
            .field("realm", &self.realm)
            .field("kdc_config", &"<redacted>")
            .finish()
    }
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
pub(crate) enum SyntheticKdcInterception {
    Intercepted(Vec<u8>),
    NotInjectionRequest,
    NotInjectionRealm(RealmMismatch),
}

impl fmt::Debug for CredentialInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kerberos(injection, _) => f
                .debug_struct("CredentialInjection::Kerberos")
                .field("jti", &injection.jti)
                .field("target_hostname", &injection.synthetic_kdc.target_hostname)
                .field("realm", &injection.synthetic_kdc.realm)
                .field("kdc_config", &"<redacted>")
                .finish(),
            Self::Ntlm(injection) => f
                .debug_struct("CredentialInjection::Ntlm")
                .field("jti", &injection.jti)
                .finish(),
        }
    }
}

pub(crate) enum CredentialInjectionInitializationResult {
    Kerberos(KerberosCredentialInjection),
    Ntlm(NtlmCredentialInjection),
}

impl CredentialInjectionInitializationResult {
    pub(crate) fn maybe_register_synthetic_kdc(self, registry: &SyntheticKdcRegistry) -> CredentialInjection {
        match self {
            Self::Kerberos(injection) => {
                // The registration rides inside the returned CredentialInjection (owned by the RDP
                // proxy), so the synthetic KDC stays published for the whole session and the
                // client's KKDCP lookups resolve; it unpublishes on drop when the session ends.
                let registration = registry.register(injection.synthetic_kdc());
                debug!(
                    jti = %injection.jti,
                    "registered synthetic KDC for credential-injection session"
                );
                CredentialInjection::Kerberos(injection, registration)
            }
            Self::Ntlm(injection) => CredentialInjection::Ntlm(injection),
        }
    }
}

impl CredentialInjection {
    pub(crate) fn from_provisioned(
        jti: Uuid,
        provisioned_connection: ProvisionedConnection,
        target_hostname: &str,
        kerberos_enabled: bool,
    ) -> anyhow::Result<CredentialInjectionInitializationResult> {
        anyhow::ensure!(
            target_hostname.eq_ignore_ascii_case(&provisioned_connection.target_hostname),
            "credential-injection target mismatch"
        );

        let ProvisionedConnection {
            credentials,
            connection_options,
            target_hostname,
        } = provisioned_connection;

        let uses_kerberos = if kerberos_enabled {
            let target_username = sspi::Username::parse(app_credential_username(&credentials.target))
                .context("invalid target credential username")?;
            target_username.domain_name().is_some()
        } else {
            false
        };

        if uses_kerberos {
            let target_kdc = connection_options
                .as_ref()
                .and_then(crate::target_connection_options::TargetConnectionOptions::krb_kdc)
                .cloned()
                .context("Kerberos credential injection requires target connection option krb_kdc")?;
            let synthetic_kdc = SyntheticKdcSession::new(jti, target_hostname, &credentials.proxy)?;

            Ok(CredentialInjectionInitializationResult::Kerberos(
                KerberosCredentialInjection {
                    jti,
                    credentials,
                    target_kdc,
                    synthetic_kdc: Arc::new(synthetic_kdc),
                },
            ))
        } else {
            Ok(CredentialInjectionInitializationResult::Ntlm(NtlmCredentialInjection {
                jti,
                credentials,
            }))
        }
    }

    pub(crate) fn jti(&self) -> Uuid {
        match self {
            Self::Kerberos(injection, _) => injection.jti,
            Self::Ntlm(injection) => injection.jti,
        }
    }

    pub(crate) fn proxy_credential(&self) -> &AppCredential {
        match self {
            Self::Kerberos(injection, _) => &injection.credentials.proxy,
            Self::Ntlm(injection) => &injection.credentials.proxy,
        }
    }

    pub(crate) fn target_credential(&self) -> &AppCredential {
        match self {
            Self::Kerberos(injection, _) => &injection.credentials.target,
            Self::Ntlm(injection) => &injection.credentials.target,
        }
    }

    pub(crate) fn kerberos_configs(
        &self,
        client_addr: SocketAddr,
        gateway_hostname: &str,
    ) -> anyhow::Result<Option<(sspi::KerberosServerConfig, ironrdp_connector::credssp::KerberosConfig)>> {
        match self {
            Self::Kerberos(injection, _) => Ok(Some((
                injection.synthetic_kdc.server_kerberos_config(client_addr)?,
                ironrdp_connector::credssp::KerberosConfig {
                    kdc_proxy_url: Some(
                        Url::try_from(&injection.target_kdc).context("convert target KDC address to URL")?,
                    ),
                    hostname: gateway_hostname.to_owned(),
                },
            ))),
            Self::Ntlm(_) => Ok(None),
        }
    }

    pub(crate) fn intercept_network_request(
        &self,
        request: &NetworkRequest,
    ) -> anyhow::Result<SyntheticKdcInterception> {
        match self {
            Self::Kerberos(injection, _) => injection.synthetic_kdc.intercept_network_request(request),
            Self::Ntlm(_) => Ok(SyntheticKdcInterception::NotInjectionRequest),
        }
    }
}

impl SyntheticKdcSession {
    fn new(jti: Uuid, target_hostname: String, proxy_credential: &AppCredential) -> anyhow::Result<Self> {
        let proxy_username = app_credential_username(proxy_credential);
        let realm = proxy_username
            .split_once('@')
            .map(|(_, realm)| realm)
            .filter(|realm| !realm.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| synthetic_realm(jti));
        let krbtgt_key = SecretBox::new(Box::new(random_32_bytes()));
        let acceptor_principal_name = "jet".to_owned();
        let acceptor_password = SecretString::from(hex::encode(random_32_bytes()));
        let acceptor_long_term_key = SecretBox::new(Box::new(random_32_bytes()));
        let kdc_config = build_kdc_config(
            &realm,
            &krbtgt_key,
            &acceptor_principal_name,
            &acceptor_password,
            &acceptor_long_term_key,
            proxy_credential,
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

    fn server_kerberos_config(&self, client_addr: SocketAddr) -> anyhow::Result<sspi::KerberosServerConfig> {
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
    ) -> anyhow::Result<SyntheticKdcInterception> {
        if request.url.host_str() != Some(IN_PROCESS_KDC_HOST) {
            return Ok(SyntheticKdcInterception::NotInjectionRequest);
        }

        let url_jti = request
            .url
            .path()
            .trim_start_matches('/')
            .parse::<Uuid>()
            .context("malformed in-process KDC URL")?;
        anyhow::ensure!(
            url_jti == self.jti(),
            "in-process KDC URL JTI does not match current CredSSP session",
        );

        debug!(
            jti = %self.jti(),
            scheme = %request.url.scheme(),
            "Credential-injection KDC intercepted in-process request"
        );

        let kdc_message = KdcProxyMessage::from_raw(&request.data).context("malformed in-process KDC proxy payload")?;
        self.handle_kdc_proxy_message(kdc_message)
    }

    pub(crate) fn handle_kdc_proxy_message(
        &self,
        message: KdcProxyMessage,
    ) -> anyhow::Result<SyntheticKdcInterception> {
        let request_realm = self.resolve_message_realm(&message);
        debug!(
            jti = %self.jti(),
            resolved_realm = %request_realm,
            "Credential-injection KDC realm resolved"
        );

        if let Some(mismatch) = realm_mismatch(&self.realm, &request_realm) {
            return Ok(SyntheticKdcInterception::NotInjectionRealm(mismatch));
        }

        let reply = self.handle_message(message)?;
        Ok(SyntheticKdcInterception::Intercepted(reply))
    }

    fn in_process_kdc_url(&self) -> anyhow::Result<Url> {
        Url::parse(&format!("http://{}/{}", IN_PROCESS_KDC_HOST, self.jti())).context("build in-process KDC URL")
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
        return None;
    }

    Some(RealmMismatch {
        expected: expected.to_owned(),
        actual: actual.to_owned(),
    })
}

fn build_kdc_config(
    realm: &str,
    krbtgt_key: &SecretBox<Vec<u8>>,
    acceptor_principal_name: &str,
    acceptor_password: &SecretString,
    acceptor_long_term_key: &SecretBox<Vec<u8>>,
    proxy_credential: &AppCredential,
) -> anyhow::Result<kdc::config::KerberosServer> {
    let (proxy_user_name, proxy_password) = proxy_credential.decrypt_password()?;
    let proxy_user_name = principal_for_realm(&proxy_user_name, realm);
    let acceptor_principal_name = principal_for_realm(acceptor_principal_name, realm);

    let acceptor_password = acceptor_password.expose_secret().to_owned();
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
        krbtgt_key: krbtgt_key.expose_secret().clone(),
        ticket_decryption_key: Some(acceptor_long_term_key.expose_secret().clone()),
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

/// Indexes Kerberos sessions created by active RDP credential-injection connections.
#[derive(Debug, Clone)]
pub struct SyntheticKdcRegistry {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<SyntheticKdcSession>>>>,
}

#[must_use = "dropping the registration unpublishes the synthetic KDC"]
pub(crate) struct SyntheticKdcRegistration {
    jti: Uuid,
    session: Arc<SyntheticKdcSession>,
    registry: SyntheticKdcRegistry,
}

impl Drop for SyntheticKdcRegistration {
    fn drop(&mut self) {
        // Only retract our own publication: a superseding reconnect may already own this JTI.
        let mut sessions = self.registry.sessions.lock();
        if sessions
            .get(&self.jti)
            .is_some_and(|current| Arc::ptr_eq(current, &self.session))
        {
            sessions.remove(&self.jti);
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
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn register(&self, session: Arc<SyntheticKdcSession>) -> SyntheticKdcRegistration {
        let jti = session.jti();
        // Replace rather than reject: a fast RDP reconnect can register before the previous
        // connection's registration has dropped. The newest connection owns the JTI.
        self.sessions.lock().insert(jti, Arc::clone(&session));
        SyntheticKdcRegistration {
            jti,
            session,
            registry: self.clone(),
        }
    }

    pub(crate) fn get(&self, jti: Uuid) -> Option<Arc<SyntheticKdcSession>> {
        self.sessions.lock().get(&jti).cloned()
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_connector::sspi::network_client::NetworkProtocol;
    use secrecy::SecretString;

    use super::*;
    use crate::credential::{CleartextAppCredential, CleartextAppCredentials};
    use crate::target_connection_options::TargetConnectionOptions;

    fn app_credentials(proxy_username: &str, target_username: &str) -> AppCredentials {
        CleartextAppCredentials {
            proxy: CleartextAppCredential::UsernamePassword {
                username: proxy_username.to_owned(),
                password: SecretString::from("pwd"),
            },
            target: CleartextAppCredential::UsernamePassword {
                username: target_username.to_owned(),
                password: SecretString::from("pwd"),
            },
        }
        .encrypt()
        .expect("credentials encrypt")
    }

    fn provisioned(target_username: &str, krb_kdc: Option<TargetAddr>) -> ProvisionedConnection {
        ProvisionedConnection {
            credentials: app_credentials("proxy@example.invalid", target_username),
            connection_options: krb_kdc.map(|kdc| TargetConnectionOptions::new(Some(kdc)).expect("connection options")),
            target_hostname: "target.example".to_owned(),
        }
    }

    fn target_kdc() -> TargetAddr {
        TargetAddr::parse("tcp://kdc.example.invalid:88", Some(88)).expect("KDC address parses")
    }

    fn session(jti: Uuid) -> SyntheticKdcSession {
        SyntheticKdcSession::new(
            jti,
            "target.example".to_owned(),
            &app_credentials("proxy@example.invalid", "target").proxy,
        )
        .expect("synthetic KDC session")
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
        assert_eq!(session(Uuid::new_v4()).realm, "example.invalid");
    }

    #[test]
    fn bare_proxy_username_yields_synthetic_realm() {
        let jti = Uuid::new_v4();
        let session = SyntheticKdcSession::new(
            jti,
            "target.example".to_owned(),
            &app_credentials("just-a-uuid", "target").proxy,
        )
        .expect("synthetic KDC session");
        assert_eq!(session.realm, synthetic_realm(jti));
    }

    #[test]
    fn from_provisioned_selects_kerberos_for_domain_target_with_kdc() {
        let kdc = target_kdc();
        let injection = CredentialInjection::from_provisioned(
            Uuid::new_v4(),
            provisioned("administrator@example.invalid", Some(kdc.clone())),
            "target.example",
            true,
        )
        .expect("Kerberos injection");

        match injection {
            CredentialInjectionInitializationResult::Kerberos(injection) => assert_eq!(injection.target_kdc, kdc),
            CredentialInjectionInitializationResult::Ntlm(_) => panic!("expected Kerberos injection"),
        }
    }

    #[test]
    fn from_provisioned_hard_errors_when_kerberos_target_has_no_kdc() {
        let error = CredentialInjection::from_provisioned(
            Uuid::new_v4(),
            provisioned("administrator@example.invalid", None),
            "target.example",
            true,
        )
        .err()
        .expect("missing KDC must abort, never fall back to NTLM");
        assert!(format!("{error:#}").contains("requires target connection option krb_kdc"));
    }

    #[test]
    fn from_provisioned_selects_ntlm_for_domainless_target() {
        let injection = CredentialInjection::from_provisioned(
            Uuid::new_v4(),
            provisioned("Administrator", None),
            "target.example",
            true,
        )
        .expect("NTLM injection");
        assert!(matches!(injection, CredentialInjectionInitializationResult::Ntlm(_)));
    }

    #[test]
    fn from_provisioned_selects_ntlm_when_kerberos_disabled() {
        let injection = CredentialInjection::from_provisioned(
            Uuid::new_v4(),
            provisioned("administrator@example.invalid", Some(target_kdc())),
            "target.example",
            false,
        )
        .expect("NTLM injection");
        assert!(matches!(injection, CredentialInjectionInitializationResult::Ntlm(_)));
    }

    #[test]
    fn from_provisioned_rejects_target_hostname_mismatch() {
        let error = CredentialInjection::from_provisioned(
            Uuid::new_v4(),
            provisioned("Administrator", None),
            "other.example",
            true,
        )
        .err()
        .expect("target hostname mismatch must fail closed");
        assert!(format!("{error:#}").contains("target mismatch"));
    }

    #[test]
    fn registered_session_is_retrievable() {
        let registry = SyntheticKdcRegistry::new();
        let jti = Uuid::new_v4();
        let session = Arc::new(session(jti));
        let _registration = registry.register(Arc::clone(&session));
        assert!(Arc::ptr_eq(&registry.get(jti).expect("registered"), &session));
    }

    #[test]
    fn register_replaces_and_guarded_drop_keeps_successor() {
        let registry = SyntheticKdcRegistry::new();
        let jti = Uuid::new_v4();
        // Two fresh sessions under one JTI model a reconnect that re-derives its own material.
        let first = Arc::new(session(jti));
        let second = Arc::new(session(jti));

        let first_registration = registry.register(Arc::clone(&first));
        let second_registration = registry.register(Arc::clone(&second));

        // The reconnect supersedes the previous publication.
        assert!(Arc::ptr_eq(&registry.get(jti).expect("registered"), &second));

        // The superseded connection's late teardown must not evict the successor.
        drop(first_registration);
        assert!(Arc::ptr_eq(&registry.get(jti).expect("still registered"), &second));

        // Dropping the current registration retracts it.
        drop(second_registration);
        assert!(registry.get(jti).is_none());
    }

    #[test]
    fn intercept_ignores_non_loopback_host() {
        let result = session(Uuid::new_v4())
            .intercept_network_request(&network_request("http://kdc.real.example/path"))
            .expect("non-loopback request dispatches");
        assert!(matches!(result, SyntheticKdcInterception::NotInjectionRequest));
    }

    #[test]
    fn intercept_rejects_malformed_url_path() {
        let error = session(Uuid::new_v4())
            .intercept_network_request(&network_request("http://cred.invalid/not-a-uuid"))
            .expect_err("non-UUID path must fail");
        assert!(format!("{error:#}").contains("malformed in-process KDC URL"));
    }

    #[test]
    fn intercept_rejects_mismatched_jti() {
        let session = session(Uuid::new_v4());
        let error = session
            .intercept_network_request(&network_request(&format!("http://cred.invalid/{}", Uuid::new_v4())))
            .expect_err("JTI mismatch must fail");
        assert!(format!("{error:#}").contains("does not match current CredSSP session"));
    }

    #[test]
    fn intercept_accepts_matching_url_path_before_payload_decode() {
        let jti = Uuid::new_v4();
        let error = session(jti)
            .intercept_network_request(&network_request(&format!("http://cred.invalid/{jti}")))
            .expect_err("empty KDC payload must fail after URL/JTI validation");
        assert!(format!("{error:#}").contains("malformed in-process KDC proxy payload"));
    }

    #[test]
    fn realm_mismatch_reports_case_insensitively() {
        assert!(realm_mismatch("AD.EXAMPLE", "ad.example").is_none());
        let mismatch = realm_mismatch("cred.invalid", "evil.example").expect("different realms mismatch");
        assert_eq!(mismatch.expected, "cred.invalid");
        assert_eq!(mismatch.actual, "evil.example");
    }
}
