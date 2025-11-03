use std::io;
use std::sync::{Arc, LazyLock};

use anyhow::Context as _;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{self, pki_types};

static DEFAULT_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = rustls::crypto::ring::DEFAULT_CIPHER_SUITES;

// rustls doc says:
//
// > Making one of these can be expensive, and should be once per process rather than once per connection.
//
// source: https://docs.rs/rustls/0.21.1/rustls/client/struct.ClientConfig.html
//
// We’ll reuse the same TLS client config for all proxy-based TLS connections.
// (TlsConnector is just a wrapper around the config providing the `connect` method.)
static TLS_CONNECTOR: LazyLock<tokio_rustls::TlsConnector> = LazyLock::new(|| {
    let mut config = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();

    // Disable TLS resumption because it’s not supported by some services such as CredSSP.
    //
    // > The CredSSP Protocol does not extend the TLS wire protocol. TLS session resumption is not supported.
    //
    // source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c
    config.resumption = rustls::client::Resumption::disabled();

    tokio_rustls::TlsConnector::from(Arc::new(config))
});

pub async fn connect<IO>(dns_name: String, stream: IO) -> io::Result<TlsStream<IO>>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    let dns_name = pki_types::ServerName::try_from(dns_name).map_err(io::Error::other)?;

    let mut tls_stream = TLS_CONNECTOR.connect(dns_name, stream).await?;

    // > To keep it simple and correct, [TlsStream] will behave like `BufWriter`.
    // > For `TlsStream<TcpStream>`, this means that data written by `poll_write`
    // > is not guaranteed to be written to `TcpStream`.
    // > You must call `poll_flush` to ensure that it is written to `TcpStream`.
    //
    // source: https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
    tls_stream.flush().await?;

    Ok(tls_stream)
}

pub enum CertificateSource {
    External {
        certificates: Vec<pki_types::CertificateDer<'static>>,
        private_key: pki_types::PrivateKeyDer<'static>,
    },
    SystemStore {
        /// This field is only used to diagnostic potential configuration problems.
        machine_hostname: String,
        cert_subject_name: String,
        store_location: crate::config::dto::CertStoreLocation,
        store_name: String,
    },
}

pub fn build_server_config(
    cert_source: CertificateSource,
    strict_checks: bool,
) -> anyhow::Result<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder().with_no_client_auth();

    match cert_source {
        CertificateSource::External {
            certificates,
            private_key,
        } => {
            let first_certificate = certificates.first().context("empty certificate list")?;

            #[expect(clippy::similar_names)]
            if strict_checks
                && let Ok(report) = check_certificate_now(first_certificate)
                && report.issues.intersects(
                    CertIssues::MISSING_SERVER_AUTH_EXTENDED_KEY_USAGE | CertIssues::MISSING_SUBJECT_ALT_NAME,
                )
            {
                // Variable names issuer/issues are similar but accurately represent certificate fields.
                let serial_number = report.serial_number;
                let subject = report.subject;
                let issuer = report.issuer;
                let not_before = report.not_before;
                let not_after = report.not_after;
                let issues = report.issues;

                anyhow::bail!(
                    "found significant issues with the certificate: serial_number = {serial_number}, subject = {subject}, issuer = {issuer}, not_before = {not_before}, not_after = {not_after}, issues = {issues} (you can set `TlsVerifyStrict` to `false` in the gateway.json configuration file if that's intended)"
                );
            }

            builder
                .with_single_cert(certificates, private_key)
                .context("failed to set server config cert")
        }

        #[cfg(windows)]
        CertificateSource::SystemStore {
            machine_hostname,
            cert_subject_name,
            store_location,
            store_name,
        } => {
            let resolver = windows::ServerCertResolver::new(
                machine_hostname,
                cert_subject_name,
                store_location,
                store_name,
                strict_checks,
            )
            .context("create ServerCertResolver")?;
            Ok(builder.with_cert_resolver(Arc::new(resolver)))
        }
        #[cfg(not(windows))]
        CertificateSource::SystemStore { .. } => {
            anyhow::bail!("system certificate store not supported for this platform")
        }
    }
}

pub fn install_default_crypto_provider() {
    if rustls::crypto::ring::default_provider().install_default().is_err() {
        let installed_provider = rustls::crypto::CryptoProvider::get_default();
        debug!(?installed_provider, "default crypto provider is already installed");
    }
}

#[cfg(windows)]
pub mod windows {
    use std::sync::Arc;

    use anyhow::Context as _;
    use parking_lot::Mutex;
    use rustls_cng::signer::CngSigningKey;
    use rustls_cng::store::{CertStore, CertStoreType};
    use tokio_rustls::rustls::pki_types::CertificateDer;
    use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
    use tokio_rustls::rustls::sign::CertifiedKey;

    use crate::SYSTEM_LOGGER;
    use crate::config::dto;
    use crate::tls::{CertIssues, check_certificate};

    const CACHE_DURATION: time::Duration = time::Duration::seconds(45);

    #[derive(Debug)]
    pub struct ServerCertResolver {
        machine_hostname: String,
        subject_name: String,
        store_type: CertStoreType,
        store_name: String,
        cached_key: Mutex<Option<KeyCache>>,
        strict_checks: bool,
    }

    #[derive(Debug)]
    struct KeyCache {
        key: Arc<CertifiedKey>,
        expires_at: time::OffsetDateTime,
    }

    impl ServerCertResolver {
        pub fn new(
            machine_hostname: String,
            cert_subject_name: String,
            store_type: dto::CertStoreLocation,
            store_name: String,
            strict_checks: bool,
        ) -> anyhow::Result<Self> {
            let store_type = match store_type {
                dto::CertStoreLocation::LocalMachine => CertStoreType::LocalMachine,
                dto::CertStoreLocation::CurrentUser => CertStoreType::CurrentUser,
                dto::CertStoreLocation::CurrentService => CertStoreType::CurrentService,
            };

            Ok(Self {
                machine_hostname,
                subject_name: cert_subject_name,
                store_type,
                store_name,
                cached_key: Mutex::new(None),
                strict_checks,
            })
        }

        fn resolve(&self, client_hello: ClientHello<'_>) -> anyhow::Result<Arc<CertifiedKey>> {
            trace!(server_name = ?client_hello.server_name(), "Received ClientHello");

            let request_server_name = client_hello
                .server_name()
                .context("server name missing from ClientHello")?;

            // Sanity check.
            if !request_server_name.eq_ignore_ascii_case(&self.machine_hostname) {
                warn!(
                    request_server_name,
                    machine_hostname = self.machine_hostname,
                    "Requested server name does not match the hostname"
                );
            }

            // Sanity check.
            if !crate::utils::wildcard_host_match(&self.subject_name, request_server_name) {
                debug!(
                    request_server_name,
                    expected_server_name = self.subject_name,
                    "Subject name mismatch; not necessarily a problem if it is instead matched by an alternative subject name"
                )
            }

            let mut cache_guard = self.cached_key.lock();

            let now = time::OffsetDateTime::now_utc();

            if let Some(cache) = cache_guard.as_ref() {
                if now < cache.expires_at {
                    trace!("Used certified key from cache");
                    return Ok(Arc::clone(&cache.key));
                }
            }

            let store = CertStore::open(self.store_type, &self.store_name).context("open Windows certificate store")?;

            // Look up certificate by subject.
            let contexts = store.find_by_subject_str(&self.subject_name).with_context(|| {
                format!(
                    "failed to find server certificate for {} from system store",
                    self.subject_name
                )
            })?;

            anyhow::ensure!(
                !contexts.is_empty(),
                "no certificate found for `{}` in system store",
                self.subject_name
            );

            trace!(subject_name = %self.subject_name, count = contexts.len(), "Found certificate contexts");

            // We will accumulate all the certificate issues we observe next.
            let mut cert_issues = CertIssues::empty();

            // Initial processing and filtering of the available candidates.
            let mut contexts: Vec<CertHandleCtx> = contexts
                .into_iter()
                .enumerate()
                .filter_map(|(idx, ctx)| {
                    let not_after = match check_certificate(ctx.as_der(), now) {
                        Ok(report) => {
                            trace!(
                                %idx,
                                serial_number = %report.serial_number,
                                subject = %report.subject,
                                issuer = %report.issuer,
                                not_before = %report.not_before,
                                not_after = %report.not_after,
                                issues = %report.issues,
                                "Parsed store certificate"
                            );

                            // Accumulate the issues found.
                            cert_issues |= report.issues;

                            // Skip the certificate if any of the following is true:
                            // - the certificate is not yet valid,
                            // - (if strict) the certificate is missing the server auth extended key usage,
                            // - (if strict) the certificate is missing a subject alternative name (SAN) extension.
                            let issues_to_check = if self.strict_checks {
                                CertIssues::NOT_YET_VALID
                                    | CertIssues::MISSING_SERVER_AUTH_EXTENDED_KEY_USAGE
                                    | CertIssues::MISSING_SUBJECT_ALT_NAME
                            } else {
                                CertIssues::NOT_YET_VALID
                            };

                            let skip = report.issues.intersects(issues_to_check);

                            if skip {
                                debug!(
                                    %idx,
                                    serial_number = %report.serial_number,
                                    issues = %report.issues,
                                    "Filtered out certificate because it has significant issues"
                                );
                                let _ = SYSTEM_LOGGER.emit(
                                    sysevent_codes::tls_certificate_rejected(
                                        report.subject,
                                        report.issues.iter_names().next().expect("at least one issue").0,
                                    )
                                    .severity(sysevent::Severity::Notice),
                                );
                                return None;
                            }

                            report.not_after
                        }
                        Err(error) => {
                            debug!(%idx, %error, "Failed to check store certificate");
                            picky::x509::date::UtcDate::ymd(1900, 1, 1).expect("hardcoded")
                        }
                    };

                    Some(CertHandleCtx {
                        idx,
                        handle: ctx,
                        not_after,
                    })
                })
                .collect();

            // Sort certificates from the farthest to the earliest expiration
            // time. Note that it appears the certificates are already returned
            // in this order, but it is not a documented behavior. It really
            // depends on the internal order maintained by the store, and there
            // is no guarantee about what this order is, thus we implement the
            // logic here anyway.
            contexts.sort_by(|a, b| b.not_after.cmp(&a.not_after));

            if enabled!(tracing::Level::TRACE) {
                contexts.iter().enumerate().for_each(|(sorted_idx, ctx)| trace!(%sorted_idx, idx = %ctx.idx, not_after = %ctx.not_after, "Sorted certificate"));
            }

            // Attempt to acquire a private key and construct CngSigningKey.
            let (context, key) = contexts
                .into_iter()
                .find_map(|ctx| {
                    let key = ctx
                        .handle
                        .acquire_key()
                        .inspect_err(|error| debug!(idx = %ctx.idx, %error, "Failed to acquire key for certificate"))
                        .ok()?;
                    CngSigningKey::new(key)
                        .inspect_err(|error| debug!(idx = %ctx.idx, %error, "CngSigningKey::new failed"))
                        .ok()
                        .map(|key| (ctx, key))
                })
                .with_context(|| {
                    format!("no usable certificate found in the system store; observed issues: {cert_issues}")
                })
                .inspect_err(|error| {
                    let _ = SYSTEM_LOGGER.emit(sysevent_codes::tls_no_suitable_certificate(error, cert_issues));
                })?;

            trace!(idx = context.idx, not_after = %context.not_after, key_algorithm_group = ?key.key().algorithm_group(), key_algorithm = ?key.key().algorithm(), "Selected certificate");

            // Attempt to acquire a full certificate chain.
            let chain = context
                .handle
                .as_chain_der()
                .context("certification chain is not available for this certificate")?;
            let certs = chain.into_iter().map(CertificateDer::from).collect();

            let key = Arc::new(CertifiedKey {
                cert: certs,
                key: Arc::new(key),
                ocsp: None,
            });

            *cache_guard = Some(KeyCache {
                key: key.clone(),
                expires_at: now + CACHE_DURATION,
            });
            trace!("Cached certified key");

            // Return CertifiedKey instance.
            return Ok(key);

            struct CertHandleCtx {
                idx: usize,
                handle: rustls_cng::cert::CertContext,
                not_after: picky::x509::date::UtcDate,
            }
        }
    }

    impl ResolvesServerCert for ServerCertResolver {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            match self.resolve(client_hello) {
                Ok(certified_key) => Some(certified_key),
                Err(error) => {
                    error!(error = format!("{error:#?}"), "Failed to resolve TLS certificate");
                    None
                }
            }
        }
    }
}

pub struct CertReport {
    pub serial_number: String,
    pub subject: picky::x509::name::DirectoryName,
    pub issuer: picky::x509::name::DirectoryName,
    pub not_before: picky::x509::date::UtcDate,
    pub not_after: picky::x509::date::UtcDate,
    pub issues: CertIssues,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CertIssues: u8 {
        const NOT_YET_VALID = 0b00000001;
        const EXPIRED = 0b00000010;
        const MISSING_SERVER_AUTH_EXTENDED_KEY_USAGE = 0b00000100;
        const MISSING_SUBJECT_ALT_NAME = 0b00001000;
    }
}

impl core::fmt::Display for CertIssues {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

pub fn check_certificate_now(cert: &[u8]) -> anyhow::Result<CertReport> {
    check_certificate(cert, time::OffsetDateTime::now_utc())
}

#[allow(clippy::similar_names)]
pub fn check_certificate(cert: &[u8], at: time::OffsetDateTime) -> anyhow::Result<CertReport> {
    use anyhow::Context as _;
    use core::fmt::Write as _;

    let cert = picky::x509::Cert::from_der(cert).context("failed to parse certificate")?;
    let at = picky::x509::date::UtcDate::from(at);

    let mut issues = CertIssues::empty();

    let serial_number = cert.serial_number().0.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:X?}");
        acc
    });
    let subject = cert.subject_name();
    let issuer = cert.issuer_name();
    let not_before = cert.valid_not_before();
    let not_after = cert.valid_not_after();

    if at < not_before {
        issues.insert(CertIssues::NOT_YET_VALID);
    } else if not_after < at {
        issues.insert(CertIssues::EXPIRED);
    }

    let mut has_server_auth_key_purpose = false;
    let mut has_san = false;

    for ext in cert.extensions() {
        match ext.extn_value() {
            picky::x509::extension::ExtensionView::ExtendedKeyUsage(eku)
                if eku.contains(picky::oids::kp_server_auth()) =>
            {
                has_server_auth_key_purpose = true;
            }
            picky::x509::extension::ExtensionView::SubjectAltName(_) => has_san = true,
            _ => {}
        }
    }

    if !has_server_auth_key_purpose {
        issues.insert(CertIssues::MISSING_SERVER_AUTH_EXTENDED_KEY_USAGE);
    }

    if !has_san {
        issues.insert(CertIssues::MISSING_SUBJECT_ALT_NAME);
    }

    Ok(CertReport {
        serial_number,
        subject,
        issuer,
        not_before,
        not_after,
        issues,
    })
}

pub mod sanity {
    use tokio_rustls::rustls;

    macro_rules! check_cipher_suite {
        ( $name:ident ) => {{
            if !crate::tls::DEFAULT_CIPHER_SUITES.contains(&rustls::crypto::ring::cipher_suite::$name) {
                anyhow::bail!(concat!(stringify!($name), " cipher suite is missing from default array"));
            }
        }};
        ( $( $name:ident ),+ $(,)? ) => {{
            $( check_cipher_suite!($name); )+
        }};
    }

    macro_rules! check_protocol_version {
        ( $name:ident ) => {{
            if !rustls::DEFAULT_VERSIONS.contains(&&rustls::version::$name) {
                anyhow::bail!(concat!("protocol ", stringify!($name), " is missing from default array"));
            }
        }};
        ( $( $name:ident ),+ $(,)? ) => {{
            $( check_protocol_version!($name); )+
        }};
    }

    pub fn check_default_configuration() -> anyhow::Result<()> {
        trace!("TLS cipher suites: {:?}", crate::tls::DEFAULT_CIPHER_SUITES);
        trace!("TLS protocol versions: {:?}", rustls::DEFAULT_VERSIONS);

        // Make sure we have a few TLS 1.2 cipher suites in our build.
        // Compilation will fail if one of these is missing.
        // Additionally, this function will returns an error if any one of these is not in the
        // default cipher suites array.
        check_cipher_suite![
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ];

        // Same idea, but with TLS protocol versions
        check_protocol_version![TLS12, TLS13];

        Ok(())
    }
}

pub mod danger {
    use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme, pki_types};

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}
