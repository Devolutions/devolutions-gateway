use std::collections::HashMap;
use std::io;
use std::sync::{Arc, LazyLock};

use anyhow::Context as _;
use parking_lot::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{self, pki_types};
use x509_cert::der::Decode as _;

static DEFAULT_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = rustls::crypto::ring::DEFAULT_CIPHER_SUITES;

// rustls doc says:
//
// > Making one of these can be expensive, and should be once per process rather than once per connection.
//
// source: https://docs.rs/rustls/0.21.1/rustls/client/struct.ClientConfig.html
//
// We’ll reuse the same TLS client config for all proxy-based TLS connections.
// (TlsConnector is just a wrapper around the config providing the `connect` method.)
static DANGEROUS_TLS_CONNECTOR: LazyLock<tokio_rustls::TlsConnector> = LazyLock::new(|| {
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

static NATIVE_ROOTS_VERIFIER: LazyLock<Arc<NativeRootsVerifier>> =
    LazyLock::new(|| Arc::new(NativeRootsVerifier::new()));

static SAFE_TLS_CONNECTOR: LazyLock<tokio_rustls::TlsConnector> = LazyLock::new(|| {
    let mut config = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(NATIVE_ROOTS_VERIFIER.clone())
        .with_no_client_auth();

    config.resumption = rustls::client::Resumption::disabled();

    tokio_rustls::TlsConnector::from(Arc::new(config))
});

// Cache for thumbprint-anchored TLS connectors to avoid recreating them for each connection.
// The rustls documentation recommends creating ClientConfig once per process rather than per connection.
static THUMBPRINT_ANCHORED_CONNECTORS: LazyLock<
    Mutex<HashMap<thumbprint::Sha256Thumbprint, tokio_rustls::TlsConnector>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub async fn dangerous_connect<IO>(dns_name: String, stream: IO) -> io::Result<TlsStream<IO>>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    let dns_name = pki_types::ServerName::try_from(dns_name).map_err(io::Error::other)?;

    let mut tls_stream = DANGEROUS_TLS_CONNECTOR.connect(dns_name, stream).await?;

    // > To keep it simple and correct, [TlsStream] will behave like `BufWriter`.
    // > For `TlsStream<TcpStream>`, this means that data written by `poll_write`
    // > is not guaranteed to be written to `TcpStream`.
    // > You must call `poll_flush` to ensure that it is written to `TcpStream`.
    //
    // source: https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
    tls_stream.flush().await?;

    Ok(tls_stream)
}

/// Connect to a TLS server with optional certificate thumbprint anchoring.
///
/// # Thumbprint Anchoring Behavior
///
/// When `cert_thumb256` is provided:
/// - If thumbprint matches: Accept immediately, bypassing ALL certificate checks (expiration, key usage, trust chain)
/// - If thumbprint doesn't match: Fall back to standard TLS verification
///
/// This is an escape hatch for certificate issues, NOT for long-term use.
pub async fn safe_connect<IO>(
    dns_name: String,
    stream: IO,
    cert_thumb256: Option<thumbprint::Sha256Thumbprint>,
) -> io::Result<TlsStream<IO>>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    let server_name = pki_types::ServerName::try_from(dns_name.clone()).map_err(io::Error::other)?;

    // Get the appropriate connector, using cache for thumbprint-anchored ones.
    let connector = if let Some(thumbprint) = cert_thumb256 {
        // Check the cache first.
        let mut cache = THUMBPRINT_ANCHORED_CONNECTORS.lock();

        // Clone existing connector or create and cache a new one.
        cache
            .entry(thumbprint.clone())
            .or_insert_with(|| {
                debug!(%thumbprint, "Creating new thumbprint-anchored TLS connector");

                let verifier = Arc::new(ThumbprintAnchoredVerifier::new(thumbprint));

                let mut config = rustls::client::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth();

                config.resumption = rustls::client::Resumption::disabled();

                tokio_rustls::TlsConnector::from(Arc::new(config))
            })
            .clone()
    } else {
        SAFE_TLS_CONNECTOR.clone()
    };

    let mut tls_stream = connector.connect(server_name, stream).await?;

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

            if strict_checks
                && let Ok(report) = check_certificate_now(first_certificate)
                && report.cert_issues.intersects(
                    CertIssues::MISSING_SERVER_AUTH_EXTENDED_KEY_USAGE | CertIssues::MISSING_SUBJECT_ALT_NAME,
                )
            {
                let serial_number = report.serial_number;
                let subject = report.subject;
                let issuer = report.issuer;
                let not_before = report.not_before;
                let not_after = report.not_after;
                let cert_issues = report.cert_issues;

                anyhow::bail!(
                    "found significant issues with the certificate: serial_number = {serial_number}, subject = {subject}, issuer = {issuer}, not_before = {not_before}, not_after = {not_after}, issues = {cert_issues} (you can set `TlsVerifyStrict` to `false` in the gateway.json configuration file if that's intended)"
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

/// Retrieves the TLS server public key from the given acceptor, with per-acceptor caching.
///
/// This function extracts the public key from the server certificate presented by the provided
/// `TlsAcceptor` via an internal loopback TLS handshake. Results are cached per unique acceptor
/// configuration to avoid redundant handshakes.
///
/// # Caching Strategy
///
/// - Each unique `TlsAcceptor` configuration (identified by its underlying `ServerConfig` pointer address)
///   maintains a separate cache entry.
/// - Cache entries expire after `LIFETIME_SECS` seconds to handle certificate rotation.
/// - This ensures that different acceptors (e.g., with different certificates) maintain independent caches.
///
/// # Arguments
///
/// * `hostname` - The hostname to use for the internal TLS connection (typically the gateway's hostname).
/// * `acceptor` - The TLS acceptor whose server certificate public key will be extracted.
///
/// # Returns
///
/// The DER-encoded public key bytes from the server certificate's SubjectPublicKeyInfo.
pub async fn get_cert_chain_for_acceptor_cached(
    hostname: String,
    acceptor: tokio_rustls::TlsAcceptor,
) -> anyhow::Result<Vec<pki_types::CertificateDer<'static>>> {
    const LIFETIME_SECS: i64 = 300;

    // Cache is keyed by the address of the acceptor's underlying ServerConfig Arc.
    // This ensures each unique acceptor configuration has its own cache entry.
    static CACHE: LazyLock<tokio::sync::Mutex<HashMap<usize, Cache>>> =
        LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // Derive a unique cache key from the acceptor's config pointer address.
    let cache_key = Arc::as_ptr(acceptor.config()).addr();

    let mut cache_map = CACHE.lock().await;

    // Check if we have a valid cached entry for this acceptor.
    if let Some(cache_entry) = cache_map.get(&cache_key)
        && now < cache_entry.update_timestamp + LIFETIME_SECS
    {
        return Ok(cache_entry.cert_chain.clone());
    }

    // Cache miss or expired; retrieve the public key via TLS handshake.
    let cert_chain = retrieve_gateway_cert_chain(hostname, acceptor).await?;

    // Update the cache for this acceptor.
    cache_map.insert(
        cache_key,
        Cache {
            cert_chain: cert_chain.clone(),
            update_timestamp: now,
        },
    );

    return Ok(cert_chain);

    struct Cache {
        cert_chain: Vec<pki_types::CertificateDer<'static>>,
        update_timestamp: i64,
    }

    async fn retrieve_gateway_cert_chain(
        hostname: String,
        acceptor: tokio_rustls::TlsAcceptor,
    ) -> anyhow::Result<Vec<pki_types::CertificateDer<'static>>> {
        let (client_side, server_side) = tokio::io::duplex(4096);

        let connect_fut = dangerous_connect(hostname, client_side);
        let accept_fut = acceptor.accept(server_side);

        let (connect_res, _) = tokio::join!(connect_fut, accept_fut);

        let tls_stream = connect_res.context("connect")?;

        let cert_chain = tls_stream
            .get_peer_certificates()
            .context("extract Devolutions Gateway TLS certificate chain")?
            .to_vec();

        Ok(cert_chain)
    }
}

pub(crate) trait GetPeerCerts {
    fn get_peer_certificates(&self) -> Option<&[pki_types::CertificateDer<'static>]>;
}

impl<S> GetPeerCerts for TlsStream<S> {
    fn get_peer_certificates(&self) -> Option<&[pki_types::CertificateDer<'static>]> {
        self.get_ref().1.peer_certificates()
    }
}

impl<S> GetPeerCerts for tokio_rustls::server::TlsStream<S> {
    fn get_peer_certificates(&self) -> Option<&[pki_types::CertificateDer<'static>]> {
        self.get_ref().1.peer_certificates()
    }
}

pub(crate) fn extract_stream_peer_public_key(tls_stream: &impl GetPeerCerts) -> anyhow::Result<Vec<u8>> {
    let cert = tls_stream
        .get_peer_certificates()
        .and_then(|certs| certs.first())
        .context("certificate is missing")?;

    extract_public_key(cert)
}

pub(crate) fn extract_public_key(cert: &pki_types::CertificateDer<'static>) -> anyhow::Result<Vec<u8>> {
    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert).context("parse X509 certificate")?;

    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("subject public key BIT STRING is not aligned")?
        .to_owned();

    Ok(public_key)
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
            use std::fmt::Write as _;

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

            if let Some(cache) = cache_guard.as_ref()
                && now < cache.expires_at
            {
                trace!("Used certified key from cache");
                return Ok(Arc::clone(&cache.key));
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
                                issues = %report.cert_issues,
                                "Parsed store certificate"
                            );

                            // Accumulate the issues found.
                            cert_issues |= report.cert_issues;

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

                            let skip = report.cert_issues.intersects(issues_to_check);

                            if skip {
                                debug!(
                                    %idx,
                                    serial_number = %report.serial_number,
                                    issues = %report.cert_issues,
                                    "Filtered out certificate because it has significant issues"
                                );
                                let _ = SYSTEM_LOGGER.emit(
                                    sysevent_codes::tls_certificate_rejected(
                                        report.subject,
                                        report.cert_issues.iter_names().next().expect("at least one issue").0,
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
            // We accumulate errors encountered during key acquisition to provide detailed diagnostics.
            let mut key_acquisition_errors = Vec::new();

            let (context, key) = contexts
                .into_iter()
                .find_map(|ctx| {
                    let key = ctx
                        .handle
                        .acquire_key()
                        .inspect_err(|error| {
                            debug!(idx = %ctx.idx, %error, "Failed to acquire key for certificate");
                            key_acquisition_errors.push(format!("cert[{}]: failed to acquire key: {error:#}", ctx.idx));
                        })
                        .ok()?;

                    CngSigningKey::new(key)
                        .inspect_err(|error| {
                            debug!(idx = %ctx.idx, %error, "CngSigningKey::new failed");
                            key_acquisition_errors
                                .push(format!("cert[{}]: failed to create signing key: {error:#}", ctx.idx));
                        })
                        .ok()
                        .map(|key| (ctx, key))
                })
                .with_context(|| {
                    let mut error_msg = "no usable certificate found in the system store".to_owned();

                    if !cert_issues.is_empty() {
                        let _ = write!(error_msg, "; observed issues: {cert_issues}");
                    }

                    if !key_acquisition_errors.is_empty() {
                        let _ = write!(
                            error_msg,
                            "; key acquisition failures: {}",
                            key_acquisition_errors.join(", ")
                        );
                    }

                    error_msg
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
                key: Arc::clone(&key),
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
    pub cert_issues: CertIssues,
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

pub fn check_certificate(cert: &[u8], at: time::OffsetDateTime) -> anyhow::Result<CertReport> {
    use core::fmt::Write as _;

    use anyhow::Context as _;

    let cert = picky::x509::Cert::from_der(cert).context("failed to parse certificate")?;
    let at = picky::x509::date::UtcDate::from(at);

    let mut cert_issues = CertIssues::empty();

    let serial_number = cert.serial_number().0.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:X?}");
        acc
    });
    let subject = cert.subject_name();
    let issuer = cert.issuer_name();
    let not_before = cert.valid_not_before();
    let not_after = cert.valid_not_after();

    if at < not_before {
        cert_issues.insert(CertIssues::NOT_YET_VALID);
    } else if not_after < at {
        cert_issues.insert(CertIssues::EXPIRED);
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
        cert_issues.insert(CertIssues::MISSING_SERVER_AUTH_EXTENDED_KEY_USAGE);
    }

    if !has_san {
        cert_issues.insert(CertIssues::MISSING_SUBJECT_ALT_NAME);
    }

    Ok(CertReport {
        serial_number,
        subject,
        issuer,
        not_before,
        not_after,
        cert_issues,
    })
}

/// Standard certificate verifier using native roots based on the [`WebPkiServerVerifier`].
///
/// This verifier attempts normal TLS verification using system roots.
/// If verification fails, certificate details are logged.
#[derive(Debug)]
pub struct NativeRootsVerifier {
    inner: rustls::client::WebPkiServerVerifier,
}

impl NativeRootsVerifier {
    pub fn new() -> Self {
        // Create a standard verifier using platform native certificate store.
        let mut root_store = rustls::RootCertStore::empty();

        // Load certificates from the platform native certificate store.
        let result = rustls_native_certs::load_native_certs();

        for error in result.errors {
            warn!(error = %error, "Error when loading native certificate");
        }

        let mut added_count = 0;

        for cert in result.certs {
            if root_store.add(cert).is_ok() {
                added_count += 1;
            }
        }

        if added_count == 0 {
            warn!("No valid certificates found in platform native certificate store");
        } else {
            debug!(count = added_count, "Loaded native certificates");
        }

        let webpki_server_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .expect("failed to build WebPkiServerVerifier; this should not fail");

        Self {
            inner: Arc::into_inner(webpki_server_verifier).expect("exactly one strong reference at this point"),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for NativeRootsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        intermediates: &[pki_types::CertificateDer<'_>],
        server_name: &pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Ok(verified) => Ok(verified),
            Err(verification_error) => {
                // Compute SHA-256 thumbprint of the certificate.
                let thumbprint = thumbprint::compute_sha256_thumbprint(end_entity);

                // Extract certificate details.
                let cert_info = extract_cert_info(end_entity);

                error!(
                    cert_subject = %cert_info.subject,
                    cert_issuer = %cert_info.issuer,
                    not_before = %cert_info.not_before,
                    not_after = %cert_info.not_after,
                    san = %cert_info.sans,
                    reason = %verification_error,
                    sha256_thumb = %thumbprint,
                    hint = "PASTE_THIS_THUMBPRINT_IN_RDM_CONNECTION",
                    "Invalid peer certificate"
                );

                Err(verification_error)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

impl Default for NativeRootsVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Certificate verifier that supports thumbprint anchoring.
///
/// This verifier accepts the certificate if the provided thumbprint matches the leaf certificate,
/// otherwise normal TLS verification using system roots is performed.
///
/// ## Security Warning
///
/// When thumbprint matches, this bypasses ALL standard TLS verification:
/// - Certificate expiration dates are NOT checked
/// - Key usage extensions are NOT validated
/// - Certificate chain trust is NOT verified
/// - Hostname matching is NOT performed
///
/// This is an **escape hatch** for users with certificate issues, NOT a long-term solution.
/// Users should resolve certificate problems and remove thumbprint configuration ASAP.
#[derive(Debug)]
pub struct ThumbprintAnchoredVerifier {
    expected_thumbprint: thumbprint::Sha256Thumbprint,
}

impl ThumbprintAnchoredVerifier {
    pub fn new(expected_thumbprint: thumbprint::Sha256Thumbprint) -> Self {
        Self { expected_thumbprint }
    }
}

impl rustls::client::danger::ServerCertVerifier for ThumbprintAnchoredVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        intermediates: &[pki_types::CertificateDer<'_>],
        server_name: &pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Compute SHA-256 thumbprint of the certificate.
        let actual_thumbprint = thumbprint::compute_sha256_thumbprint(end_entity);

        // Thumbprint matches, accept immediately.
        // SECURITY: This bypasses ALL certificate validation checks when thumbprint matches.
        // No validation of: expiration, key usage, hostname, or trust chain.
        if actual_thumbprint == self.expected_thumbprint {
            info!(
                sha256_thumb = %actual_thumbprint,
                "Accepting TLS connection via certificate thumbprint anchor (bypassing standard validation)"
            );

            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // Otherwise, try the normal verification.
        NATIVE_ROOTS_VERIFIER.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        NATIVE_ROOTS_VERIFIER.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        NATIVE_ROOTS_VERIFIER.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        NATIVE_ROOTS_VERIFIER.supported_verify_schemes()
    }
}

struct CertInfo {
    subject: String,
    issuer: String,
    not_before: x509_cert::time::Time,
    not_after: x509_cert::time::Time,
    sans: String,
}

fn extract_cert_info(cert_der: &[u8]) -> CertInfo {
    use std::fmt::Write as _;

    use bytes::Buf as _;

    match x509_cert::Certificate::from_der(cert_der) {
        Ok(cert) => {
            let subject = cert.tbs_certificate.subject.to_string();
            let issuer = cert.tbs_certificate.issuer.to_string();
            let not_before = cert.tbs_certificate.validity.not_before;
            let not_after = cert.tbs_certificate.validity.not_after;

            let mut sans = String::new();
            let mut first = true;

            if let Some(extensions) = cert.tbs_certificate.extensions {
                for ext in extensions {
                    if let Ok(san) = x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                        for name in san.0 {
                            if first {
                                first = false;
                            } else {
                                let _ = write!(sans, ",");
                            }

                            match name {
                                x509_cert::ext::pkix::name::GeneralName::OtherName(other_name) => {
                                    let _ = write!(sans, "{}", other_name.type_id);
                                }
                                x509_cert::ext::pkix::name::GeneralName::Rfc822Name(name) => {
                                    let _ = write!(sans, "{}", name.as_str());
                                }
                                x509_cert::ext::pkix::name::GeneralName::DnsName(name) => {
                                    let _ = write!(sans, "{}", name.as_str());
                                }
                                x509_cert::ext::pkix::name::GeneralName::DirectoryName(rdn_sequence) => {
                                    let _ = write!(sans, "{rdn_sequence}");
                                }
                                x509_cert::ext::pkix::name::GeneralName::EdiPartyName(_) => {
                                    let _ = write!(sans, "<EDI Party Name>");
                                }
                                x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) => {
                                    let _ = write!(sans, "{}", uri.as_str());
                                }
                                x509_cert::ext::pkix::name::GeneralName::IpAddress(octet_string) => {
                                    if let Ok(ip) = octet_string.as_bytes().try_get_u128() {
                                        let ip = std::net::Ipv6Addr::from_bits(ip);
                                        let _ = write!(sans, "{ip}");
                                    } else if let Ok(ip) = octet_string.as_bytes().try_get_u32() {
                                        let ip = std::net::Ipv4Addr::from_bits(ip);
                                        let _ = write!(sans, "{ip}");
                                    } else {
                                        let _ = write!(sans, "<IP Address>");
                                    }
                                }
                                x509_cert::ext::pkix::name::GeneralName::RegisteredId(object_identifier) => {
                                    let _ = write!(sans, "{object_identifier}");
                                }
                            }
                        }
                    }
                }
            }

            CertInfo {
                subject,
                issuer,
                not_before,
                not_after,
                sans,
            }
        }
        Err(_) => CertInfo {
            subject: "<parse error>".to_owned(),
            issuer: "<parse error>".to_owned(),
            not_before: x509_cert::time::Time::INFINITY,
            not_after: x509_cert::time::Time::INFINITY,
            sans: "<parse error>".to_owned(),
        },
    }
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

pub mod thumbprint {
    use core::fmt;

    // SHA-256 thumbprint should be exactly 64 hex characters (32 bytes).
    const EXPECTED_SHA256_LENGTH: usize = 64;

    /// Normalized SHA-256 Thumbprint.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Sha256Thumbprint(
        /// INVARIANT: 64-character, lowercased hex with no separator.
        String,
    );

    impl fmt::Display for Sha256Thumbprint {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }

    impl Sha256Thumbprint {
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error(
        "certificate thumbprint has unexpected length: expected {EXPECTED_SHA256_LENGTH} hex characters (SHA-256), got {actual_length}; \
         this may indicate a SHA-1 thumbprint (40 chars) or incorrect format"
    )]
    pub struct ThumbprintLengthError {
        actual_length: usize,
    }

    /// Normalize thumbprint to lowercase hex with no separators.
    ///
    /// Validates that the resulting thumbprint has the expected length for SHA-256 (64 hex chars).
    pub fn normalize_sha256_thumbprint(thumb: &str) -> Result<Sha256Thumbprint, ThumbprintLengthError> {
        let normalized = thumb
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|mut c| {
                c.make_ascii_lowercase();
                c
            })
            .collect::<String>();

        if normalized.len() != EXPECTED_SHA256_LENGTH {
            return Err(ThumbprintLengthError {
                actual_length: normalized.len(),
            });
        }

        Ok(Sha256Thumbprint(normalized))
    }

    /// Compute SHA-256 thumbprint of certificate DER bytes.
    pub fn compute_sha256_thumbprint(cert_der: &[u8]) -> Sha256Thumbprint {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(cert_der);
        Sha256Thumbprint(hex::encode(hash))
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, reason = "allowed in tests")]

        use rstest::rstest;

        use super::*;

        #[rstest]
        #[case("3a7fb2c45e8d9f1a2b3c4d5e6f7a8b9cadbecfd0e1f2031425364758697a8b9c")]
        #[case("3A7FB2C45E8D9F1A2B3C4D5E6F7A8B9CADBECFD0E1F2031425364758697A8B9C")]
        #[case("3a7Fb2C45E8d9f1a2b3c4D5E6f7a8b9CAdbecfd0E1f2031425364758697A8b9c")]
        #[case("3A 7F B2 C4 5E 8D 9F 1A 2B 3C 4D 5E 6F 7A 8B 9C AD BE CF D0 E1 F2 03 14 25 36 47 58 69 7A 8B 9C")]
        #[case("3A:7F:B2:C4:5E:8D:9F:1A:2B:3C:4D:5E:6F:7A:8B:9C:AD:BE:CF:D0:E1:F2:03:14:25:36:47:58:69:7A:8B:9C")]
        #[case("3a:7F-B2.C4_5E:8d:9f_1a-2b:3c-4d.5e:6f:7a:8b:9c.ad:be:cf:d0.e1:f2:03:14:25-36-47-58_69-7A:8B:9C")]
        fn test_normalize_thumbprint(#[case] input: &str) {
            assert_eq!(
                normalize_sha256_thumbprint(input).unwrap().as_str(),
                "3a7fb2c45e8d9f1a2b3c4d5e6f7a8b9cadbecfd0e1f2031425364758697a8b9c"
            );
        }

        #[test]
        fn test_compute_sha256_thumbprint() {
            // Test with known input.
            let test_data = b"Hello, World!";
            let thumbprint = compute_sha256_thumbprint(test_data);

            // Expected SHA-256 of "Hello, World!".
            let expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
            assert_eq!(thumbprint.as_str(), expected);

            // Test output format (lowercase hex, no separators).
            assert!(
                thumbprint
                    .as_str()
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
            assert_eq!(thumbprint.as_str().len(), 64); // SHA-256 is 32 bytes = 64 hex chars.
        }

        #[test]
        fn test_compute_sha256_thumbprint_deterministic() {
            // Same input should always produce same thumbprint.
            let test_data = b"test certificate data";
            let thumbprint1 = compute_sha256_thumbprint(test_data);
            let thumbprint2 = compute_sha256_thumbprint(test_data);
            assert_eq!(thumbprint1, thumbprint2);
        }
    }
}
