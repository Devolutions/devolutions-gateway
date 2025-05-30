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

pub fn build_server_config(cert_source: CertificateSource) -> anyhow::Result<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder().with_no_client_auth();

    match cert_source {
        CertificateSource::External {
            certificates,
            private_key,
        } => builder
            .with_single_cert(certificates, private_key)
            .context("failed to set server config cert"),

        #[cfg(windows)]
        CertificateSource::SystemStore {
            machine_hostname,
            cert_subject_name,
            store_location,
            store_name,
        } => {
            let resolver =
                windows::ServerCertResolver::new(machine_hostname, cert_subject_name, store_location, store_name)
                    .context("create ServerCertResolver")?;
            Ok(builder.with_cert_resolver(Arc::new(resolver)))
        }
        #[cfg(not(windows))]
        CertificateSource::SystemStore { .. } => {
            anyhow::bail!("System Certificate Store not supported for this platform")
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

    use crate::config::dto;

    const CACHE_DURATION: time::Duration = time::Duration::seconds(45);

    #[derive(Debug)]
    pub struct ServerCertResolver {
        machine_hostname: String,
        subject_name: String,
        store_type: CertStoreType,
        store_name: String,
        cached_key: Mutex<Option<KeyCache>>,
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
            })
        }

        fn resolve(&self, client_hello: ClientHello<'_>) -> anyhow::Result<Arc<CertifiedKey>> {
            use core::fmt::Write as _;

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

            let x509_date_now = picky::x509::date::UtcDate::from(now);

            // Initial processing and filtering of the available candidates.
            let mut contexts: Vec<CertHandleCtx> = contexts
                .into_iter()
                .enumerate()
                .filter_map(|(idx, ctx)| {
                    let not_after = match picky::x509::Cert::from_der(ctx.as_der()) {
                        Ok(cert) => {
                            let serial_number = cert.serial_number().0.iter().fold(
                                String::new(),
                                |mut acc, byte| {
                                    let _ = write!(acc, "{byte:X?}");
                                    acc
                                },
                            );
                            let subject = cert.subject_name();
                            let issuer = cert.issuer_name();
                            let not_before = cert.valid_not_before();
                            let not_after = cert.valid_not_after();

                            trace!(%idx, %serial_number, %subject, %issuer, %not_before, %not_after, "Parsed store certificate");

                            if x509_date_now < not_before {
                                debug!(
                                    %idx, %serial_number, %not_before, "Filtered out certificate based on not before validity date"
                                );
                                return None;
                            }

                            let has_server_auth_key_purpose = cert.extensions().iter().any(|ext| match ext.extn_value() {
                                picky::x509::extension::ExtensionView::ExtendedKeyUsage(eku) => eku.contains(picky::oids::kp_server_auth()),
                                _ => false,
                            });

                            if !has_server_auth_key_purpose {
                                debug!(
                                    %idx, %serial_number, "Filtered out certificate because it does not have the server auth extended usage"
                                );
                                return None;
                            }

                            not_after
                        }
                        Err(error) => {
                            debug!(%error, "Failed to parse store certificate number {idx}");
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
                .context("no usable certificate found in the system store")?;

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
    use tokio_rustls::rustls::{pki_types, DigitallySignedStruct, Error, SignatureScheme};

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
