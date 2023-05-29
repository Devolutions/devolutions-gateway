use std::io;
use std::sync::Arc;

use anyhow::Context as _;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls;

lazy_static::lazy_static! {
    // rustls doc says:
    //
    // > Making one of these can be expensive, and should be once per process rather than once per connection.
    //
    // source: https://docs.rs/rustls/0.21.1/rustls/client/struct.ClientConfig.html
    //
    // We’ll reuse the same TLS client config for all proxy-based TLS connections.
    // (TlsConnector is just a wrapper around the config providing the `connect` method.)
    static ref TLS_CONNECTOR: tokio_rustls::TlsConnector = {
        let mut tls_client_config = rustls::client::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
            .with_no_client_auth();

        // Disable TLS resumption because it’s not supported by some services such as CredSSP.
        //
        // > The CredSSP Protocol does not extend the TLS wire protocol. TLS session resumption is not supported.
        //
        // source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c
        tls_client_config.resumption = tokio_rustls::rustls::client::Resumption::disabled();

        tokio_rustls::TlsConnector::from(Arc::new(tls_client_config))
    };
}

pub async fn connect(dns_name: &str, stream: TcpStream) -> io::Result<TlsStream<TcpStream>> {
    use tokio::io::AsyncWriteExt as _;

    let dns_name = dns_name
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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

pub fn build_server_config(
    certificates: Vec<rustls::Certificate>,
    private_key: rustls::PrivateKey,
) -> anyhow::Result<rustls::ServerConfig> {
    rustls::ServerConfig::builder()
        .with_cipher_suites(rustls::DEFAULT_CIPHER_SUITES) // = with_safe_default_cipher_suites, but explicit, just to show we are using rustls's default cipher suites
        .with_safe_default_kx_groups()
        .with_protocol_versions(rustls::DEFAULT_VERSIONS) // = with_safe_default_protocol_versions, but explicit as well
        .context("couldn't set supported TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("couldn't set server config cert")
}

pub mod sanity {
    use tokio_rustls::rustls;

    macro_rules! check_cipher_suite {
        ( $name:ident ) => {{
            if !rustls::DEFAULT_CIPHER_SUITES.contains(&rustls::cipher_suite::$name) {
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
        trace!("TLS cipher suites: {:?}", rustls::DEFAULT_CIPHER_SUITES);
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

mod danger {
    use tokio_rustls::rustls;

    pub(super) struct NoCertificateVerification;

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}