#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate tracing;

#[cfg(feature = "openapi")]
pub mod openapi;

pub mod config;
pub mod generic_client;
pub mod http;
pub mod interceptor;
pub mod jet;
pub mod jet_client;
pub mod jet_rendezvous_tcp_proxy;
pub mod jmux;
pub mod listener;
pub mod log;
pub mod plugin_manager;
pub mod preconnection_pdu;
pub mod proxy;
pub mod rdp;
pub mod rdp_extension;
pub mod registry;
pub mod service;
pub mod session;
pub mod subscriber;
pub mod tcp;
pub mod token;
pub mod transport;
pub mod utils;
pub mod websocket_client;

pub mod tls_sanity {
    use anyhow::Context as _;
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

    pub fn build_rustls_config(
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
}
