//! TLS for the fake RDP server and the CredSSP client.

use std::sync::Arc;

use anyhow::Context as _;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;
use x509_cert::der::Decode as _;

pub(crate) fn tls_acceptor() -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let cert = CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).context("parse cert PEM")?;
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).context("parse key PEM")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("TLS server config")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

pub(crate) fn dangerous_tls_connector() -> tokio_rustls::TlsConnector {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

pub(crate) fn peer_public_key(tls: &tokio_rustls::client::TlsStream<TcpStream>) -> anyhow::Result<Vec<u8>> {
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("gateway TLS certificate missing")?;
    extract_public_key(cert)
}

pub(crate) fn server_public_key() -> anyhow::Result<Vec<u8>> {
    let cert = CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).context("parse mock RDP cert")?;
    extract_public_key(&cert)
}

fn extract_public_key(cert: &CertificateDer<'_>) -> anyhow::Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(cert.as_ref()).context("parse X509")?;
    let public_key = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .context("unaligned subject public key")?
        .to_owned();
    Ok(public_key)
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Self-signed certificate for localhost (valid for 100 years).
const CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUPRJa8i280unV3/kW6TE2fSUw8PwwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI1MTEyNTA5NDAzMFoYDzIxMjUx
MTAxMDk0MDMwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDHpBlyRgUx/V9cQGw/eqDFc6odxB2hvnbudi67LvEj
cNIWOU79R1e/NswME4oecqT9W05n4UyxkABfm2qjODO0nDf47W0DsgbEA87qE715
RWg8AtC529CZAazqTV3gqYyRMsCuVKzPVxgWa8rhPc7E6In1uDRak0lWKQPQSBbc
34nxMOVIusZNlkAEar8/aYPr/YWvdEqkobEvXp+g9WsuMaU913ecacWDjyWDkf80
pPPtf+uet7WMysKMhzGQtpbgilT8XCo8uTsgUbK+TMWvkF9bcxAQDnJsrZRL7Jfh
ofsFfQbTIvbvpn+4J4kmHN36BTohlNL8TX1jrU3cPA7dAgMBAAGjUzBRMB0GA1Ud
DgQWBBTT+m6dyc/c3mXF3JAsZr9OqUwgWTAfBgNVHSMEGDAWgBTT+m6dyc/c3mXF
3JAsZr9OqUwgWTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBB
i/yonZY3ztaeGElzD8xkI+rJ+daJ5WzdfKnzudJllg/Ht8m7wO5SdQnMt2T44gbH
05uekc1zXnXb7fJKqs3R6DacctG0nQ3acuI+IMtTaBbbAcf3PJJlo0Pap0ypVC0R
IUiUhJGFNi4cCBOvJqsly0d3T5xqOXU1Q5j3mIwRBY68+m9btwwuZWvASRADtCyZ
RpisBzS4a6jSeHXa4iG/VhskbiZkcnfHNTw7yNJJdv125y2zQkWWF9wlLbYwWr40
x9Ba6YbssOz6epATKhvt80yclO34AzUyimssvViIUpgFEyaPhZZTw46Q/6X3ixK4
/v4eYM0cCHN0h+rynSor
-----END CERTIFICATE-----"#;

/// Private key for the self-signed certificate.
const KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHpBlyRgUx/V9c
QGw/eqDFc6odxB2hvnbudi67LvEjcNIWOU79R1e/NswME4oecqT9W05n4UyxkABf
m2qjODO0nDf47W0DsgbEA87qE715RWg8AtC529CZAazqTV3gqYyRMsCuVKzPVxgW
a8rhPc7E6In1uDRak0lWKQPQSBbc34nxMOVIusZNlkAEar8/aYPr/YWvdEqkobEv
Xp+g9WsuMaU913ecacWDjyWDkf80pPPtf+uet7WMysKMhzGQtpbgilT8XCo8uTsg
UbK+TMWvkF9bcxAQDnJsrZRL7JfhofsFfQbTIvbvpn+4J4kmHN36BTohlNL8TX1j
rU3cPA7dAgMBAAECggEAKh7KK5zwTaq6atlAvWfe8anEk4EkC1MG/qq6k02FHMgZ
2wx+SNu7fKFQDaA1vNTNUJLqCOq05qWOHp3IsuURq6JmAMP/Aw+Vc9el2ScPC74E
Dt09MmlZKl77H3fxPYwoFx5RHrbIuvoSH/DgHgOPU2YIbWpOyWlXyLDgmBoNkM3N
fXYLXJONpStPHeQLhh7LcHO3CZgn6kycJyByEO2NtcchS5zITiJuwL+qR5/QIlvD
Yo7jdCjelJat38MZ9dE1us8xlIjQtsYF/acZZtcpYho+7ZpDCNcb+xF8KStKei+B
MMpWISsa+Zh9g7lPYTnG/i1dSMMT100XCEw8o4rBoQKBgQDnptz8acp7DB2wJH4L
c0xuw8IlrSl3BGUEj8H+RyFlpH3+//i6/fE9MrtF8b4FSYUp5AG4NVFGcRbwJVGW
jeL13YwIKMdXjmx8fDIylCgBB1tzBS9T/0ws3HS8avxhKvjgoXIZm6D3XDcBslrH
c9/LojT8YGI1wx7jWI2qKj8yeQKBgQDcn+kQ1QjzgIz6bAVWY3t1jr5uHHyaS+5G
ihY/mx4Mn3DURgPXZHz/HrN9rZkax0zuq9wuIlqgZ2KI37iCF49M4aZxC788LyDo
Hp0Cak3wt3g0Tj6J7SJiQe8h/6VBS4R5dRD2vhEc3xPAOf7WIFdlLYBOOvE/LmOt
N6ChkfgGhQKBgQDSiDqLRPJ7BjXtIh1T9sPeXxeR+mCXBG1yydx7ZtYZdHf2S1kZ
STX4cqT1GpGiaIEX41sUuZBWPu2j76bI98bvwRxFRhp1nsFGGfHdOf1pgfBBBtNO
udXXZ7zIiUs6XD24mcIDOAgBB9QOPLR4VP1uKsuRG1/mkKD/6jlGEANDsQKBgQDC
AoEygxQnBVFz2c/rwvnLS+Zb8AMGsGTtdPrRnjeThBX1JUi1fbGJq1bN2v27Fa2q
aEjr7NvjGGcG1C1tgQhL5Fa4LEtTwmHenSUW/aJiXwR+gpvuMDC/VRnTvPp2a9En
+XEcedGUoPq+XIGjjLctyxB8Osrw83tF1JgV3MXN/QKBgQC83B54rYDd4QmVH5nL
WLw834fgr+Z1hA6UqJIaahlD/bDwzbbJEv0pHCBxe01ywQFivqWBdVbuoy9YSeLS
KKEklzh+L0SorrYoBA5F63qx0zy05bba0ASplgDUEUNZn7oIFi7x5pVsNNaNxZpR
bQGM8UrNQvWQ+tutRmp7PM6VuQ==
-----END PRIVATE KEY-----"#;
