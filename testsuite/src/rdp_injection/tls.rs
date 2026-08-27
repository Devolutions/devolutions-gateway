//! TLS plumbing for the fake RDP server and the test client.

use std::sync::Arc;

use anyhow::Context as _;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;
use x509_cert::der::Decode as _;

use crate::tls_fixtures::{CERT_PEM, KEY_PEM};

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn tls_acceptor() -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let cert = CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).context("parse cert PEM")?;
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).context("parse key PEM")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("TLS server config")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

pub fn dangerous_tls_connector() -> tokio_rustls::TlsConnector {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

pub fn peer_public_key(tls: &tokio_rustls::client::TlsStream<TcpStream>) -> anyhow::Result<Vec<u8>> {
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("gateway TLS certificate missing")?;
    extract_public_key(cert)
}

pub fn server_public_key() -> anyhow::Result<Vec<u8>> {
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
