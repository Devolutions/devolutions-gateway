use anyhow::Context as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, Error, SignatureScheme, pki_types};
use std::borrow::Cow;
use std::path::Path;

use crate::doctor::macros::diagnostic;
use crate::doctor::{Args, Diagnostic, DiagnosticCtx, InspectCert, cert_to_pem, help};

pub(super) fn run(args: &Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
    let mut root_store = rustls::RootCertStore::empty();
    let mut server_certificates = Vec::new();

    diagnostic!(callback, rustls_load_native_certs(&mut root_store));

    if let Some(chain_path) = &args.chain_path {
        diagnostic!(callback, rustls_read_chain(&chain_path, &mut server_certificates));
    } else if let Some(subject_name) = args.subject_name.as_deref()
        && args.allow_network
    {
        diagnostic!(
            callback,
            rustls_fetch_chain(subject_name, args.server_port, &mut server_certificates)
        );
    }

    if !server_certificates.is_empty() {
        diagnostic!(
            callback,
            rustls_check_end_entity_cert(&server_certificates, args.subject_name.as_deref())
        );
        diagnostic!(callback, rustls_check_chain(&root_store, &server_certificates));
    }
}

fn rustls_load_native_certs(_: &mut DiagnosticCtx, root_store: &mut rustls::RootCertStore) -> anyhow::Result<()> {
    let result = rustls_native_certs::load_native_certs();

    for error in result.errors {
        warn!("Error when loading native certs: {:?}", anyhow::Error::new(error),);
    }

    for cert in result.certs {
        if let Err(e) = root_store.add(cert.clone()) {
            warn!("Invalid root certificate: {e}");
            let root_cert_pem = cert_to_pem(&cert).context("failed to write the certificate as PEM")?;
            info!("{root_cert_pem}");
        }
    }

    Ok(())
}

fn rustls_fetch_chain(
    ctx: &mut DiagnosticCtx,
    subject_name: &str,
    port: Option<u16>,
    server_certificates: &mut Vec<pki_types::CertificateDer<'static>>,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::net::TcpStream;

    info!("Connect to {subject_name}");

    let mut socket = TcpStream::connect((subject_name, port.unwrap_or(443)))
        .with_context(|| format!("failed to connect to {subject_name}..."))
        .inspect_err(|_| help::failed_to_connect_to_server(ctx, subject_name))?;

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    let config = std::sync::Arc::new(config);
    let subject_name = pki_types::ServerName::try_from(subject_name.to_owned()).context("invalid DNS name")?;
    let mut client = rustls::ClientConnection::new(config, subject_name).context("failed to create TLS client")?;

    info!("Fetch server certificates");

    loop {
        if client.wants_read() {
            client.read_tls(&mut socket).context("read_tls failed")?;
            client.process_new_packets().context("process_new_packets failed")?;
        }

        if client.wants_write() {
            client.write_tls(&mut socket).context("write_tls failed")?;
        }

        socket.flush().context("flush failed")?;

        if let Some(peer_certificates) = client.peer_certificates() {
            for certificate in peer_certificates {
                server_certificates.push(certificate.clone().into_owned());
            }

            break;
        }
    }

    crate::doctor::log_chain(server_certificates.iter());
    help::x509_io_link(ctx, server_certificates.iter());

    Ok(())
}

fn rustls_read_chain(
    ctx: &mut DiagnosticCtx,
    chain_path: &Path,
    server_certificates: &mut Vec<pki_types::CertificateDer<'static>>,
) -> anyhow::Result<()> {
    info!("Read file at {}", chain_path.display());

    let mut file = std::fs::File::open(chain_path)
        .map(std::io::BufReader::new)
        .context("read file from disk")?;

    for (idx, certificate) in rustls_pemfile::certs(&mut file).enumerate() {
        let certificate = certificate.with_context(|| format!("failed to read certificate number {idx}"))?;
        server_certificates.push(certificate);
    }

    crate::doctor::log_chain(server_certificates.iter());
    help::x509_io_link(ctx, server_certificates.iter());

    Ok(())
}

fn rustls_check_end_entity_cert(
    ctx: &mut DiagnosticCtx,
    server_certificates: &[pki_types::CertificateDer<'static>],
    subject_name_to_verify: Option<&str>,
) -> anyhow::Result<()> {
    let end_entity_cert = server_certificates.first().cloned().context("empty chain")?;

    info!("Decode end entity certificate");

    let end_entity_cert =
        rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

    if let Some(subject_name_to_verify) = subject_name_to_verify {
        info!("Verify validity for DNS name");

        let server_name = pki_types::ServerName::try_from(subject_name_to_verify).context("invalid DNS name")?;
        rustls::client::verify_server_name(&end_entity_cert, &server_name)
            .inspect_err(|_| help::cert_invalid_hostname(ctx, subject_name_to_verify))
            .context("verify DNS name")?;
    }

    Ok(())
}

fn rustls_check_chain(
    ctx: &mut DiagnosticCtx,
    root_store: &rustls::RootCertStore,
    server_certificates: &[pki_types::CertificateDer<'static>],
) -> anyhow::Result<()> {
    use rustls::client::verify_server_cert_signed_by_trust_anchor;

    let mut certs = server_certificates.iter().cloned();

    let end_entity_cert = certs.next().context("empty chain")?;

    info!("Decode end entity certificate");

    let end_entity_cert =
        rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

    info!("Verify server certificate signed by trust anchor");

    let intermediates: Vec<_> = certs.collect();
    let now = pki_types::UnixTime::now();
    let ring_crypto_provider = rustls::crypto::ring::default_provider();

    verify_server_cert_signed_by_trust_anchor(
        &end_entity_cert,
        root_store,
        &intermediates,
        now,
        ring_crypto_provider.signature_verification_algorithms.all,
    )
    .inspect_err(|error| {
        if let Error::InvalidCertificate(cert_error) = error {
            match cert_error {
                rustls::CertificateError::Expired => help::cert_is_expired(ctx),
                rustls::CertificateError::NotValidYet => help::cert_is_not_yet_valid(ctx),
                rustls::CertificateError::UnknownIssuer => help::cert_unknown_issuer(ctx),
                rustls::CertificateError::InvalidPurpose => help::cert_invalid_purpose(ctx),
                _ => (),
            }
        }
    })
    .context("failed to verify certification chain")?;

    Ok(())
}

impl InspectCert for pki_types::CertificateDer<'_> {
    fn der(&self) -> anyhow::Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self))
    }

    fn friendly_name(&self) -> Option<Cow<'_, str>> {
        None
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

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
