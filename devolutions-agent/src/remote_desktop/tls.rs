use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::Context as _;
use camino::Utf8Path;
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

pub(crate) fn acceptor(cert_path: &Utf8Path, key_path: &Utf8Path) -> anyhow::Result<TlsAcceptor> {
    let cert_file = File::open(cert_path).with_context(|| format!("failed to open {cert_path}"))?;
    let cert = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .next()
        .context("no certificate")??;

    let key_file = File::open(key_path).with_context(|| format!("failed to open {key_path}"))?;
    let key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(key_file))
        .next()
        .context("no private key")?
        .map(rustls::pki_types::PrivateKeyDer::from)?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("bad certificate/key")?;

    // This adds support for the SSLKEYLOGFILE env variable (https://wiki.wireshark.org/TLS#using-the-pre-master-secret)
    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
