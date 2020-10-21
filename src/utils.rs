//pub mod association;

use std::{
    collections::HashMap,
    fs,
    hash::Hash,
    io::{self, BufReader},
    net::{SocketAddr, ToSocketAddrs},
};

use crate::config::CertificateConfig;
/*
use tokio::{
    codec::{Decoder, Encoder, Framed, FramedParts},
    prelude::{AsyncRead, AsyncWrite},
};
 */
use url::Url;
use x509_parser::parse_x509_der;

pub mod danger_transport {
    pub struct NoCertificateVerification;

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

/// FIXME: we need to upgrade to tokio 0.3 in order to make resolving async
/*
pub fn resolve_url_to_socket_arr(url: &Url) -> Option<SocketAddr> {
    let host = url.host_str()?;
    let port = url.port()?;
    format!("{}:{}", host, port).to_socket_addrs().ok()?.next()
}
*/
#[macro_export]
macro_rules! io_try {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    };
}
/*
pub fn get_tls_peer_pubkey<S>(stream: &tokio_rustls::TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    let der = get_der_cert_from_stream(&stream)?;

    get_pub_key_from_der(&der)
}
*/
pub fn get_pub_key_from_der(cert: &[u8]) -> io::Result<Vec<u8>> {
    let res = parse_x509_der(cert)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Utils: invalid der certificate."))?;
    let public_key = res.1.tbs_certificate.subject_pki.subject_public_key;

    Ok(public_key.data.to_vec())
}
/*
fn get_der_cert_from_stream<S>(stream: &tokio_rustls::TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    use rustls::internal::msgs::handshake::CertificatePayload;

    let payload: CertificatePayload = stream
        .get_ref()
        .1
        .get_peer_certificates()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to get the peer certificate."))?;

    Ok(payload[0].as_ref().to_vec())
}
*/
pub fn load_certs(config: &CertificateConfig) -> io::Result<Vec<rustls::Certificate>> {
    if let Some(filename) = &config.certificate_file {
        let certfile = fs::File::open(filename).unwrap_or_else(|_| panic!("cannot open certificate file {}", filename));
        let mut reader = BufReader::new(certfile);

        rustls::internal::pemfile::certs(&mut reader)
            .map_err(|()| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse certificate"))
    } else if let Some(data) = &config.certificate_data {
        load_certs_from_data(data)
            .map_err(|()| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse certificate data"))
    } else {
        let certfile = include_bytes!("cert/publicCert.pem");
        let mut reader = BufReader::new(certfile.as_ref());

        rustls::internal::pemfile::certs(&mut reader)
            .map_err(|()| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse certificate"))
    }
}

pub fn load_private_key(config: &CertificateConfig) -> io::Result<rustls::PrivateKey> {
    let mut pkcs8_keys = load_pkcs8_private_key(config)?;

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        Ok(pkcs8_keys.remove(0))
    } else {
        let mut rsa_keys = load_rsa_private_key(config)?;

        assert!(!rsa_keys.is_empty());
        Ok(rsa_keys.remove(0))
    }
}

fn load_rsa_private_key(config: &CertificateConfig) -> io::Result<Vec<rustls::PrivateKey>> {
    if let Some(filename) = &config.private_key_file {
        let keyfile = fs::File::open(filename).unwrap_or_else(|_| panic!("cannot open private key file {}", filename));
        rustls::internal::pemfile::rsa_private_keys(&mut BufReader::new(keyfile))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "File contains invalid rsa private key"))
    } else if let Some(data) = &config.private_key_data {
        load_rsa_private_key_from_data(data)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid rsa private key"))
    } else {
        let keyfile = include_bytes!("cert/private.pem");
        rustls::internal::pemfile::rsa_private_keys(&mut BufReader::new(keyfile.as_ref()))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "File contains invalid rsa private key"))
    }
}

fn load_pkcs8_private_key(config: &CertificateConfig) -> io::Result<Vec<rustls::PrivateKey>> {
    if let Some(filename) = &config.private_key_file {
        let keyfile = fs::File::open(filename).unwrap_or_else(|_| panic!("cannot open private key file {}", filename));
        rustls::internal::pemfile::pkcs8_private_keys(&mut BufReader::new(keyfile)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "File contains invalid pkcs8 private key (encrypted keys not supported)",
            )
        })
    } else if let Some(data) = &config.private_key_data {
        load_pkcs8_private_key_from_data(data)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid pkcs8 private key"))
    } else {
        let keyfile = include_bytes!("cert/private.pem");
        rustls::internal::pemfile::pkcs8_private_keys(&mut BufReader::new(keyfile.as_ref())).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "File contains invalid pkcs8 private key (encrypted keys not supported)",
            )
        })
    }
}

fn load_certs_from_data(data: &str) -> Result<Vec<rustls::Certificate>, ()> {
    extract_der_data(
        data.to_string(),
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        &|v| rustls::Certificate(v),
    )
}

fn load_rsa_private_key_from_data(data: &str) -> Result<Vec<rustls::PrivateKey>, ()> {
    extract_der_data(
        data.to_string(),
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        &|v| rustls::PrivateKey(v),
    )
}

fn load_pkcs8_private_key_from_data(data: &str) -> Result<Vec<rustls::PrivateKey>, ()> {
    extract_der_data(
        data.to_string(),
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        &|v| rustls::PrivateKey(v),
    )
}

fn extract_der_data<A>(
    mut data: String,
    start_mark: &str,
    end_mark: &str,
    f: &dyn Fn(Vec<u8>) -> A,
) -> Result<Vec<A>, ()> {
    let mut ders = Vec::new();

    while let Some(start_index) = data.find(start_mark) {
        let drain_index = start_index + start_mark.len();
        data.drain(..drain_index);
        if let Some(index) = data.find(end_mark) {
            let base64_buf = &data[..index];
            let der = base64::decode(&base64_buf).map_err(|_| ())?;
            ders.push(f(der));

            let drain_index = index + end_mark.len();
            data.drain(..drain_index);
        } else {
            break;
        }
    }

    Ok(ders)
}
/*
pub fn update_framed_codec<Io, OldCodec, NewCodec>(
    framed: Framed<Io, OldCodec>,
    codec: NewCodec,
) -> Framed<Io, NewCodec>
where
    Io: AsyncRead + AsyncWrite,
    OldCodec: Decoder + Encoder,
    NewCodec: Decoder + Encoder,
{
    let FramedParts { io, read_buf, .. } = framed.into_parts();

    let mut new_parts = FramedParts::new(io, codec);
    new_parts.read_buf = read_buf;

    Framed::from_parts(new_parts)
}
*/
#[allow(clippy::implicit_hasher)]
pub fn swap_hashmap_kv<K, V>(hm: HashMap<K, V>) -> HashMap<V, K>
where
    V: Hash + Eq,
{
    let mut result = HashMap::with_capacity(hm.len());
    for (k, v) in hm {
        result.insert(v, k);
    }

    result
}
