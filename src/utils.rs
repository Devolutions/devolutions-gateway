pub mod association;

use std::{
    fs,
    io::{self, BufReader},
    net::SocketAddr,
};
use url::Url;
use x509_parser::parse_x509_der;

pub mod danger_transport {
    pub struct NoCertificateVerification {}

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

pub fn url_to_socket_arr(url: &Url) -> SocketAddr {
    let host = url.host_str().unwrap().to_string();
    let port = url.port().map(|port| port.to_string()).unwrap();

    format!("{}:{}", host, port).parse::<SocketAddr>().unwrap()
}

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

pub fn get_tls_peer_pubkey<S>(stream: &tokio_rustls::TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    let der = get_der_cert_from_stream(&stream)?;

    get_pub_key_from_der(der)
}

pub fn auth_identity_to_credentials(auth_identity: sspi::AuthIdentity) -> ironrdp::rdp::Credentials {
    ironrdp::rdp::Credentials {
        username: auth_identity.username,
        password: auth_identity.password,
        domain: auth_identity.domain,
    }
}

pub fn get_pub_key_from_der(cert: Vec<u8>) -> io::Result<Vec<u8>> {
    let res = parse_x509_der(&cert[..])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Utils: invalid der certificate."))?;
    let public_key = res.1.tbs_certificate.subject_pki.subject_public_key;

    Ok(public_key.data.to_vec())
}

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

pub fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).map_err(|()| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse certificate: {}", filename),
        )
    })
}

pub fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    let mut rsa_keys = {
        let keyfile = fs::File::open(filename)?;
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader).map_err(|()| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File contains invalid rsa private key: {}", filename),
            )
        })?
    };

    let mut pkcs8_keys = {
        let keyfile = fs::File::open(filename)?;
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader).map_err(|()| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "File contains invalid pkcs8 private key (encrypted keys not supported): {}",
                    filename
                ),
            )
        })?
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        Ok(pkcs8_keys.remove(0))
    } else {
        assert!(!rsa_keys.is_empty());
        Ok(rsa_keys.remove(0))
    }
}
