pub mod association;

use std::{io::{self, BufReader}, net::SocketAddr, fs};

use tokio::codec::{Framed, FramedParts};
use url::Url;
use x509_parser::parse_x509_der;
use crate::config::CertificateConfig;
use std::io::Read;

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

pub fn load_certs(config: &CertificateConfig) -> io::Result<Vec<rustls::Certificate>> {
    let certfile: Box<dyn Read> = if let Some(filename) = &config.certificate_file {
        let certfile = fs::File::open(filename).expect(&format!("cannot open certificate file {}", filename));
        Box::new(certfile)
    } else {
        let certfile = include_bytes!("cert/publicCert.pem");
        Box::new(certfile.as_ref())
    };

    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader)
        .map_err(|()| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse certificate"))
}

pub fn load_private_key(config: &CertificateConfig) -> io::Result<rustls::PrivateKey> {
    let mut rsa_keys = {
        let rsa_keyfile: Box<dyn Read> = if let Some(filename) = &config.private_key_file {
            let keyfile = fs::File::open(filename).expect(&format!("cannot open private key file {}", filename));
            Box::new(keyfile)
        } else {
            let keyfile = include_bytes!("cert/private.pem");
            Box::new(keyfile.as_ref())
        };

        rustls::internal::pemfile::rsa_private_keys(&mut BufReader::new(rsa_keyfile))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "File contains invalid rsa private key"))?
    };

    let mut pkcs8_keys = {
        let pkcs8_keyfile: Box<dyn Read> = if let Some(filename) = &config.private_key_file {
            let keyfile = fs::File::open(filename).expect(&format!("cannot open private key file {}", filename));
            Box::new(keyfile)
        } else {
            let keyfile = include_bytes!("cert/private.pem");
            Box::new(keyfile.as_ref())
        };

        rustls::internal::pemfile::pkcs8_private_keys(&mut BufReader::new(pkcs8_keyfile)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "File contains invalid pkcs8 private key (encrypted keys not supported)",
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

pub fn update_framed_codec<Io, OldCodec, NewCodec>(
    framed: Framed<Io, OldCodec>,
    codec: NewCodec,
) -> Framed<Io, NewCodec> {
    let parts = framed.into_parts();

    let mut new_parts = FramedParts::new(parts.io, codec);
    new_parts.read_buf = parts.read_buf;

    Framed::from_parts(new_parts)
}
