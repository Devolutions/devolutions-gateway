pub mod association;

use crate::config::CertificateConfig;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::hash::Hash;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::{rustls, Connect, TlsConnector};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts};
use url::Url;
use x509_parser::certificate::X509Certificate;
use x509_parser::traits::FromDer;

pub mod danger_transport {
    use tokio_rustls::rustls;

    pub struct NoCertificateVerification;

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

pub async fn resolve_url_to_socket_arr(url: &Url) -> Option<SocketAddr> {
    let host = url.host_str()?;
    let port = url.port()?;
    lookup_host((host, port)).await.ok().map(|mut it| it.next()).flatten()
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

pub fn get_tls_peer_pubkey<S>(stream: &tokio_rustls::TlsStream<S>) -> io::Result<Vec<u8>> {
    let der = get_der_cert_from_stream(stream)?;
    get_pub_key_from_der(&der)
}

pub fn get_pub_key_from_der(cert: &[u8]) -> io::Result<Vec<u8>> {
    let res = X509Certificate::from_der(cert)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Utils: invalid der certificate."))?;
    let public_key = res.1.tbs_certificate.subject_pki.subject_public_key;

    Ok(public_key.data.to_vec())
}

fn get_der_cert_from_stream<S>(stream: &tokio_rustls::TlsStream<S>) -> io::Result<Vec<u8>> {
    let (_, session) = stream.get_ref();
    let payload = session
        .peer_certificates()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to get the peer certificate."))?;

    let cert = payload
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Payload does not contain any certificates"))?;

    Ok(cert.as_ref().to_vec())
}

pub fn load_cert(config: &CertificateConfig) -> io::Result<rustls::Certificate> {
    let data = if let Some(filename) = &config.certificate_file {
        Cow::Owned(fs::read_to_string(filename)?)
    } else if let Some(data) = &config.certificate_data {
        Cow::Borrowed(data)
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, "certificate is missing"));
    };

    let pem = picky::pem::parse_pem(data.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if pem.label() != "CERTIFICATE" {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("bad label for certificate pem: {}", pem.label()),
        ));
    }

    Ok(rustls::Certificate(pem.into_data().into_owned()))
}

pub fn load_private_key(config: &CertificateConfig) -> io::Result<rustls::PrivateKey> {
    let data = if let Some(filename) = &config.private_key_file {
        Cow::Owned(fs::read_to_string(filename)?)
    } else if let Some(data) = &config.private_key_data {
        Cow::Borrowed(data)
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, "private key is missing"));
    };

    let pem = picky::pem::parse_pem(data.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if pem.label() != "PRIVATE KEY" && pem.label() != "RSA PRIVATE KEY" {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("bad label for private key pem: {}", pem.label()),
        ));
    }

    Ok(rustls::PrivateKey(pem.into_data().into_owned()))
}

pub fn update_framed_codec<Io, OldCodec, NewCodec, OldDecodedType, NewDecodedType>(
    framed: Framed<Io, OldCodec>,
    codec: NewCodec,
) -> Framed<Io, NewCodec>
where
    Io: AsyncRead + AsyncWrite,
    OldCodec: Decoder + Encoder<OldDecodedType>,
    NewCodec: Decoder + Encoder<NewDecodedType>,
{
    let FramedParts { io, read_buf, .. } = framed.into_parts();

    let mut new_parts = FramedParts::new(io, codec);
    new_parts.read_buf = read_buf;

    Framed::from_parts(new_parts)
}

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

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + Sync + 'static {}

pub fn url_to_socket_addr(url: &Url) -> io::Result<SocketAddr> {
    use std::net::ToSocketAddrs;

    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "bad host in url"))?;

    let port = url
        .port_or_known_default()
        .or_else(|| match url.scheme() {
            "tcp" => Some(8080),
            _ => None,
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad or missing port in url"))?;

    Ok((host, port).to_socket_addrs().unwrap().next().unwrap())
}

pub fn into_other_io_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(desc: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

pub fn create_tls_connector(socket: TcpStream) -> Connect<TcpStream> {
    let dns_name = rustls::ServerName::try_from("stub_string").unwrap();

    let rustls_client_conf = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(danger_transport::NoCertificateVerification))
        .with_no_client_auth();
    let rustls_client_conf = Arc::new(rustls_client_conf);

    let connector = TlsConnector::from(rustls_client_conf);
    connector.connect(dns_name, socket)
}
