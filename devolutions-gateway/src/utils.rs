pub mod association;

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::hash::Hash;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use futures::stream::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio_rustls::rustls;
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts};
use url::Url;
use x509_parser::parse_x509_der;

use crate::config::CertificateConfig;

pub mod danger_transport {
    use tokio_rustls::rustls;

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

pub async fn resolve_url_to_socket_arr(url: &Url) -> Option<SocketAddr> {
    let host = url.host_str()?;
    let port = url.port()?;
    lookup_host(format!("{}:{}", host, port))
        .await
        .ok()
        .map(|mut it| it.next())
        .flatten()
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
    let der = get_der_cert_from_stream(&stream)?;
    get_pub_key_from_der(&der)
}

pub fn get_pub_key_from_der(cert: &[u8]) -> io::Result<Vec<u8>> {
    let res = parse_x509_der(cert)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Utils: invalid der certificate."))?;
    let public_key = res.1.tbs_certificate.subject_pki.subject_public_key;

    Ok(public_key.data.to_vec())
}

fn get_der_cert_from_stream<S>(stream: &tokio_rustls::TlsStream<S>) -> io::Result<Vec<u8>> {
    let (_, session) = stream.get_ref();
    let payload = session
        .get_peer_certificates()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Failed to get the peer certificate."))?;

    let cert = payload
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Payload does not contain any certificates"))?;

    Ok(cert.as_ref().to_vec())
}

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
        let certfile = include_bytes!("../cert/publicCert.pem");
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
        let keyfile = include_bytes!("../cert/private.pem");
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
        let keyfile = include_bytes!("../cert/private.pem");
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

// Now in tokio 0.3.3 TcpListener::incoming() is temporary removed and will be returned in one of the next patches.
// The next struct is created in purpose to fill the gap.
// When incoming() will be returned, the Incoming struct should be replaced with the same from tokio

type AcceptType<'a> = Option<Pin<Box<dyn Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send + Sync + 'a>>>;

pub struct Incoming<'a> {
    pub listener: &'a TcpListener,
    pub accept: AcceptType<'a>,
}

impl Stream for Incoming<'_> {
    type Item = io::Result<TcpStream>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.accept.is_none() {
                self.accept = Some(Box::pin(self.listener.accept()));
            }

            if let Some(f) = &mut self.accept {
                let res = ready!(f.as_mut().poll(cx));
                self.accept = None;
                return Poll::Ready(Some(res.map(|(stream, _)| stream)));
            }
        }
    }
}

pub fn get_default_port_from_server_url(url: &Url) -> io::Result<u16> {
    match url.scheme() {
        "tcp" => Ok(8080),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Bad server url")),
    }
}

pub fn into_other_io_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(desc: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
