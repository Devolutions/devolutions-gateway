pub mod association;

use std::{io, net::SocketAddr};

use url::Url;

const TLS_PUBLIC_KEY_HEADER: usize = 24;

pub fn url_to_socket_arr(url: &Url) -> SocketAddr {
    let host = url.host_str().unwrap().to_string();
    let port = url.port().map(|port| port.to_string()).unwrap();

    format!("{}:{}", host, port).parse::<SocketAddr>().unwrap()
}

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

macro_rules! codec_try {
    ($e:expr) => {
        match $e {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        }
    };
}

pub fn get_tls_pubkey(der: &[u8], pass: &str) -> io::Result<Vec<u8>> {
    let cert = openssl::pkcs12::Pkcs12::from_der(der)?.parse(pass)?.cert;
    get_tls_pubkey_from_cert(cert)
}

pub fn get_tls_peer_pubkey<S>(stream: &tokio_tls::TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    let der = get_der_cert_from_stream(&stream)?;
    let cert = openssl::x509::X509::from_der(&der)?;

    get_tls_pubkey_from_cert(cert)
}

fn get_der_cert_from_stream<S>(stream: &tokio_tls::TlsStream<S>) -> io::Result<Vec<u8>>
where
    S: io::Read + io::Write,
{
    stream
        .get_ref()
        .peer_certificate()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to get the peer certificate: {}", e),
            )
        })?
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "A server must provide the certificate"))?
        .to_der()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to convert the peer certificate to der: {}", e),
            )
        })
}

fn get_tls_pubkey_from_cert(cert: openssl::x509::X509) -> io::Result<Vec<u8>> {
    Ok(cert.public_key()?.public_key_to_der()?.split_off(TLS_PUBLIC_KEY_HEADER))
}
