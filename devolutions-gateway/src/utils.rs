pub mod association;

use anyhow::Context;
use core::fmt;
use serde::{de, ser};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::{rustls, Connect, TlsConnector};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts};
use url::Url;

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

pub async fn resolve_url_to_socket_addr(url: &Url) -> anyhow::Result<SocketAddr> {
    let host = url.host_str().context("bad URL: host missing")?;
    let port = url.port().context("bad URL: port missing")?;
    lookup_host((host, port))
        .await?
        .next()
        .context("host lookup yielded no result")
}

pub async fn resolve_target_to_socket_addr(dest: &TargetAddr) -> anyhow::Result<SocketAddr> {
    match &dest.host {
        HostRepr::Domain(domain, port) => lookup_host((domain.as_str(), *port))
            .await?
            .next()
            .context("host lookup yielded no result"),
        HostRepr::Ip(addr) => Ok(*addr),
    }
}

const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);

pub async fn tcp_stream_connect(dest: &TargetAddr) -> anyhow::Result<TcpStream> {
    let fut = async move {
        let socket_addr = resolve_target_to_socket_addr(dest).await?;
        TcpStream::connect(socket_addr).await.context("couldn't connect stream")
    };
    let stream = tokio::time::timeout(CONNECTION_TIMEOUT, fut).await??;
    Ok(stream)
}

pub async fn tcp_transport_connect(target: &TargetAddr) -> anyhow::Result<(SocketAddr, transport::Transport)> {
    let url = target.to_url().context("bad target")?;
    tcp_transport_connect_with_url(&url).await
}

pub async fn tcp_transport_connect_with_url(url: &Url) -> anyhow::Result<(SocketAddr, transport::Transport)> {
    use tokio_rustls::TlsStream;
    use transport::Transport;

    async fn connect_impl(url: &Url) -> anyhow::Result<(SocketAddr, transport::Transport)> {
        let socket_addr = resolve_url_to_socket_addr(url).await?;

        match url.scheme() {
            "tcp" => {
                let stream = TcpStream::connect(&socket_addr).await?;
                Ok((socket_addr, Transport::new(stream).into_erased()))
            }
            "tls" => {
                let stream = TcpStream::connect(&socket_addr).await?;
                let tls_handshake = create_tls_connector(stream).await?;
                Ok((
                    socket_addr,
                    Transport::new(TlsStream::Client(tls_handshake)).into_erased(),
                ))
            }
            scheme => {
                anyhow::bail!("Unsupported scheme: {}", scheme);
            }
        }
    }

    let (addr, transport) = tokio::time::timeout(CONNECTION_TIMEOUT, connect_impl(url)).await??;

    Ok((addr, transport))
}

pub async fn successive_try<'a, F, Fut, In, Out>(inputs: &'a [In], func: F) -> anyhow::Result<(Out, &'a In)>
where
    In: Display,
    F: Fn(&'a In) -> Fut + 'a,
    Fut: core::future::Future<Output = anyhow::Result<Out>>,
{
    let mut error: Option<anyhow::Error> = None;

    for input in inputs {
        match func(input).await {
            Ok(o) => return Ok((o, input)),
            Err(e) => {
                let e = e.context(format!("{} failed", input));
                match error.take() {
                    Some(prev_err) => error = Some(prev_err.context(e)),
                    None => error = Some(e),
                }
            }
        }
    }

    Err(error.context("empty input list")?)
}

pub fn get_tls_peer_pubkey<S>(stream: &tokio_rustls::TlsStream<S>) -> anyhow::Result<Vec<u8>> {
    let der = get_der_cert_from_stream(stream)?;

    let cert = picky::x509::Cert::from_der(&der).context("couldn't parse TLS certificate")?;

    let key_der = cert
        .public_key()
        .to_der()
        .context("Couldn't get der for public key contained in TLS certificate")?;

    Ok(key_der)
}

fn get_der_cert_from_stream<S>(stream: &tokio_rustls::TlsStream<S>) -> anyhow::Result<Vec<u8>> {
    let (_, session) = stream.get_ref();
    let payload = session
        .peer_certificates()
        .context("Failed to get the peer certificate")?;

    let cert = payload.first().context("Payload does not contain any certificate")?;

    Ok(cert.as_ref().to_vec())
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

pub fn url_to_socket_addr(url: &Url) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;

    let host = url.host_str().context("bad url: host missing")?;

    let port = url
        .port_or_known_default()
        .or_else(|| match url.scheme() {
            "tcp" => Some(8080),
            _ => None,
        })
        .context("bad url: port missing")?;

    Ok((host, port).to_socket_addrs().unwrap().next().unwrap())
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

#[derive(Debug)]
pub enum BadTargetAddr {
    HostMissing,
    PortMissing,
    BadPort { value: SmolStr },
}

impl fmt::Display for BadTargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BadTargetAddr::HostMissing => write!(f, "host is missing"),
            BadTargetAddr::PortMissing => write!(f, "port is missing"),
            BadTargetAddr::BadPort { value } => write!(f, "bad port value: {}", value),
        }
    }
}

impl std::error::Error for BadTargetAddr {}

/// <SCHEME>://<ADDR>:<PORT>
///
/// Similar to `url::Url`, but doesn't contain any route.
/// Also, when parsing, default scheme is `tcp`.
#[derive(Debug, Clone)]
pub struct TargetAddr {
    serialization: SmolStr,
    scheme: SmolStr,
    host: HostRepr,
}

#[derive(Debug, Clone)]
pub enum HostRepr {
    Domain(SmolStr, u16),
    Ip(SocketAddr),
}

impl fmt::Display for HostRepr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostRepr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
            HostRepr::Ip(ip) => ip.fmt(f),
        }
    }
}

impl TargetAddr {
    const DEFAULT_SCHEME: &'static str = "tcp";

    pub fn parse(s: &str, default_port: impl Into<Option<u16>>) -> Result<Self, BadTargetAddr> {
        target_addr_parse_impl(s, default_port.into())
    }

    pub fn as_str(&self) -> &str {
        &self.serialization
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &HostRepr {
        &self.host
    }

    pub fn to_url(&self) -> Result<url::Url, url::ParseError> {
        self.serialization.parse()
    }

    pub fn to_uri(&self) -> Result<http::Uri, http::uri::InvalidUri> {
        self.serialization.parse()
    }

    pub fn to_uri_with_path_and_query(&self, path_and_query: &str) -> Result<http::Uri, http::uri::InvalidUri> {
        format!("{}{}", self.serialization, path_and_query).parse()
    }
}

fn target_addr_parse_impl(s: &str, default_port: Option<u16>) -> Result<TargetAddr, BadTargetAddr> {
    let (scheme, rest) = if let Some(scheme_end_idx) = s.find("://") {
        (SmolStr::new(&s[..scheme_end_idx]), &s[scheme_end_idx + "://".len()..])
    } else {
        (SmolStr::new_inline(TargetAddr::DEFAULT_SCHEME), s)
    };

    if let Ok(addr) = rest.parse::<SocketAddr>() {
        Ok(TargetAddr {
            serialization: SmolStr::from(format!("{}://{}", scheme, addr)),
            scheme,
            host: HostRepr::Ip(addr),
        })
    } else {
        let (domain, port) = if let Some(domain_end_idx) = rest.find(':') {
            let domain = SmolStr::new(&rest[..domain_end_idx]);

            let port = &rest[domain_end_idx + 1..];
            let port = port
                .parse::<u16>()
                .map_err(|_| BadTargetAddr::BadPort { value: port.into() })?;

            (domain, port)
        } else if let Some(default_port) = default_port {
            (SmolStr::new(rest), default_port)
        } else {
            return Err(BadTargetAddr::PortMissing);
        };

        Ok(TargetAddr {
            serialization: SmolStr::from(format!("{}://{}:{}", scheme, domain, port)),
            scheme,
            host: HostRepr::Domain(domain, port),
        })
    }
}

impl TryFrom<&url::Url> for TargetAddr {
    type Error = BadTargetAddr;

    fn try_from(url: &url::Url) -> Result<Self, Self::Error> {
        let scheme = SmolStr::from(url.scheme());

        let port = url.port().ok_or(BadTargetAddr::PortMissing)?;

        let host = match url.host().ok_or(BadTargetAddr::HostMissing)? {
            url::Host::Domain(domain) => HostRepr::Domain(domain.into(), port),
            url::Host::Ipv4(ipv4) => HostRepr::Ip(SocketAddr::new(IpAddr::V4(ipv4), port)),
            url::Host::Ipv6(ipv6) => HostRepr::Ip(SocketAddr::new(IpAddr::V6(ipv6), port)),
        };

        let serialization = SmolStr::from(format!("{}://{}", scheme, host));

        Ok(Self {
            serialization,
            scheme,
            host,
        })
    }
}

impl TryFrom<url::Url> for TargetAddr {
    type Error = BadTargetAddr;

    fn try_from(url: url::Url) -> Result<Self, Self::Error> {
        TargetAddr::try_from(&url)
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.serialization)
    }
}

impl ser::Serialize for TargetAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.serialization)
    }
}

impl FromStr for TargetAddr {
    type Err = BadTargetAddr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s, None)
    }
}

impl<'de> de::Deserialize<'de> for TargetAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;

        impl<'de> de::Visitor<'de> for V {
            type Value = TargetAddr;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a destination host such as <SCHEME>://<HOST>:<PORT>")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                s.parse::<Self::Value>().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(V)
    }
}
