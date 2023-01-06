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
use tap::Pipe as _;
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
    let port = dest.port();

    if let Some(ip) = dest.host_ip() {
        Ok(SocketAddr::new(ip, port))
    } else {
        lookup_host((dest.host(), port))
            .await?
            .next()
            .context("host lookup yielded no result")
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

pub async fn tcp_transport_connect(target: &TargetAddr) -> anyhow::Result<transport::Transport> {
    let url = target.to_url().context("bad target")?;
    tcp_transport_connect_with_url(&url).await
}

pub async fn tcp_transport_connect_with_url(url: &Url) -> anyhow::Result<transport::Transport> {
    use tokio_rustls::TlsStream;
    use transport::Transport;

    async fn connect_impl(url: &Url) -> anyhow::Result<transport::Transport> {
        let socket_addr = resolve_url_to_socket_addr(url).await?;

        match url.scheme() {
            "tcp" => {
                let stream = TcpStream::connect(&socket_addr).await?;
                Ok(Transport::new(stream, socket_addr))
            }
            "tls" => {
                let stream = TcpStream::connect(&socket_addr).await?;
                let tls_handshake = create_tls_connector(stream).await?;
                Ok(Transport::new(TlsStream::Client(tls_handshake), socket_addr))
            }
            scheme => {
                anyhow::bail!("Unsupported scheme: {}", scheme);
            }
        }
    }

    let transport = tokio::time::timeout(CONNECTION_TIMEOUT, connect_impl(url)).await??;

    Ok(transport)
}

pub async fn successive_try<'a, F, Fut, In, Out>(
    inputs: impl IntoIterator<Item = &'a In>,
    func: F,
) -> anyhow::Result<(Out, &'a In)>
where
    In: Display + 'a,
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
    let port = url.port_or_known_default().context("bad url: port missing")?;

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
    TooLong,
    BadPort { value: SmolStr },
}

impl fmt::Display for BadTargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BadTargetAddr::HostMissing => write!(f, "host is missing"),
            BadTargetAddr::PortMissing => write!(f, "port is missing"),
            BadTargetAddr::TooLong => write!(f, "address representation is too long"),
            BadTargetAddr::BadPort { value } => write!(f, "bad port value: {}", value),
        }
    }
}

impl std::error::Error for BadTargetAddr {}

/// <SCHEME>://<ADDR>:<PORT>
///
/// Similar to `url::Url`, but doesn't contain any route.
/// Also, when parsing, default scheme is `tcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAddr {
    // String representation
    serialization: String,

    // Components
    scheme_end: u16,
    host_start: u16,
    host_end: u16,
    host_internal: HostInternal,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostInternal {
    Domain,
    Ip(IpAddr),
}

impl TargetAddr {
    const DEFAULT_SCHEME: &'static str = "tcp";

    pub fn from_components(scheme: &str, host: &str, port: u16) -> Result<Self, BadTargetAddr> {
        let scheme_end = scheme.len();

        let (host_internal, is_ipv6) = if let Ok(ip_addr) = host.parse::<IpAddr>() {
            (HostInternal::Ip(ip_addr), ip_addr.is_ipv6())
        } else {
            (HostInternal::Domain, false)
        };

        let (serialization, host_start) = if is_ipv6 {
            (format!("{scheme}://[{host}]:{port}"), scheme_end + "://[".len())
        } else {
            (format!("{scheme}://{host}:{port}"), scheme_end + "://".len())
        };

        let host_end = host_start + host.len();

        Ok(TargetAddr {
            serialization,
            scheme_end: scheme_end.pipe(u16::try_from).map_err(|_| BadTargetAddr::TooLong)?,
            host_start: host_start.pipe(u16::try_from).map_err(|_| BadTargetAddr::TooLong)?,
            host_end: host_end.pipe(u16::try_from).map_err(|_| BadTargetAddr::TooLong)?,
            host_internal,
            port,
        })
    }

    pub fn parse(s: &str, default_port: impl Into<Option<u16>>) -> Result<Self, BadTargetAddr> {
        target_addr_parse_impl(s, Self::DEFAULT_SCHEME, default_port.into())
    }

    pub fn parse_with_default_scheme(
        s: &str,
        default_scheme: &str,
        default_port: impl Into<Option<u16>>,
    ) -> Result<Self, BadTargetAddr> {
        target_addr_parse_impl(s, default_scheme, default_port.into())
    }

    pub fn as_str(&self) -> &str {
        &self.serialization
    }

    pub fn scheme(&self) -> &str {
        self.h_slice(0, self.scheme_end)
    }

    pub fn host(&self) -> &str {
        self.h_slice(self.host_start, self.host_end)
    }

    pub fn host_ip(&self) -> Option<IpAddr> {
        match self.host_internal {
            HostInternal::Domain => None,
            HostInternal::Ip(ip) => Some(ip),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
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

    #[inline]
    fn h_slice(&self, start: u16, end: u16) -> &str {
        &self.serialization[usize::from(start)..usize::from(end)]
    }
}

fn target_addr_parse_impl(
    s: &str,
    default_scheme: &str,
    default_port: Option<u16>,
) -> Result<TargetAddr, BadTargetAddr> {
    let (scheme, rest) = if let Some(scheme_end) = s.find("://") {
        (&s[..scheme_end], &s[scheme_end + "://".len()..])
    } else {
        (default_scheme, s)
    };

    let is_ipv6 = matches!(rest.chars().next(), Some('['));

    let port_start = if is_ipv6 {
        rest.rfind("]:").map(|idx| idx + 2)
    } else {
        rest.rfind(':').map(|idx| idx + 1)
    };

    let (rest, port) = if let Some(port_start) = port_start {
        let port = &rest[port_start..];
        let port = port
            .parse::<u16>()
            .map_err(|_| BadTargetAddr::BadPort { value: port.into() })?;

        (&rest[..port_start - 1], port)
    } else if let Some(default_port) = default_port {
        (rest, default_port)
    } else {
        return Err(BadTargetAddr::PortMissing);
    };

    let host = if is_ipv6 {
        rest.trim_start_matches('[').trim_end_matches(']')
    } else {
        rest
    };

    TargetAddr::from_components(scheme, host, port)
}

impl TryFrom<&url::Url> for TargetAddr {
    type Error = BadTargetAddr;

    fn try_from(url: &url::Url) -> Result<Self, Self::Error> {
        let scheme = url.scheme();
        let port = url.port_or_known_default().ok_or(BadTargetAddr::PortMissing)?;
        let host = url.host_str().ok_or(BadTargetAddr::HostMissing)?;
        Self::from_components(scheme, host, port)
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
        target_addr_parse_impl(s, Self::DEFAULT_SCHEME, None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;
    use rstest::rstest;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[rstest]
    #[case("localhost:80", "tcp", "localhost", None, 80)]
    #[case(
        "udp://127.0.0.1:8080",
        "udp",
        "127.0.0.1",
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        8080
    )]
    #[case(
        "tcp://[2001:db8::8a2e:370:7334]:7171",
        "tcp",
        "2001:db8::8a2e:370:7334",
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334))),
        7171
    )]
    #[case(
        "https://[2001:0db8:0000:0000:0000:8a2e:0370:7334]:433",
        "https",
        "2001:0db8:0000:0000:0000:8a2e:0370:7334",
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334))),
        433
    )]
    #[case(
        "ws://[::1]:2222",
        "ws",
        "::1",
        Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
        2222
    )]
    fn target_addr_parsing(
        #[case] repr: &str,
        #[case] scheme: &str,
        #[case] host: &str,
        #[case] ip: Option<IpAddr>,
        #[case] port: u16,
    ) {
        let addr = TargetAddr::parse(repr, None).unwrap();
        assert_eq!(addr.scheme(), scheme);
        assert_eq!(addr.host(), host);
        assert_eq!(addr.host_ip(), ip);
        assert_eq!(addr.port(), port);
    }

    #[rstest]
    fn target_addr_with_default_port(
        #[values("localhost", "127.0.0.1", "::1", "2001:db8::8a2e:370:7334")] host: &str,
        #[values(None, Some(12))] port: Option<u16>,
    ) {
        let default_port = 8080;

        let is_ipv6 = host.find(':').is_some();

        let mut s = String::new();

        if is_ipv6 {
            write!(s, "[{host}]").unwrap();
        } else {
            write!(s, "{host}").unwrap();
        }

        if let Some(port) = port {
            write!(s, ":{port}").unwrap();
        }

        let addr = TargetAddr::parse(&s, default_port).unwrap();

        assert_eq!(addr.scheme(), "tcp");
        assert_eq!(addr.host(), host);

        if let Some(expected) = port {
            assert_eq!(addr.port(), expected);
        } else {
            assert_eq!(addr.port(), default_port);
        }
    }

    #[rstest]
    fn target_addr_with_default_scheme(
        #[values(None, Some("tcp"), Some("udp"))] scheme: Option<&str>,
        #[values("tcp", "udp")] default_scheme: &str,
    ) {
        let mut s = String::new();

        if let Some(scheme) = scheme {
            write!(s, "{scheme}://").unwrap();
        }

        write!(s, "localhost:2222").unwrap();

        let addr = TargetAddr::parse_with_default_scheme(&s, default_scheme, None).unwrap();

        if let Some(expected) = scheme {
            assert_eq!(addr.scheme(), expected);
        } else {
            assert_eq!(addr.scheme(), default_scheme);
        }

        assert_eq!(addr.host(), "localhost");
        assert_eq!(addr.host_ip(), None);
        assert_eq!(addr.port(), 2222);
    }
}
