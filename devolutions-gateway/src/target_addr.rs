use core::fmt;
use std::net::IpAddr;
use std::ops::RangeBounds;
use std::str::FromStr;

use serde::{de, ser};
use smol_str::SmolStr;
use tap::Pipe as _;

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
            BadTargetAddr::BadPort { value } => write!(f, "bad port value: {value}"),
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
    // String representation
    serialization: String,

    // Components
    scheme_end: u16,
    host_start: u16,
    host_end: u16,
    host_internal: HostInternal,
    port: u16,
}

#[derive(Debug, Clone)]
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
        self.h_slice_repr(..self.scheme_end)
    }

    pub fn host(&self) -> &str {
        self.h_slice_repr(self.host_start..self.host_end)
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

    pub fn as_addr(&self) -> &str {
        self.h_slice_repr((self.scheme_end + 3)..)
    }

    // Slice the internal representation using a [`Range<u16>`]
    fn h_slice_repr(&self, range: impl RangeBounds<u16>) -> &str {
        use std::ops::Bound;

        // TODO(@CBenoit): use Bound::map when stabilized (bound_map feature)
        // https://github.com/rust-lang/rust/issues/86026
        let lo = match range.start_bound() {
            Bound::Included(idx) => Bound::Included(usize::from(*idx)),
            Bound::Excluded(idx) => Bound::Excluded(usize::from(*idx)),
            Bound::Unbounded => Bound::Unbounded,
        };
        let hi = match range.end_bound() {
            Bound::Included(idx) => Bound::Included(usize::from(*idx)),
            Bound::Excluded(idx) => Bound::Excluded(usize::from(*idx)),
            Bound::Unbounded => Bound::Unbounded,
        };

        &self.serialization.as_str()[(lo, hi)]
    }

    pub fn to_uri_with_path_and_query(
        &self,
        path_and_query: &str,
    ) -> Result<axum::http::Uri, axum::http::uri::InvalidUri> {
        format!("{}{}", self.serialization, path_and_query).parse()
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

impl PartialEq for TargetAddr {
    fn eq(&self, other: &Self) -> bool {
        self.scheme() == other.scheme() && self.host() == other.host() && self.port() == other.port()
    }
}

impl Eq for TargetAddr {}

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

        impl de::Visitor<'_> for V {
            type Value = TargetAddr;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl std::net::ToSocketAddrs for TargetAddr {
    type Iter = std::vec::IntoIter<std::net::SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        self.as_addr().to_socket_addrs()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use core::fmt::Write as _;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("localhost:80", "tcp", "localhost", None, 80, "localhost:80")]
    #[case(
        "udp://127.0.0.1:8080",
        "udp",
        "127.0.0.1",
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        8080,
        "127.0.0.1:8080"
    )]
    #[case(
        "tcp://[2001:db8::8a2e:370:7334]:7171",
        "tcp",
        "2001:db8::8a2e:370:7334",
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334))),
        7171,
        "[2001:db8::8a2e:370:7334]:7171"
    )]
    #[case(
        "https://[2001:0db8:0000:0000:0000:8a2e:0370:7334]:433",
        "https",
        "2001:0db8:0000:0000:0000:8a2e:0370:7334",
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334))),
        433,
        "[2001:0db8:0000:0000:0000:8a2e:0370:7334]:433"
    )]
    #[case(
        "ws://[::1]:2222",
        "ws",
        "::1",
        Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
        2222,
        "[::1]:2222"
    )]
    fn target_addr_parsing(
        #[case] repr: &str,
        #[case] scheme: &str,
        #[case] host: &str,
        #[case] ip: Option<IpAddr>,
        #[case] port: u16,
        #[case] as_addr: &str,
    ) {
        let addr = TargetAddr::parse(repr, None).unwrap();
        assert_eq!(addr.scheme(), scheme);
        assert_eq!(addr.host(), host);
        assert_eq!(addr.host_ip(), ip);
        assert_eq!(addr.port(), port);
        assert_eq!(addr.as_addr(), as_addr);
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
