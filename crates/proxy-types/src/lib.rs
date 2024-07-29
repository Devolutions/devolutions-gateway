use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// Bounded address (used in responses)
pub type BoundAddr = DestAddr;

impl DestAddr {
    pub fn as_ip(&self) -> Option<SocketAddr> {
        match self {
            DestAddr::Ip(ip) => Some(*ip),
            _ => None,
        }
    }

    pub fn as_domain(&self) -> Option<(&str, u16)> {
        match self {
            DestAddr::Domain(dns, port) => Some((dns, *port)),
            _ => None,
        }
    }
}

/// A trait to convert to `TargetAddr` (destination) similar to `std::net::ToSocketAddrs`
pub trait ToDestAddr {
    fn to_dest_addr(&self) -> io::Result<DestAddr>;
}

impl ToDestAddr for DestAddr {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        Ok(self.clone())
    }
}

impl ToDestAddr for SocketAddr {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        Ok(DestAddr::Ip(*self))
    }
}

impl ToDestAddr for SocketAddrV4 {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        Ok(DestAddr::Ip(SocketAddr::V4(*self)))
    }
}

impl ToDestAddr for SocketAddrV6 {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        Ok(DestAddr::Ip(SocketAddr::V6(*self)))
    }
}

impl ToDestAddr for (Ipv4Addr, u16) {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        Ok(DestAddr::Ip(SocketAddr::V4(SocketAddrV4::new(self.0, self.1))))
    }
}

impl ToDestAddr for (Ipv6Addr, u16) {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        Ok(DestAddr::Ip(SocketAddr::V6(SocketAddrV6::new(self.0, self.1, 0, 0))))
    }
}

impl ToDestAddr for (&str, u16) {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        if let Ok(addr) = self.0.parse::<Ipv4Addr>() {
            return (addr, self.1).to_dest_addr();
        }

        if let Ok(addr) = self.0.parse::<Ipv6Addr>() {
            return (addr, self.1).to_dest_addr();
        }

        Ok(DestAddr::Domain(self.0.to_owned(), self.1))
    }
}

impl ToDestAddr for &str {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        if let Ok(addr) = self.parse::<SocketAddrV4>() {
            return addr.to_dest_addr();
        }

        if let Ok(addr) = self.parse::<SocketAddrV6>() {
            return addr.to_dest_addr();
        }

        let (host, port) = self
            .rsplit_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad socket address format"))?;

        let host = host.to_owned();
        let port = port
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid port value: {e}")))?;

        Ok(DestAddr::Domain(host, port))
    }
}

impl ToDestAddr for String {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        self.as_str().to_dest_addr()
    }
}

impl<T: ToDestAddr + ?Sized> ToDestAddr for &T {
    fn to_dest_addr(&self) -> io::Result<DestAddr> {
        (**self).to_dest_addr()
    }
}
