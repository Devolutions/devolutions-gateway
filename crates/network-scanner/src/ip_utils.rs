use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use network_interface::{Addr, NetworkInterfaceConfig, V4IfAddr};

#[derive(Debug, Clone)]
pub enum IpAddrRange {
    V4(IpV4AddrRange),
    V6(IpV6AddrRange),
}

#[derive(Debug, Clone)]
pub struct IpV4AddrRange {
    lower: Ipv4Addr,
    upper: Ipv4Addr,
    current: Option<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub struct IpV6AddrRange {
    lower: Ipv6Addr,
    upper: Ipv6Addr,
    current: Option<Ipv6Addr>,
}

impl IpV4AddrRange {
    pub fn new(lower: Ipv4Addr, upper: Ipv4Addr) -> Self {
        let (lower, upper) = if u32::from(lower) > u32::from(upper) {
            (upper, lower)
        } else {
            (lower, upper)
        };
        Self {
            lower,
            upper,
            current: Some(lower),
        }
    }
}

impl IpV6AddrRange {
    pub fn new(lower: Ipv6Addr, upper: Ipv6Addr) -> Self {
        let (lower, upper) = if u128::from(lower) > u128::from(upper) {
            (upper, lower)
        } else {
            (lower, upper)
        };
        Self {
            lower,
            upper,
            current: Some(lower),
        }
    }
}

// Implement Iterator for IPv4 range
impl Iterator for IpV4AddrRange {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        if u32::from(current) > u32::from(self.upper) {
            return None;
        }
        let next = increment_ipv4(current);
        self.current = Some(next);
        Some(current)
    }
}

// Implement Iterator for IPv6 range
impl Iterator for IpV6AddrRange {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        if u128::from(current) > u128::from(self.upper) {
            return None;
        }
        let next = increment_ipv6(current);
        self.current = Some(next);
        Some(current)
    }
}

// Helper to create the appropriate enum variant
impl IpAddrRange {
    pub fn new(lower: IpAddr, upper: IpAddr) -> anyhow::Result<Self> {
        match (lower, upper) {
            (IpAddr::V4(l), IpAddr::V4(u)) => Ok(IpAddrRange::V4(IpV4AddrRange::new(l, u))),
            (IpAddr::V6(l), IpAddr::V6(u)) => Ok(IpAddrRange::V6(IpV6AddrRange::new(l, u))),
            _ => anyhow::bail!("IP range needs to be the same type (both IPv4 or both IPv6)"),
        }
    }

    pub fn has_overlap(&self, other: &Self) -> bool {
        match (self, other) {
            (IpAddrRange::V4(a), IpAddrRange::V4(b)) => {
                u32::from(a.lower) <= u32::from(b.upper) && u32::from(a.upper) >= u32::from(b.lower)
            }
            (IpAddrRange::V6(a), IpAddrRange::V6(b)) => {
                u128::from(a.lower) <= u128::from(b.upper) && u128::from(a.upper) >= u128::from(b.lower)
            }
            _ => false,
        }
    }
}

// Implement IntoIterator for the enum so that it returns an IpAddr
impl IntoIterator for IpAddrRange {
    type Item = IpAddr;
    type IntoIter = IpAddrRangeIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            IpAddrRange::V4(range) => IpAddrRangeIter::V4(range),
            IpAddrRange::V6(range) => IpAddrRangeIter::V6(range),
        }
    }
}

// Enum for the iterator
pub enum IpAddrRangeIter {
    V4(IpV4AddrRange),
    V6(IpV6AddrRange),
}

impl Iterator for IpAddrRangeIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            IpAddrRangeIter::V4(r) => r.next().map(IpAddr::V4),
            IpAddrRangeIter::V6(r) => r.next().map(IpAddr::V6),
        }
    }
}

// Helper to increment an Ipv4Addr
fn increment_ipv4(ip: Ipv4Addr) -> Ipv4Addr {
    let mut octets = ip.octets();
    for i in (0..4).rev() {
        if octets[i] < 255 {
            octets[i] += 1;
            return Ipv4Addr::from(octets);
        }
        octets[i] = 0;
    }
    Ipv4Addr::from(octets)
}

// Helper to increment an Ipv6Addr
fn increment_ipv6(ip: Ipv6Addr) -> Ipv6Addr {
    let mut segments = ip.segments();
    for i in (0..8).rev() {
        if segments[i] < 0xffff {
            segments[i] += 1;
            return Ipv6Addr::from(segments);
        }
        segments[i] = 0;
    }
    Ipv6Addr::from(segments)
}

// Subnet as before
#[derive(Debug, Clone)]
pub struct Subnet {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
}

impl From<Subnet> for IpAddrRange {
    fn from(value: Subnet) -> Self {
        let (lower, upper) = calculate_subnet_bounds(value.ip, value.netmask);
        IpAddrRange::new(lower.into(), upper.into())
            .expect("Subnet bounds must be valid IPv4 addresses")
    }
}

impl From<&Subnet> for IpAddrRange {
    fn from(value: &Subnet) -> Self {
        let (lower, upper) = calculate_subnet_bounds(value.ip, value.netmask);
        IpAddrRange::new(lower.into(), upper.into())
            .expect("Subnet bounds must be valid IPv4 addresses")
    }
}

// Converting from V4IfAddr to IPv4 range
impl TryFrom<V4IfAddr> for IpAddrRange {
    type Error = anyhow::Error;

    fn try_from(value: V4IfAddr) -> Result<Self, Self::Error> {
        let V4IfAddr { ip, netmask, .. } = value;
        let netmask = netmask.ok_or_else(|| anyhow::anyhow!("No netmask found"))?;
        let (lower, upper) = calculate_subnet_bounds(ip, netmask);
        IpAddrRange::new(lower.into(), upper.into())
    }
}

fn calculate_subnet_bounds(ip: Ipv4Addr, netmask: Ipv4Addr) -> (Ipv4Addr, Ipv4Addr) {
    let ip_u32 = u32::from(ip);
    let netmask_u32 = u32::from(netmask);

    // Network Address
    let network_address = Ipv4Addr::from(ip_u32 & netmask_u32);

    // Broadcast Address
    let broadcast_address = Ipv4Addr::from(ip_u32 | !netmask_u32);

    (network_address, broadcast_address)
}

pub fn get_subnets() -> anyhow::Result<Vec<Subnet>> {
    let interfaces = network_interface::NetworkInterface::show()
        .context("failed to get network interfaces")?;

    let subnets: Vec<_> = interfaces
        .into_iter()
        .flat_map(|interface| {
            interface.addr.into_iter().filter_map(|addr| {
                match addr {
                    Addr::V4(v4) => {
                        // Skip loopback or link-local
                        if v4.ip.is_loopback() || v4.ip.is_link_local() {
                            return None;
                        }
                        // Only keep if broadcast is present
                        if v4.broadcast.is_some() {
                            let netmask = v4.netmask?;
                            let broadcast = v4.broadcast?;
                            Some(Subnet {
                                ip: v4.ip,
                                netmask,
                                broadcast,
                            })
                        } else {
                            None
                        }
                    }
                    Addr::V6(_) => None,
                }
            })
        })
        .collect();

    Ok(subnets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iter_ipv4() {
        let lower = "10.10.0.0".parse::<Ipv4Addr>().unwrap();
        let upper = "10.10.0.2".parse::<Ipv4Addr>().unwrap();
        let range = IpAddrRange::new(lower.into(), upper.into()).unwrap();

        let mut iter = range.into_iter();
        assert_eq!(iter.next(), Some("10.10.0.0".parse::<IpAddr>().unwrap()));
        assert_eq!(iter.next(), Some("10.10.0.1".parse::<IpAddr>().unwrap()));
        assert_eq!(iter.next(), Some("10.10.0.2".parse::<IpAddr>().unwrap()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_has_overlap() {
        let r1 = IpAddrRange::new(
            "192.168.1.0".parse().unwrap(),
            "192.168.1.255".parse().unwrap(),
        )
        .unwrap();
        let r2 = IpAddrRange::new(
            "192.168.1.100".parse().unwrap(),
            "192.168.2.10".parse().unwrap(),
        )
        .unwrap();
        assert!(r1.has_overlap(&r2));
    }
}
