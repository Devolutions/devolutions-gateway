use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use network_interface::{Addr, NetworkInterfaceConfig, V4IfAddr};

#[derive(Debug, Clone)]
pub enum IpAddrRange {
    V4(IpV4AddrRange),
    V6(IpV6AddrRange),
}

impl TryFrom<&str> for IpAddrRange {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid IP range format, expected 'lower-upper', got '{}'", value);
        }
        let lower = parts[0].parse::<IpAddr>()?;
        let upper = parts[1].parse::<IpAddr>()?;

        match (lower, upper) {
            (IpAddr::V4(lower), IpAddr::V4(upper)) => Ok(IpAddrRange::new_ipv4(lower, upper)),
            (IpAddr::V6(lower), IpAddr::V6(upper)) => Ok(IpAddrRange::new_ipv6(lower, upper)),
            _ => anyhow::bail!("IP address types do not match"),
        }
    }
}

impl TryFrom<&String> for IpAddrRange {
    type Error = anyhow::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct IpV4AddrRange {
    lower: Ipv4Addr,
    upper: Ipv4Addr,
}

impl IntoIterator for IpV4AddrRange {
    type Item = Ipv4Addr;

    type IntoIter = IpV4RangeIterator;

    fn into_iter(self) -> Self::IntoIter {
        IpV4RangeIterator {
            current: Some(self.lower),
            upper: self.upper,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpV6AddrRange {
    lower: Ipv6Addr,
    upper: Ipv6Addr,
}

impl IntoIterator for IpV6AddrRange {
    type Item = Ipv6Addr;

    type IntoIter = IpV6RangeIterator;

    fn into_iter(self) -> Self::IntoIter {
        IpV6RangeIterator {
            current: Some(self.lower),
            upper: self.upper,
        }
    }
}

impl IpV4AddrRange {
    pub fn new(lower: Ipv4Addr, upper: Ipv4Addr) -> Self {
        let (lower, upper) = if u32::from(lower) > u32::from(upper) {
            (upper, lower)
        } else {
            (lower, upper)
        };
        Self { lower, upper }
    }
}

impl IpV6AddrRange {
    pub fn new(lower: Ipv6Addr, upper: Ipv6Addr) -> Self {
        let (lower, upper) = if u128::from(lower) > u128::from(upper) {
            (upper, lower)
        } else {
            (lower, upper)
        };
        Self { lower, upper }
    }
}

pub struct IpV4RangeIterator {
    current: Option<Ipv4Addr>,
    upper: Ipv4Addr,
}
pub struct IpV6RangeIterator {
    current: Option<Ipv6Addr>,
    upper: Ipv6Addr,
}

impl Iterator for IpV4RangeIterator {
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

// // Implement Iterator for IPv6 range
impl Iterator for IpV6RangeIterator {
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
    pub fn new_ipv4(lower: Ipv4Addr, upper: Ipv4Addr) -> Self {
        IpAddrRange::V4(IpV4AddrRange::new(Ipv4Addr::from(upper), Ipv4Addr::from(lower)))
    }

    pub fn new_ipv6(lower: Ipv6Addr, upper: Ipv6Addr) -> Self {
        IpAddrRange::V6(IpV6AddrRange::new(Ipv6Addr::from(upper), Ipv6Addr::from(lower)))
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
            IpAddrRange::V4(range) => IpAddrRangeIter::V4(range.into_iter()),
            IpAddrRange::V6(range) => IpAddrRangeIter::V6(range.into_iter()),
        }
    }
}

// Enum for the iterator
pub enum IpAddrRangeIter {
    V4(IpV4RangeIterator),
    V6(IpV6RangeIterator),
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
        Self::from(&value)
    }
}

impl From<&Subnet> for IpAddrRange {
    fn from(value: &Subnet) -> Self {
        let (lower, upper) = calculate_subnet_bounds(value.ip, value.netmask);
        IpAddrRange::new_ipv4(lower.into(), upper.into())
    }
}

// Converting from V4IfAddr to IPv4 range
impl TryFrom<V4IfAddr> for IpAddrRange {
    type Error = anyhow::Error;

    fn try_from(value: V4IfAddr) -> Result<Self, Self::Error> {
        let V4IfAddr { ip, netmask, .. } = value;
        let netmask = netmask.ok_or_else(|| anyhow::anyhow!("No netmask found"))?;
        let (lower, upper) = calculate_subnet_bounds(ip, netmask);
        Ok(IpAddrRange::new_ipv4(lower, upper))
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
    let interfaces = network_interface::NetworkInterface::show().context("failed to get network interfaces")?;

    let subnets: Vec<_> = interfaces
        .into_iter()
        .flat_map(|interface| {
            interface.addr.into_iter().filter_map(|addr| {
                match addr {
                    Addr::V4(v4) => {
                        // Skip loopback or link-local
                        if v4.ip.is_loopback() || v4.ip.is_link_local() {
                            return None;
                        } // Only keep if broadcast is present
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
        let upper = "10.10.0.30".parse::<Ipv4Addr>().unwrap();
        let range = IpAddrRange::new_ipv4(lower.into(), upper.into());

        let mut iter = range.into_iter();
        for i in 0..31 {
            let expected = format!("10.10.0.{i}").parse::<Ipv4Addr>().unwrap();
            assert_eq!(iter.next(), Some(IpAddr::V4(expected)));
        }
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_has_overlap() {
        let r1 = IpAddrRange::new_ipv4("192.168.1.0".parse().unwrap(), "192.168.1.255".parse().unwrap());
        let r2 = IpAddrRange::new_ipv4("192.168.1.100".parse().unwrap(), "192.168.2.10".parse().unwrap());
        assert!(r1.has_overlap(&r2));
    }

    #[test]
    fn test_subnet_to_ip_range() {
        let subnet = Subnet {
            ip: Ipv4Addr::new(192, 168, 1, 0),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
        };

        let ip_range = IpAddrRange::from(subnet);

        let mut iter = ip_range.into_iter();

        for i in 0..256 {
            let expected = format!("192.168.1.{i}").parse::<Ipv4Addr>().unwrap();
            assert_eq!(iter.next(), Some(IpAddr::V4(expected)));
        }
    }
}
