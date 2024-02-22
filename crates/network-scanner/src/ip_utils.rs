use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use network_interface::{Addr, NetworkInterfaceConfig, V4IfAddr};

#[derive(Debug, Clone)]
pub struct IpAddrRange {
    lower: IpAddr,
    upper: IpAddr,
}

pub struct IpAddrRangeIter {
    range: IpAddrRange,
    current: Option<IpAddr>,
}

impl IpAddrRangeIter {
    pub fn new(range: IpAddrRange) -> Self {
        Self {
            current: Some(range.lower),
            range,
        }
    }
}

impl Iterator for IpAddrRangeIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current.take()?;
        if current > self.range.upper {
            return None;
        }
        self.current = Some(increment_ip(current));
        Some(current)
    }
}

fn increment_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            for i in (0..4).rev() {
                if octets[i] < 255 {
                    octets[i] += 1;
                    break;
                } else {
                    octets[i] = 0;
                }
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(ip) => {
            let mut segments = ip.segments();
            for i in (0..8).rev() {
                if segments[i] < 0xffff {
                    segments[i] += 1;
                    break;
                } else {
                    segments[i] = 0;
                }
            }
            IpAddr::V6(Ipv6Addr::from(segments))
        }
    }
}

impl IpAddrRange {
    pub fn is_ipv6(&self) -> bool {
        self.lower.is_ipv6() && self.upper.is_ipv6()
    }

    pub fn is_ipv4(&self) -> bool {
        self.lower.is_ipv4() && self.upper.is_ipv4()
    }

    pub fn new(lower: IpAddr, upper: IpAddr) -> anyhow::Result<Self> {
        if lower.is_ipv4() != upper.is_ipv4() {
            anyhow::bail!("IP range needs to be the same type");
        }

        if lower > upper {
            return Ok(Self {
                lower: upper,
                upper: lower,
            });
        }

        Ok(Self { lower, upper })
    }

    fn into_iter_inner(self) -> IpAddrRangeIter {
        IpAddrRangeIter::new(self)
    }

    pub fn has_overlap(&self, other: &Self) -> bool {
        self.lower <= other.upper && self.upper >= other.lower
    }
}

impl IntoIterator for IpAddrRange {
    type Item = IpAddr;
    type IntoIter = IpAddrRangeIter;

    fn into_iter(self) -> Self::IntoIter {
        self.into_iter_inner()
    }
}

impl TryFrom<V4IfAddr> for IpAddrRange {
    type Error = anyhow::Error;

    fn try_from(value: V4IfAddr) -> Result<Self, Self::Error> {
        let V4IfAddr {
            ip,
            broadcast: _,
            netmask,
        } = value;

        let Some(netmask) = netmask else {
            anyhow::bail!("Network interface does not have a netmask");
        };

        let (lower, upper) = calculate_subnet_bounds(ip, netmask);

        Self::new(lower.into(), upper.into())
    }
}

impl From<Subnet> for IpAddrRange {
    fn from(value: Subnet) -> Self {
        let Subnet { ip, netmask, .. } = value;

        let (lower, upper) = calculate_subnet_bounds(ip, netmask);
        Self::new(lower.into(), upper.into()).unwrap()
    }
}

impl From<&Subnet> for IpAddrRange {
    fn from(value: &Subnet) -> Self {
        let Subnet { ip, netmask, .. } = value;

        let (lower, upper) = calculate_subnet_bounds(*ip, *netmask);
        Self::new(lower.into(), upper.into()).unwrap()
    }
}

fn calculate_subnet_bounds(ip: Ipv4Addr, netmask: Ipv4Addr) -> (Ipv4Addr, Ipv4Addr) {
    let ip_u32 = u32::from(ip);
    let netmask_u32 = u32::from(netmask);

    // Calculate Network Address (Lower IP)
    let network_address = Ipv4Addr::from(ip_u32 & netmask_u32);

    // Calculate Broadcast Address (Upper IP)
    let wildcard_mask = !netmask_u32;
    let broadcast_address = Ipv4Addr::from(ip_u32 | wildcard_mask);

    (network_address, broadcast_address)
}

#[derive(Debug, Clone)]
pub struct Subnet {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
}

pub fn get_subnets() -> anyhow::Result<Vec<Subnet>> {
    let interfaces = network_interface::NetworkInterface::show().context("failed to get network interfaces")?;

    let subnet: Vec<_> = interfaces
        .into_iter()
        .map(|interface| {
            interface
                .addr
                .into_iter()
                .filter_map(|addr| {
                    let addr = match addr {
                        Addr::V4(v4) => {
                            if v4.ip.is_loopback() || v4.ip.is_link_local() {
                                return None;
                            }
                            v4
                        }
                        Addr::V6(_) => return None,
                    };

                    if addr.broadcast.is_some() {
                        Some(addr)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .flat_map(|addrs| addrs.into_iter())
        .map(|addr| {
            let ip = addr.ip;
            let netmask = addr.netmask.unwrap();
            let broadcast = addr.broadcast.unwrap();
            Subnet { ip, netmask, broadcast }
        })
        .collect();

    Ok(subnet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_v4_if_addr() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let netmask = Ipv4Addr::new(255, 255, 255, 0);
        let broadcast = Ipv4Addr::new(192, 168, 1, 255);
        let v4_if_addr = V4IfAddr {
            ip,
            broadcast: Some(broadcast),
            netmask: Some(netmask),
        };

        let range = IpAddrRange::try_from(v4_if_addr).unwrap();

        assert_eq!(range.lower, "192.168.1.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(range.upper, broadcast);
    }

    #[test]
    fn test_from_bad_v4_if_addr() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let bad_v4_if_addr = V4IfAddr {
            ip,
            broadcast: None,
            netmask: None,
        };

        let range = IpAddrRange::try_from(bad_v4_if_addr);
        assert!(range.is_err());
    }

    #[test]
    fn test_iter_ipv4() {
        let lower = "10.10.0.0".parse::<Ipv4Addr>().unwrap();
        let upper = "10.10.0.2".parse::<Ipv4Addr>().unwrap();

        let range = IpAddrRange::new(lower.into(), upper.into()).unwrap();

        let mut iter = range.into_iter();

        assert_eq!(iter.next(), Some(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 0))));
        assert_eq!(iter.next(), Some(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1))));
        assert_eq!(iter.next(), Some(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 2))));
        assert_eq!(iter.next(), None);
    }
}
