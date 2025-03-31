use std::net::IpAddr;

use super::NetworkInterface;

#[derive(Debug, Clone)]
pub struct Filter {
    pub ignore_ipv6: bool,
    pub include_loopback: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            ignore_ipv6: true,
            include_loopback: false,
        }
    }
}

impl Filter {
    pub fn matches(&self, interface: &NetworkInterface) -> bool {
        // 1. Loopback exclusion
        if !self.include_loopback {
            for addr in &interface.routes {
                if let IpAddr::V4(ipv4) = addr.ip {
                    if ipv4.octets()[0] == 127 {
                        return false;
                    }
                }
            }
        }

        true
    }

    pub fn clean(&self, interfaces: &mut NetworkInterface) {
        if self.ignore_ipv6 {
            interfaces.routes.retain(|addr| matches!(addr.ip, IpAddr::V4(_)));
            interfaces.ip_adresses.retain(|addr| matches!(addr, IpAddr::V4(_)));
        }
    }
}
