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

pub(crate) fn is_loop_back(interface: &NetworkInterface) -> bool {
    for addr in &interface.routes {
        if let IpAddr::V4(ipv4) = addr.ip {
            if ipv4.octets()[0] == 127 {
                return false;
            }
        }
    }

    return true;
}

pub(crate) fn filter_out_ipv6_if(ignore_ipv6: bool, mut interface: NetworkInterface) -> NetworkInterface {
    if ignore_ipv6 {
        interface.routes.retain(|addr| matches!(addr.ip, IpAddr::V4(_)));
        interface.ip_adresses.retain(|addr| matches!(addr, IpAddr::V4(_)));
    }

    interface
}
