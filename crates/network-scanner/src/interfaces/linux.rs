use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::interfaces::NetworkInterface;
use pnet::datalink;

pub fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    let mut res = vec![];
    for interface in datalink::interfaces() {
        let interface: crate::interfaces::NetworkInterface = interface.into();
        res.push(interface);
    }

    let file_routes = read_proc_net_route();
    for ref routes in file_routes {
        for interface in &mut res {
            if routes.iface == interface.name {
                interface.complete_from_route(routes)?;
            }
        }
    }

    let dns_servers = parse_dns_servers_from_resolv_conf("/etc/resolv.conf")?;
    // for interface in &mut res {
    //     for dns_server in &dns_servers {
    //         if interface.ip_accessible(dns_server) {
    //             interface.dns_servers.push(dns_server.clone());
    //         }
    //     }
    // }

    Ok(res)
}

impl NetworkInterface {
    fn complete_from_route(&mut self, route: &Route) -> anyhow::Result<()> {
        if self.name != route.iface {
            anyhow::bail!(
                "Route interface {} does not match interface name {}",
                route.iface,
                self.name
            );
        }

        self.default_gateway.push(route.gateway.into());
        self.prefixes.push((route.destination.into(), route.mask));
        Ok(())
    }

    // fn ip_accessible(&self, ip: &IpAddr) -> bool {
    //     if let IpAddr::V4(ipv4) = ip {
    //         for (subnet, prefix) in &self.prefixes {
    //             if let IpAddr::V4(subnet) = subnet {
    //                 if is_ip_in_subnet(*ipv4, *subnet, *prefix) {
    //                     return true;
    //                 }
    //             }
    //         }
    //     }
    //     return false;
    // }
}

// fn is_ip_in_subnet(ip: Ipv4Addr, subnet_ip: Ipv4Addr, prefix: u32) -> bool {
//     println!("ip: {:?}, subnet_ip: {:?}, prefix: {:?}", ip, subnet_ip, prefix);
//     let ip_u32 = u32::from(ip);
//     let subnet_ip_u32 = u32::from(subnet_ip);
//     let mask = !0u32.checked_shl(32 - prefix).unwrap_or(0);

//     (ip_u32 & mask) == (subnet_ip_u32 & mask)
// }

impl From<pnet::datalink::NetworkInterface> for NetworkInterface {
    fn from(interface: pnet::datalink::NetworkInterface) -> Self {
        let operational_status = interface.is_up();

        let pnet::datalink::NetworkInterface {
            name,
            description,
            mac,
            ips,
            ..
        } = interface;

        let ip_v4_addr: Vec<Ipv4Addr> = ips
            .iter()
            .filter_map(|ip| match ip {
                pnet::ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                _ => None,
            })
            .collect();

        let ip_v6_addr: Vec<Ipv6Addr> = ips
            .iter()
            .filter_map(|ip| match ip {
                pnet::ipnetwork::IpNetwork::V6(ipv6) => Some(ipv6.ip()),
                _ => None,
            })
            .collect();

        Self {
            name,
            description: Some(description),
            mac_address: vec![mac
                .map(|mac| vec![mac.0, mac.1, mac.2, mac.3, mac.4, mac.5])
                .unwrap_or_default()],
            default_gateway: vec![],
            dns_servers: vec![],
            ipv4_address: ip_v4_addr,
            ipv6_address: ip_v6_addr,
            operational_status,
            prefixes: vec![],
        }
    }
}

#[derive(Debug)]
struct Route {
    iface: String,
    destination: Ipv4Addr,
    gateway: Ipv4Addr,
    mask: u32,
}

fn read_proc_net_route() -> Vec<Route> {
    let file_path = "/proc/net/route";
    match parse_routes_from_file(file_path) {
        Ok(routes) => routes,
        Err(e) => {
            tracing::warn!("Failed to read route file: {}", e);
            Vec::new()
        }
    }
}

fn parse_route_line(line: &str) -> anyhow::Result<Route> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        anyhow::bail!("Invalid route line: {}", line);
    }

    let iface = parts[0].to_string();
    let destination = parse_hex_ip(parts[1])?;
    let gateway = parse_hex_ip(parts[2])?;
    let mask = u32::from_str_radix(parts[7], 16)?.leading_ones() as u32;

    Ok(Route {
        iface,
        destination,
        gateway,
        mask,
    })
}

fn parse_hex_ip(hex_str: &str) -> anyhow::Result<Ipv4Addr> {
    let ip = u32::from_str_radix(hex_str, 16)?;
    Ok(Ipv4Addr::new(
        (ip & 0xff) as u8,
        ((ip >> 8) & 0xff) as u8,
        ((ip >> 16) & 0xff) as u8,
        ((ip >> 24) & 0xff) as u8,
    ))
}

fn parse_routes_from_file(file_path: &str) -> io::Result<Vec<Route>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut routes = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Ok(route) = parse_route_line(&line) {
            routes.push(route);
        }
    }

    Ok(routes)
}

fn parse_dns_servers_from_resolv_conf(file_path: &str) -> anyhow::Result<Vec<IpAddr>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut dns_servers = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("nameserver") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                match parts[1].parse::<IpAddr>() {
                    Ok(ip_addr) => dns_servers.push(ip_addr),
                    Err(e) => anyhow::bail!("Failed to parse IP address: {}, error: {}", parts[1], e),
                }
            }
        }else{
            anyhow::bail!("Invalid line in resolv.conf: {}", line);
        }
    }

    Ok(dns_servers)
}