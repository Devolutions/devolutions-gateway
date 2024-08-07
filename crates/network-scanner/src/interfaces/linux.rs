use anyhow::Context;
use std::net::IpAddr;
use std::num::NonZeroI32;
use tokio::sync::mpsc::Receiver;

use crate::interfaces::NetworkInterface;
use futures_util::stream::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlag};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::{new_connection, Handle};

use super::InterfaceAddress;

pub async fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    let mut links_info = vec![];
    let mut routes_info = vec![];

    // Retrieve all links, and find the addresses associated with each link
    let mut receiver = get_all_links(handle.clone()).await?;
    let handle = handle.clone();
    while let Some(mut link) = receiver.recv().await {
        debug!(raw_link = ?link);
        let handle = handle.clone();

        let mut result = get_address(handle.clone(), link.clone()).await;
        if let Err(rtnetlink::Error::NetlinkError(ref msg)) = result {
            if msg.code.map_or(0, NonZeroI32::get) == -16 {
                // Linux EBUSY, retry only once.
                warn!(error = %msg, %link.name, "Retrying link address fetch");
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                result = get_address(handle, link.clone()).await;
            }
        }

        let addresses = match result {
            Ok(addresses) => addresses,
            Err(error) => {
                error!(%error, %link.name, "Failed to get the address for the interface");
                continue;
            }
        };

        debug!(?addresses);

        let address = addresses
            .iter()
            .map(|addr| AddressInfo::try_from(addr.clone()))
            .collect::<Result<Vec<_>, _>>()
            .inspect_err(|e| error!(error = format!("{e:#}"), "Failed to parse address info"));

        let Ok(address) = address else {
            continue;
        };

        link.addresses = address;
        links_info.push(link);
    }

    let mut routes_v4 = handle.route().get(rtnetlink::IpVersion::V4).execute();
    while let Ok(Some(route)) = routes_v4.try_next().await {
        let info = match RouteInfo::try_from(route) {
            Ok(res) => res,
            Err(e) => {
                error!(error = format!("{e:#}"), "Failed to parse the route");
                continue;
            }
        };

        routes_info.push(info);
    }

    let mut routes_v6 = handle.route().get(rtnetlink::IpVersion::V6).execute();
    while let Ok(Some(route)) = routes_v6.try_next().await {
        let info = match RouteInfo::try_from(route) {
            Ok(res) => res,
            Err(e) => {
                error!(error = format!("{e:#}"), "Failed to parse route info");
                continue;
            }
        };
        routes_info.push(info);
    }

    let dns_servers = read_resolve_conf()?;

    // assign matching routes to links
    for link_info in &mut links_info {
        link_info.routes = routes_info
            .iter()
            .filter(|route_info| route_info.index == link_info.index)
            .cloned()
            .collect();
    }

    // if a link can access a dns server, add it to the link
    for link_info in &mut links_info {
        for dns_server in &dns_servers {
            if link_info.can_access(*dns_server) {
                link_info.dns_servers.push(*dns_server);
            }
        }
    }

    let result: Vec<NetworkInterface> = links_info
        .iter()
        .map(|link_info| link_info.try_into())
        .collect::<Result<Vec<_>, _>>()?;

    anyhow::Ok(result)
}

impl TryFrom<&LinkInfo> for NetworkInterface {
    type Error = anyhow::Error;
    fn try_from(link_info: &LinkInfo) -> Result<NetworkInterface, anyhow::Error> {
        convert_link_info_to_network_interface(link_info)
    }
}

fn convert_link_info_to_network_interface(link_info: &LinkInfo) -> anyhow::Result<NetworkInterface> {
    let mut addresses = Vec::new();

    for address_info in &link_info.addresses {
        addresses.push((address_info.address, u32::from(address_info.prefix_len)));
    }

    let gateways = link_info
        .routes
        .iter()
        .filter_map(|route_info| route_info.gateway)
        .collect();

    Ok(NetworkInterface {
        name: link_info.name.clone(),
        description: None,
        mac_address: link_info.mac.as_slice().try_into().ok(),
        addresses: addresses
            .into_iter()
            .map(|(addr, prefix)| InterfaceAddress {
                ip: addr,
                prefixlen: prefix,
            })
            .collect(),
        operational_status: link_info.flags.contains(&LinkFlag::Up),
        gateways,
        dns_servers: link_info.dns_servers.clone(),
    })
}

#[derive(Debug, Clone, Default)]
struct LinkInfo {
    mac: Vec<u8>,
    flags: Vec<LinkFlag>,
    name: String,
    index: u32,
    addresses: Vec<AddressInfo>,
    routes: Vec<RouteInfo>,
    dns_servers: Vec<IpAddr>,
}

impl LinkInfo {
    fn can_access(&self, ip: IpAddr) -> bool {
        self.routes.iter().any(|route| route.can_access(ip))
    }
}

#[derive(Debug, Clone)]
struct AddressInfo {
    address: IpAddr,
    prefix_len: u8,
}

#[derive(Debug, Clone)]
struct RouteInfo {
    gateway: Option<IpAddr>,
    destination: Option<IpAddr>,
    destination_prefix: u8,
    index: u32,
}

impl RouteInfo {
    // check routing table to see if the ip can be accessed
    fn can_access(&self, ip: IpAddr) -> bool {
        self.destination
            .map(|destination| is_ip_covered((destination, self.destination_prefix), ip))
            .unwrap_or(false)
            || self.destination_prefix == 0 // default route
    }
}

impl TryFrom<RouteMessage> for RouteInfo {
    type Error = anyhow::Error;

    fn try_from(value: RouteMessage) -> Result<Self, Self::Error> {
        let gateway = value
            .attributes
            .iter()
            .find_map(|attr| {
                if let RouteAttribute::Gateway(gateway) = attr {
                    Some(gateway)
                } else {
                    None
                }
            })
            .and_then(|route_addr| match route_addr {
                RouteAddress::Inet(v4) => Some(IpAddr::from(*v4)),
                RouteAddress::Inet6(v6) => Some(IpAddr::from(*v6)),
                _ => None,
            });

        let index = *value
            .attributes
            .iter()
            .find_map(|attr| {
                if let RouteAttribute::Oif(index) = attr {
                    Some(index)
                } else {
                    None
                }
            })
            .context("no index found")?;

        let destination_prefix = value.header.destination_prefix_length;
        let destination = value
            .attributes
            .iter()
            .find(|attr| matches!(attr, RouteAttribute::Destination(_)))
            .and_then(|attr| {
                if let RouteAttribute::Destination(destination) = attr {
                    match destination {
                        RouteAddress::Inet(v4) => Some(IpAddr::from(*v4)),
                        RouteAddress::Inet6(v6) => Some(IpAddr::from(*v6)),
                        _ => None,
                    }
                } else {
                    None
                }
            });

        let route_info = RouteInfo {
            gateway,
            index,
            destination,
            destination_prefix,
        };

        Ok(route_info)
    }
}

impl TryFrom<AddressMessage> for AddressInfo {
    type Error = anyhow::Error;

    fn try_from(value: AddressMessage) -> Result<Self, Self::Error> {
        let addr = value
            .attributes
            .iter()
            .find_map(|attr| {
                if let AddressAttribute::Address(addr) = attr {
                    Some(addr)
                } else {
                    None
                }
            })
            .context("no address found")?;

        let prefix_len = value.header.prefix_len;

        let address_info = AddressInfo {
            address: *addr,
            prefix_len,
        };

        Ok(address_info)
    }
}

async fn get_all_links(handle: Handle) -> anyhow::Result<Receiver<LinkInfo>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(5);
    let mut links = handle.link().get().execute();
    while let Some(msg) = links.try_next().await? {
        let name = msg.attributes.iter().find_map(|attr| {
            if let LinkAttribute::IfName(name) = attr {
                Some(name.clone())
            } else {
                None
            }
        });

        let Some(name) = name else {
            continue;
        };

        let mac = msg
            .attributes
            .iter()
            .find_map(|attr| {
                if let LinkAttribute::Address(mac) = attr {
                    Some(mac.clone())
                } else {
                    None
                }
            })
            .context("no mac address found")?;

        let index = msg.header.index;
        let flags = msg.header.flags;

        let link_info = LinkInfo {
            mac,
            flags,
            name,
            index,
            ..Default::default()
        };

        sender.send(link_info).await?;
    }

    anyhow::Ok(receiver)
}

async fn get_address(handle: Handle, link_info: LinkInfo) -> Result<Vec<AddressMessage>, rtnetlink::Error> {
    let mut res = vec![];

    let mut addr_stream = handle.address().get().set_link_index_filter(link_info.index).execute();

    while let Some(msg) = addr_stream.try_next().await? {
        res.push(msg);
    }

    Ok(res)
}

fn read_resolve_conf() -> anyhow::Result<Vec<IpAddr>> {
    let mut dns_servers = vec![];
    let file = std::fs::read_to_string("/etc/resolv.conf").inspect_err(|e| {
        error!(error = format!("{e:#}"), "Failed to read /etc/resolv.conf");
    })?;
    for line in file.lines() {
        if line.starts_with("nameserver") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(ip) = parts.get(1) {
                if let Ok(ip) = ip.parse() {
                    dns_servers.push(ip);
                }
            }
        }
    }
    Ok(dns_servers)
}

fn is_ip_covered((prefix_ip, prefix_len): (IpAddr, u8), ip: IpAddr) -> bool {
    match (prefix_ip, ip) {
        (IpAddr::V4(prefix_v4), IpAddr::V4(ipv4)) => {
            let prefix_int = u32::from_be_bytes(prefix_v4.octets());
            let ip_int = u32::from_be_bytes(ipv4.octets());
            let mask = !0u32 << (32 - prefix_len);
            let masked_prefix = prefix_int & mask;
            let masked_ip = ip_int & mask;

            masked_prefix == masked_ip
        }
        (IpAddr::V6(prefix_v6), IpAddr::V6(ipv6)) => {
            let prefix_int = u128::from_be_bytes(prefix_v6.octets());
            let ip_int = u128::from_be_bytes(ipv6.octets());
            let mask = !0u128 << (128 - prefix_len);
            let masked_prefix = prefix_int & mask;
            let masked_ip = ip_int & mask;
            masked_prefix == masked_ip
        }
        _ => false,
    }
}
