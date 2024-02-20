use anyhow::Context;
use std::{net::IpAddr, num::NonZeroI32};
use tokio::sync::mpsc::Receiver;

use crate::interfaces::NetworkInterface;
use futures_util::stream::TryStreamExt;
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlag},
    route::{RouteAddress, RouteAttribute, RouteMessage},
};
use rtnetlink::{new_connection, Handle};

pub fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let (link_sender, link_receiver) = crossbeam::channel::unbounded();
    let handle_clone = handle.clone();
    // Retrieve all links, and find the addresses associated with each link
    tokio::spawn(async move {
        let mut receiver = get_all_links(handle.clone()).await?;
        let handle = handle.clone();
        while let Some(mut link) = receiver.recv().await {
            tracing::debug!(raw_link = ?link);
            let handle = handle.clone();

            let mut result = get_address(handle.clone(), link.clone()).await;

            if let Err(rtnetlink::Error::NetlinkError(ref msg)) = result {
                if msg.code.map_or(0, NonZeroI32::get) == -16 {
                    // Linux EBUSY, retry only once
                    tracing::warn!("retrying link address fetch");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    result = get_address(handle, link.clone()).await;
                }
            }

            let addresses = match result {
                Ok(addresses) => addresses,
                Err(e) => {
                    tracing::error!("error getting address: {:?}", e);
                    continue;
                }
            };

            tracing::debug!(addresses= ?addresses);
            let address = addresses
                .iter()
                .map(|addr| AddressInfo::try_from(addr.clone()))
                .collect::<Result<Vec<_>, _>>();

            let Ok(address) = address else {
                tracing::error!("error parsing address: {:?}", address);
                continue;
            };

            link.addresses = address;

            if let Err(e) = link_sender.send(link) {
                tracing::error!("error sending link: {:?}", e);
                break;
            }
        }
        anyhow::Ok(())
    });

    let (router_sender, router_receiver) = crossbeam::channel::unbounded();
    // find all routes
    tokio::spawn(async move {
        let mut routes_v4 = handle_clone.route().get(rtnetlink::IpVersion::V4).execute();
        let route_sender_v4 = router_sender.clone();
        while let Ok(Some(route)) = routes_v4.try_next().await {
            let route_info = match RouteInfo::try_from(route) {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!("error parsing route: {:?}", e);
                    continue;
                }
            };
            route_sender_v4.send(route_info)?;
        }
        let mut routes_v6 = handle_clone.route().get(rtnetlink::IpVersion::V6).execute();
        while let Ok(Some(route)) = routes_v6.try_next().await {
            let route_info = match RouteInfo::try_from(route) {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!("error parsing route: {:?}", e);
                    continue;
                }
            };
            router_sender.send(route_info)?;
        }
        anyhow::Ok(())
    });

    let (dns_sender, dns_receiver) = crossbeam::channel::unbounded();
    // find all nameservers
    tokio::spawn(async move {
        let dns_servers = read_resolve_conf().await?;
        for dns_server in dns_servers {
            dns_sender.send(dns_server)?;
        }
        anyhow::Ok(())
    });

    let mut link_infos = vec![];
    let mut route_infos = vec![];
    let mut dns_servers = vec![];

    while let Ok(link_info) = link_receiver.recv() {
        tracing::debug!(link = ?link_info);
        link_infos.push(link_info);
    }

    while let Ok(route_info) = router_receiver.recv() {
        tracing::debug!(route = ?route_info);
        route_infos.push(route_info);
    }

    while let Ok(dns_server) = dns_receiver.recv() {
        tracing::debug!(dns_server = ?dns_server);
        dns_servers.push(dns_server);
    }

    // assign matching routes to links
    for link_info in &mut link_infos {
        link_info.routes = route_infos
            .iter()
            .filter(|route_info| route_info.index == link_info.index)
            .cloned()
            .collect();
    }

    // if a link can access a dns server, add it to the link
    for link_info in &mut link_infos {
        for dns_server in &dns_servers {
            if link_info.can_access(*dns_server) {
                link_info.dns_servers.push(*dns_server);
            }
        }
    }

    let result: Vec<NetworkInterface> = link_infos
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
    let mut ip_addresses: Vec<IpAddr> = Vec::new();
    let mut prefixes = Vec::new();

    for address_info in &link_info.addresses {
        match address_info.address {
            IpAddr::V4(addr) => ip_addresses.push(addr.into()),
            IpAddr::V6(addr) => ip_addresses.push(addr.into()),
        }
        prefixes.push((address_info.address, address_info.prefix_len as u32));
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
        ip_addresses,
        prefixes,
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
                    Some(mac.to_vec())
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

async fn read_resolve_conf() -> anyhow::Result<Vec<IpAddr>> {
    let mut dns_servers = vec![];
    let file = tokio::fs::read_to_string("/etc/resolv.conf").await?;
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
