use std::net::IpAddr;

use anyhow::Context;
use futures::stream::TryStreamExt;

use tokio::sync::mpsc::Receiver;

use crate::interfaces::NetworkInterface;
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
    tokio::spawn(async move {
        let mut receiver = get_all_links(handle.clone()).await?;
        let handle = handle.clone();
        while let Some(mut link) = receiver.recv().await {
            tracing::debug!(raw_link = ?link);
            let handle = handle.clone();
            let addresses = match get_address(handle, link.clone()).await {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!("Error getting address: {:?}", e);
                    continue;
                }
            };

            tracing::debug!(addresses= ?addresses);
            link.addresses = addresses
                .iter()
                .map(|addr| AddressInfo::try_from(addr.clone()).unwrap())
                .collect();

            link_sender.send(link).unwrap();
        }
        anyhow::Ok(())
    });

    let (router_sender, router_receiver) = crossbeam::channel::unbounded();
    tokio::spawn(async move {
        let mut routes_v4 = handle_clone.route().get(rtnetlink::IpVersion::V4).execute();
        let route_sender_v4 = router_sender.clone();
        while let Ok(Some(route)) = routes_v4.try_next().await {
            let route_info = match RouteInfo::try_from(route) {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!("Error parsing route: {:?}", e);
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
                    tracing::error!("Error parsing route: {:?}", e);
                    continue;
                }
            };
            router_sender.send(route_info)?;
        }
        anyhow::Ok(())
    });

    let mut link_infos = vec![];
    let mut route_infos = vec![];

    while let Ok(link_info) = link_receiver.recv() {
        tracing::debug!(link = ?link_info);
        link_infos.push(link_info);
    }

    while let Ok(route_info) = router_receiver.recv() {
        tracing::debug!(route = ?route_info);
        route_infos.push(route_info);
    }

    for link_info in &mut link_infos {
        for route_info in &route_infos {
            if route_info.index == link_info.index {
                link_info.routes.push(route_info.clone());
            }
        }
    }

    anyhow::Ok(link_infos.iter().map(|link_info| link_info.into()).collect())
}

impl From<&LinkInfo> for NetworkInterface {
    fn from(link_info: &LinkInfo) -> NetworkInterface {
        convert_link_info_to_network_interface(link_info)
    }
}

fn convert_link_info_to_network_interface(link_info: &LinkInfo) -> NetworkInterface {
    let mut ipv4_address = Vec::new();
    let mut ipv6_address = Vec::new();
    let mut prefixes = Vec::new();

    for address_info in &link_info.addresses {
        match address_info.address {
            IpAddr::V4(addr) => ipv4_address.push(addr),
            IpAddr::V6(addr) => ipv6_address.push(addr),
        }
        prefixes.push((address_info.address, address_info.prefix_len as u32));
    }

    let default_gateway = link_info
        .routes
        .iter()
        .filter_map(|route_info| route_info.gateway)
        .collect();

    NetworkInterface {
        name: link_info.name.clone(),
        description: None,
        mac_address: vec![link_info.mac],
        ipv4_address,
        ipv6_address,
        prefixes,
        operational_status: link_info.flags.contains(&LinkFlag::Up),
        default_gateway,
        dns_servers: vec![], // TODO: Implement DNS server lookup
    }
}

#[derive(Debug, Clone, Default)]
struct LinkInfo {
    mac: [u8; 6],
    flags: Vec<LinkFlag>,
    name: String,
    index: u32,
    addresses: Vec<AddressInfo>,
    routes: Vec<RouteInfo>,
}

#[derive(Debug, Clone)]
struct AddressInfo {
    address: IpAddr,
    prefix_len: u8,
}

#[derive(Debug, Clone)]
struct RouteInfo {
    gateway: Option<IpAddr>,
    index: u32,
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
            .context("No index found")?;

        let route_info = RouteInfo { gateway, index };

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
            .context("No address found")?;

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
                    Some([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]])
                } else {
                    None
                }
            })
            .context("No mac address found")?;

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

async fn get_address(handle: Handle, link_info: LinkInfo) -> anyhow::Result<Vec<AddressMessage>> {
    let mut res = vec![];

    let mut addr_stream = handle.address().get().set_link_index_filter(link_info.index).execute();

    while let Some(msg) = addr_stream.try_next().await? {
        res.push(msg);
    }

    anyhow::Ok(res)
}
