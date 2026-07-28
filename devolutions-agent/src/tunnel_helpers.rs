use std::net::{IpAddr, SocketAddr};

use agent_tunnel_proto::DomainAdvertisement;
use anyhow::{Context as _, bail};
use ipnetwork::Ipv4Network;
use tokio::net::TcpStream;

/// Parsed connection target — either a raw IP or a domain name.
#[derive(Debug)]
pub(crate) enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl Target {
    /// Parse a `host:port` string into a typed target.
    pub(crate) fn parse(target: &str) -> anyhow::Result<Self> {
        // Try IP:port first (handles both IPv4 and IPv6).
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr.ip(), addr.port()));
        }

        // Otherwise it's domain:port — split on last ':'.
        let (host, port_str) = target
            .rsplit_once(':')
            .with_context(|| format!("target missing port: {target}"))?;
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in target: {target}"))?;

        Ok(Self::Domain(host.to_owned(), port))
    }
}

/// Resolve a target to candidate socket addresses the agent is willing to reach.
///
/// A hostname matching an advertised domain is allowed on its own: the Gateway routes
/// hostnames on the domain advertisement alone, so advertising domains and no subnets has
/// to work. Anything else has to land in an advertised subnet, and only IPv4 subnets
/// travel on the wire, so an IPv6 address only ever gets through on a domain match.
pub(crate) async fn resolve_target(
    target: &Target,
    advertise_subnets: &[Ipv4Network],
    advertise_domains: &[DomainAdvertisement],
) -> anyhow::Result<Vec<SocketAddr>> {
    fn in_subnets(advertise_subnets: &[Ipv4Network], ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => advertise_subnets.iter().any(|subnet| subnet.contains(ipv4)),
            IpAddr::V6(_) => false,
        }
    }

    match target {
        Target::Ip(ip, port) => {
            if !in_subnets(advertise_subnets, *ip) {
                bail!("target {ip}:{port} is not in advertised subnets");
            }
            Ok(vec![SocketAddr::new(*ip, *port)])
        }
        Target::Domain(host, port) => {
            let lookup = format!("{host}:{port}");
            let resolved = tokio::net::lookup_host(&lookup)
                .await
                .with_context(|| format!("resolve target {lookup}"))?;

            let allowed: Vec<SocketAddr> = if advertise_domains.iter().any(|adv| adv.domain.matches_hostname(host)) {
                resolved.collect()
            } else {
                resolved
                    .filter(|addr| in_subnets(advertise_subnets, addr.ip()))
                    .collect()
            };

            if allowed.is_empty() {
                bail!("target {lookup} resolved to no address this agent advertises");
            }

            Ok(allowed)
        }
    }
}

/// Try connecting to each candidate in order, return the first success.
pub(crate) async fn connect_to_target(candidates: &[SocketAddr]) -> anyhow::Result<(TcpStream, SocketAddr)> {
    let mut last_error = None;

    for candidate in candidates {
        match TcpStream::connect(candidate).await {
            Ok(stream) => return Ok((stream, *candidate)),
            Err(error) => last_error = Some((candidate, error)),
        }
    }

    let Some((candidate, error)) = last_error else {
        bail!("no target candidates available");
    };

    Err(error).with_context(|| format!("TCP connect failed for {candidate}"))
}
