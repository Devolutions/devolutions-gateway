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
/// A hostname matching an advertised explicit DNS route is allowed on its own: the Gateway routes
/// hostnames on the DNS advertisement alone, so advertising names and no subnets has
/// to work. Anything else has to land in an advertised subnet, and only IPv4 subnets
/// travel on the wire, so an IPv6 address only ever gets through on a DNS-route match.
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

#[cfg(test)]
mod tests {
    use agent_tunnel_proto::DomainName;

    use super::*;

    fn subnets(list: &[&str]) -> Vec<Ipv4Network> {
        list.iter().map(|s| s.parse().expect("valid subnet")).collect()
    }

    fn domains(list: &[&str]) -> Vec<DomainAdvertisement> {
        list.iter()
            .map(|d| DomainAdvertisement {
                domain: DomainName::new(*d),
                auto_detected: false,
            })
            .collect()
    }

    // The Gateway routes a matching DNS advertisement alone, so an agent advertising
    // DNS routes and no subnets still has to honour the request.
    #[tokio::test]
    async fn domain_target_matching_advertised_domain_needs_no_subnet() {
        let target = Target::parse("localhost:3389").expect("parse target");

        let resolved = resolve_target(&target, &[], &domains(&["localhost"]))
            .await
            .expect("hostname matches an advertised DNS route");

        assert!(!resolved.is_empty(), "expected at least one resolved address");
    }

    #[tokio::test]
    async fn domain_target_falls_back_to_advertised_subnets() {
        let target = Target::Domain("127.0.0.1".to_owned(), 3389);

        let resolved = resolve_target(&target, &subnets(&["127.0.0.0/8"]), &[])
            .await
            .expect("resolved address is inside an advertised subnet");

        assert_eq!(resolved, vec!["127.0.0.1:3389".parse().expect("parse addr")]);
    }

    #[tokio::test]
    async fn domain_target_matching_neither_domain_nor_subnet_is_rejected() {
        let target = Target::Domain("127.0.0.1".to_owned(), 3389);

        let error = resolve_target(&target, &[], &[])
            .await
            .expect_err("nothing is advertised");

        assert!(
            format!("{error:#}").contains("no address this agent advertises"),
            "unexpected error: {error:#}"
        );
    }
}
