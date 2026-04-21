use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context as _, bail};
use ipnetwork::Ipv4Network;
use tokio::net::TcpStream;

/// Parsed connection target — either a raw IP or a domain name.
#[derive(Debug)]
pub(crate) enum Target {
    Ip(Ipv4Addr, u16),
    Domain(String, u16),
}

impl Target {
    /// Parse a `host:port` string into a typed target.
    pub(crate) fn parse(target: &str) -> anyhow::Result<Self> {
        // Try IP:port first.
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return match addr.ip() {
                IpAddr::V4(ip) => Ok(Self::Ip(ip, addr.port())),
                IpAddr::V6(_) => bail!("IPv6 targets are not supported: {target}"),
            };
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

/// Resolve a target to candidate socket addresses within the advertised subnets.
pub(crate) async fn resolve_target(
    target: &Target,
    advertise_subnets: &[Ipv4Network],
) -> anyhow::Result<Vec<SocketAddr>> {
    match target {
        Target::Ip(ip, port) => {
            if !advertise_subnets.iter().any(|subnet| subnet.contains(*ip)) {
                bail!("target {ip}:{port} is not in advertised subnets");
            }
            Ok(vec![SocketAddr::new(IpAddr::V4(*ip), *port)])
        }
        Target::Domain(host, port) => {
            let lookup = format!("{host}:{port}");
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&lookup)
                .await
                .with_context(|| format!("resolve target {lookup}"))?
                .filter(|addr| match addr.ip() {
                    IpAddr::V4(ipv4) => advertise_subnets.iter().any(|subnet| subnet.contains(ipv4)),
                    IpAddr::V6(_) => false,
                })
                .collect();

            if resolved.is_empty() {
                bail!("target {lookup} did not resolve to any address in advertised subnets");
            }

            Ok(resolved)
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
