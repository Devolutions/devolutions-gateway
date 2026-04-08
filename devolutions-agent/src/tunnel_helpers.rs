use std::net::SocketAddr;

use anyhow::{Context as _, bail};
use ipnetwork::Ipv4Network;
use tokio::net::TcpStream;

/// Resolve a `host:port` target and filter to addresses within advertised subnets.
pub(crate) async fn resolve_target_candidates(
    target: &str,
    advertise_subnets: &[Ipv4Network],
) -> anyhow::Result<Vec<SocketAddr>> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(target)
        .await
        .with_context(|| format!("resolve target {target}"))?
        .collect();

    if resolved.is_empty() {
        bail!("no addresses resolved for target {target}");
    }

    let reachable: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|addr| match addr.ip() {
            std::net::IpAddr::V4(ipv4) => advertise_subnets.iter().any(|subnet| subnet.contains(ipv4)),
            // TODO: Support IPv6.
            std::net::IpAddr::V6(_) => false,
        })
        .collect();

    if reachable.is_empty() {
        bail!("target {target} is not in advertised subnets");
    }

    Ok(reachable)
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

/// Current wall-clock time in milliseconds since UNIX epoch.
pub(crate) fn current_time_millis() -> u64 {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch");

    u64::try_from(elapsed.as_millis()).expect("millisecond timestamp should fit in u64")
}
