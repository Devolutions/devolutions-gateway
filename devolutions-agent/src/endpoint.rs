//! Helpers for parsing `host:port` endpoint strings used by the agent tunnel.
//!
//! The agent persists gateway endpoints as `format_endpoint(host, port)` (see
//! [`crate::enrollment::format_endpoint`]) — DNS / IPv4 stay as-is, IPv6
//! literals are wrapped in brackets: `[fd00::7]:4433`.
//!
//! When that string is later split back into `(host, port)` we MUST drop the
//! brackets from the IPv6 host before passing it to Rustls / Quinn: Rustls'
//! [`rustls_pki_types::ServerName`] does not accept a bracketed IPv6 literal,
//! and a naive `rsplit_once(':')` would leave `[fd00::7]` as the "host" half.
//!
//! Both `tunnel.rs` (runtime) and `verify_tunnel` (one-shot probe) need this
//! same split, hence the shared module.

use anyhow::{Context as _, Result, bail};

/// The host part of a parsed endpoint, ready to be used as a TLS server name
/// and/or DNS-resolved.
///
/// IPv6 literals are returned **without** surrounding brackets — that's the
/// form Rustls expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHost(String);

impl EndpointHost {
    /// View the host as a plain string (no brackets for IPv6 literals).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EndpointHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Split a `host:port` endpoint string into its host and port components.
///
/// Accepts:
/// - `gateway.example.com:4433` (DNS)
/// - `10.10.0.7:4433` (IPv4)
/// - `[fd00::7]:4433` (IPv6 literal, bracketed)
///
/// The returned host is always unbracketed — safe to pass to
/// [`rustls_pki_types::ServerName::try_from`] and to DNS resolvers. The full
/// original string (with brackets, if any) is still appropriate for
/// `tokio::net::lookup_host` because both bracketed and unbracketed IPv6
/// `host:port` forms are accepted there; callers that already have the raw
/// endpoint can keep using it directly for lookup.
pub fn split_endpoint(endpoint: &str) -> Result<(EndpointHost, u16)> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        bail!("endpoint is empty");
    }

    // IPv6 bracketed form first: "[<host>]:<port>".
    if let Some(after_open) = trimmed.strip_prefix('[') {
        let (host_part, rest) = after_open
            .split_once(']')
            .with_context(|| format!("missing ']' in bracketed endpoint: {endpoint}"))?;
        let port_str = rest
            .strip_prefix(':')
            .with_context(|| format!("missing ':' after ']' in bracketed endpoint: {endpoint}"))?;
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in endpoint: {endpoint}"))?;
        if host_part.is_empty() {
            bail!("empty host inside brackets: {endpoint}");
        }
        return Ok((EndpointHost(host_part.to_owned()), port));
    }

    // Unbracketed: DNS or IPv4. Split on the last ':' — DNS / IPv4 have no
    // other colons in the host part.
    let (host, port_str) = trimmed
        .rsplit_once(':')
        .with_context(|| format!("endpoint missing port: {endpoint}"))?;
    if host.is_empty() {
        bail!("empty host in endpoint: {endpoint}");
    }
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in endpoint: {endpoint}"))?;
    Ok((EndpointHost(host.to_owned()), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_dns_endpoint() {
        let (host, port) = split_endpoint("gateway.example.com:4433").expect("dns");
        assert_eq!(host.as_str(), "gateway.example.com");
        assert_eq!(port, 4433);
    }

    #[test]
    fn split_ipv4_endpoint() {
        let (host, port) = split_endpoint("10.10.0.7:4433").expect("ipv4");
        assert_eq!(host.as_str(), "10.10.0.7");
        assert_eq!(port, 4433);
    }

    #[test]
    fn split_ipv6_bracketed_endpoint_unbrackets_host() {
        let (host, port) = split_endpoint("[fd00::7]:4433").expect("ipv6 bracketed");
        // Critical: the host must NOT include the surrounding brackets so it
        // can be passed straight to `rustls_pki_types::ServerName::try_from`.
        assert_eq!(host.as_str(), "fd00::7");
        assert_eq!(port, 4433);
    }

    #[test]
    fn split_ipv6_bracketed_host_parses_as_rustls_server_name() {
        let (host, _port) = split_endpoint("[fd00::7]:4433").expect("ipv6 bracketed");
        let server_name = rustls_pki_types::ServerName::try_from(host.as_str().to_owned());
        assert!(
            server_name.is_ok(),
            "unbracketed IPv6 literal must be a valid rustls ServerName, got: {:?}",
            server_name.err()
        );
    }

    #[test]
    fn split_dns_host_parses_as_rustls_server_name() {
        let (host, _port) = split_endpoint("gateway.example.com:4433").expect("dns");
        let server_name = rustls_pki_types::ServerName::try_from(host.as_str().to_owned());
        assert!(server_name.is_ok());
    }

    #[test]
    fn split_rejects_missing_port() {
        let err = split_endpoint("gateway.example.com").expect_err("must reject");
        let msg = format!("{err:#}");
        assert!(msg.contains("missing port"), "got: {msg}");
    }

    #[test]
    fn split_rejects_empty_host_brackets() {
        let err = split_endpoint("[]:4433").expect_err("must reject empty brackets");
        let msg = format!("{err:#}");
        assert!(msg.contains("empty host"), "got: {msg}");
    }

    #[test]
    fn split_rejects_unparseable_port() {
        let err = split_endpoint("gateway.example.com:notaport").expect_err("must reject");
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid port"), "got: {msg}");
    }
}
