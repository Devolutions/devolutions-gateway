use url::Url;

/// How the Gateway's internal client should reach the target, provisioned alongside the credentials.
///
/// `krb_kdc` is validated as a URL at construction — supported scheme, host, explicit port, and no
/// userinfo/path/query/fragment — so CredSSP can use it directly without re-checking or failing late.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawTargetConnectionOptions")]
pub(crate) struct TargetConnectionOptions {
    krb_kdc: Option<Url>,
}

impl TargetConnectionOptions {
    pub(crate) fn new(krb_kdc: Option<&str>) -> Result<Self, InvalidKdcAddr> {
        let krb_kdc = match krb_kdc {
            Some(raw) => Some(parse_krb_kdc(raw)?),
            None => None,
        };
        Ok(Self { krb_kdc })
    }

    pub(crate) fn krb_kdc(&self) -> Option<&Url> {
        self.krb_kdc.as_ref()
    }
}

pub(crate) fn is_supported_krb_kdc_scheme(scheme: &str) -> bool {
    matches!(scheme, "tcp" | "udp")
}

/// Parse and validate a KDC address for the target-side CredSSP leg.
///
/// URL syntax is authoritative. Values that `TargetAddr` would accept but `Url` would split
/// differently (e.g. `tcp://dc.example/path:88`) are rejected here.
fn parse_krb_kdc(raw: &str) -> Result<Url, InvalidKdcAddr> {
    let url = Url::parse(raw).map_err(|_| InvalidKdcAddr::NotAUrl(raw.to_owned()))?;

    if !is_supported_krb_kdc_scheme(url.scheme()) {
        return Err(InvalidKdcAddr::UnsupportedScheme(url.scheme().to_owned()));
    }

    if url.host_str().is_none_or(str::is_empty) {
        return Err(InvalidKdcAddr::MissingHost(raw.to_owned()));
    }

    if url.port().is_none() {
        return Err(InvalidKdcAddr::MissingPort(raw.to_owned()));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(InvalidKdcAddr::UnexpectedComponents(raw.to_owned()));
    }

    // `Url` normalizes a bare authority to path "/" for some schemes; both mean "no path".
    let path = url.path();
    if !path.is_empty() && path != "/" {
        return Err(InvalidKdcAddr::UnexpectedComponents(raw.to_owned()));
    }

    if url.query().is_some() || url.fragment().is_some() {
        return Err(InvalidKdcAddr::UnexpectedComponents(raw.to_owned()));
    }

    Ok(url)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InvalidKdcAddr {
    #[error("unsupported kdc protocol: {0}")]
    UnsupportedScheme(String),
    #[error("kdc address is missing a host: {0}")]
    MissingHost(String),
    #[error("kdc address is missing a port: {0}")]
    MissingPort(String),
    #[error("kdc address is not a valid url: {0}")]
    NotAUrl(String),
    #[error("kdc address must not include userinfo, path, query, or fragment: {0}")]
    UnexpectedComponents(String),
}

#[derive(Deserialize)]
struct RawTargetConnectionOptions {
    #[serde(default)]
    krb_kdc: Option<String>,
}

impl TryFrom<RawTargetConnectionOptions> for TargetConnectionOptions {
    type Error = InvalidKdcAddr;

    fn try_from(raw: RawTargetConnectionOptions) -> Result<Self, Self::Error> {
        Self::new(raw.krb_kdc.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_options(krb_kdc: &str) -> Result<TargetConnectionOptions, serde_json::Error> {
        serde_json::from_value(serde_json::json!({ "krb_kdc": krb_kdc }))
    }

    #[test]
    fn accepts_supported_kdc_protocols() {
        for krb_kdc in ["tcp://dc.example.com:88", "udp://dc.example.com:88"] {
            let options = parse_options(krb_kdc).expect("supported KDC protocol should deserialize");
            assert_eq!(
                options.krb_kdc().expect("KDC address should be present").as_str(),
                krb_kdc
            );
        }
    }

    #[test]
    fn rejects_unsupported_kdc_protocol() {
        let error = parse_options("https://dc.example.com:443").expect_err("unsupported KDC protocol");
        assert!(error.to_string().contains("unsupported kdc protocol: https"));
    }

    #[test]
    fn rejects_kdc_without_a_host() {
        assert!(
            parse_options("tcp://:88").is_err(),
            "a host-less KDC address must be rejected at provisioning time"
        );
    }

    #[test]
    fn rejects_kdc_without_a_port() {
        let error = parse_options("tcp://dc.example.com").expect_err("port is required");
        assert!(error.to_string().contains("missing a port"));
    }

    #[test]
    fn rejects_path_that_target_addr_would_misparse() {
        // TargetAddr would treat the host as `dc.example/path`; Url treats `/path:88` as a path
        // and leaves the port unset. Either way provisioning must fail.
        let error = parse_options("tcp://dc.example/path:88").expect_err("path must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("missing a port") || message.contains("must not include"),
            "{message}"
        );
    }

    #[test]
    fn rejects_explicit_path_with_port() {
        let error = parse_options("tcp://dc.example.com:88/extra").expect_err("path must be rejected");
        assert!(error.to_string().contains("must not include"));
    }

    #[test]
    fn rejects_userinfo_query_and_fragment() {
        for krb_kdc in [
            "tcp://user@dc.example.com:88",
            "tcp://user:pass@dc.example.com:88",
            "tcp://dc.example.com:88?x=1",
            "tcp://dc.example.com:88#frag",
        ] {
            let error = parse_options(krb_kdc).expect_err("extra URL components must be rejected");
            assert!(
                error.to_string().contains("must not include"),
                "unexpected error for {krb_kdc}: {error}"
            );
        }
    }

    #[test]
    fn new_rejects_unsupported_scheme_for_in_crate_callers() {
        assert!(TargetConnectionOptions::new(Some("https://dc.example.com:443")).is_err());
    }
}
