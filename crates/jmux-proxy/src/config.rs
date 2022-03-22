use anyhow::Context;
use jmux_proto::DestinationUrl;

/// JMUX proxy configuration struct.
///
/// All parameters are designed to be opt-in rather than opt-out: default values are conservatives
/// and always safe (whitelist approach).
#[derive(Debug, Default, Clone)]
pub struct JmuxConfig {
    /// Rule to use when filtering requests.
    pub filtering: FilteringRule,
}

impl JmuxConfig {
    /// A safe default JMUX configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// The most permissive configuration.
    pub fn permissive() -> Self {
        Self {
            filtering: FilteringRule::Allow,
        }
    }

    /// A safe default for client only.
    ///
    /// This configuration effectively disable proxying abilities and kind of
    /// reduce the JMUX "proxy" to a JMUX client.
    pub fn client() -> Self {
        Self {
            filtering: FilteringRule::Deny,
        }
    }
}

/// Filtering rule for JMUX requests.
///
/// ```
/// use jmux_proxy::FilteringRule;
///
/// # fn main() -> anyhow::Result<()> {
/// let always_allow = FilteringRule::Allow;
///
/// always_allow.validate_destination_str("tcp://devolutions.net:80")?;
/// always_allow.validate_destination_str("ws://127.0.0.1:8080")?;
///
/// // Let's build this rule:
/// //   (
/// //     port 80
/// //     AND ( host doc.rust-lang.org OR second-level domain segment named "devolutions" )
/// //   )
/// //   OR ( port 22 AND any domain segment named "vps" )
/// //   OR ( NOT { port 1080 } AND host sekai.net )
/// //   OR ( host:port 127.0.0.1:8080 AND scheme "wss" )
/// let elaborated_rule = FilteringRule::port(80)
///     .and(
///         FilteringRule::host("doc.rust-lang.org")
///             .or(FilteringRule::wildcard_host("devolutions.*"))
///             .or(FilteringRule::wildcard_host("*.devolutions.net"))
///     )
///     .or(FilteringRule::port(22).and(FilteringRule::wildcard_host("vps.*.*")))
///     .or(FilteringRule::port(1080).invert().and(FilteringRule::host("sekai.net")))
///     .or(FilteringRule::host_and_port("127.0.0.1", 8080).and(FilteringRule::scheme("wss")));
///
/// assert!(elaborated_rule.validate_destination_str("tcp://doc.rust-lang.org:80").is_ok());
/// assert!(elaborated_rule.validate_destination_str("ws://devolutions.net:80").is_ok());
/// assert!(elaborated_rule.validate_destination_str("wss://dvls.devolutions.net:80").is_ok());
/// assert!(elaborated_rule.validate_destination_str("tcp://dvls.devolutions.ninja:80").is_err());
/// assert!(elaborated_rule.validate_destination_str("tcp://devolutions.bad.ninja:80").is_err());
/// assert!(elaborated_rule.validate_destination_str("tcp://duckduckgo.com:80").is_err());
///
/// assert!(elaborated_rule.validate_destination_str("tcp://vps.my-web-site.com:22").is_ok());
/// assert!(elaborated_rule.validate_destination_str("tcp://vps.rust-lang.org:22").is_ok());
/// assert!(elaborated_rule.validate_destination_str("tcp://super.vps.ninja:22").is_err());
/// assert!(elaborated_rule.validate_destination_str("tcp://vps.super.devolutions.ninja:22").is_err());
/// assert!(elaborated_rule.validate_destination_str("tcp://vps.my-web-site.com:2222").is_err());
/// assert!(elaborated_rule.validate_destination_str("tcp://myvps.ovh.com:22").is_err());
/// assert!(elaborated_rule.validate_destination_str("tcp://doc.rust-lang.org:22").is_err());
/// assert!(elaborated_rule.validate_destination_str("wss://127.0.0.1:22").is_err());
///
/// assert!(elaborated_rule.validate_destination_str("tcp://sekai.net:80").is_ok());
/// assert!(elaborated_rule.validate_destination_str("tcp://sekai.net:8080").is_ok());
/// assert!(elaborated_rule.validate_destination_str("tcp://sekai.net:22").is_ok());
/// assert!(elaborated_rule.validate_destination_str("tcp://sekai.net:1080").is_err());
///
/// assert!(elaborated_rule.validate_destination_str("wss://127.0.0.1:8080").is_ok());
/// assert!(elaborated_rule.validate_destination_str("wss://doc.rust-lang.org:8080").is_err());
/// assert!(elaborated_rule.validate_destination_str("wss://127.0.0.1:80").is_err());
/// assert!(elaborated_rule.validate_destination_str("tcp://127.0.0.1:8080").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub enum FilteringRule {
    /// Always denied.
    Deny,
    /// Always allowed.
    Allow,
    /// Invert the rule
    Not(Box<FilteringRule>),
    /// Must fulfill every rule.
    All(Vec<FilteringRule>),
    /// Must fulfill at least one rule.
    Any(Vec<FilteringRule>),
    /// Host must match exactly.
    Host(String),
    /// Port must match exactly.
    Port(u16),
    /// Scheme must match exactly.
    Scheme(String),
    /// Host and port must match exactly.
    HostAndPort { host: String, port: u16 },
    /// Rule matching multiple sub-domains, as in wildcard certificates.
    /// e.g.: `*.example.com`, `*.*.devolutions.net`
    WildcardHost(String),
}

impl Default for FilteringRule {
    fn default() -> Self {
        FilteringRule::Deny
    }
}

impl FilteringRule {
    pub fn deny() -> Self {
        Self::Deny
    }

    pub fn allow() -> Self {
        Self::Allow
    }

    /// Puts current rule behind a NOT operator
    pub fn invert(self) -> Self {
        Self::Not(Box::new(self))
    }

    pub fn host(host: impl Into<String>) -> Self {
        Self::Host(host.into())
    }

    pub fn port(port: u16) -> Self {
        Self::Port(port)
    }

    pub fn scheme(scheme: impl Into<String>) -> Self {
        Self::Scheme(scheme.into())
    }

    pub fn host_and_port(host: impl Into<String>, port: u16) -> Self {
        Self::HostAndPort {
            host: host.into(),
            port,
        }
    }

    pub fn wildcard_host(host: impl Into<String>) -> Self {
        Self::WildcardHost(host.into())
    }

    /// Combine current rule using an "AND" operator
    pub fn and(self, rule: Self) -> Self {
        match self {
            Self::Allow => rule,
            Self::All(mut sub_rules) => {
                sub_rules.push(rule);
                Self::All(sub_rules)
            }
            current_rule => {
                let mut sub_rules = Vec::with_capacity(16);
                sub_rules.push(current_rule);
                sub_rules.push(rule);
                Self::All(sub_rules)
            }
        }
    }

    /// Combine current rule using an "OR" operator
    pub fn or(self, rule: Self) -> Self {
        match self {
            Self::Deny => rule,
            Self::Any(mut sub_rules) => {
                sub_rules.push(rule);
                Self::Any(sub_rules)
            }
            current_rule => {
                let mut sub_rules = Vec::with_capacity(16);
                sub_rules.push(current_rule);
                sub_rules.push(rule);
                Self::Any(sub_rules)
            }
        }
    }

    pub fn validate_destination(&self, destination_url: &DestinationUrl) -> anyhow::Result<()> {
        if is_valid(
            self,
            destination_url.scheme(),
            destination_url.host(),
            destination_url.port(),
        ) {
            Ok(())
        } else {
            anyhow::bail!("target doesn't obey the filtering rule");
        }
    }

    pub fn validate_destination_str(&self, destination_url: impl AsRef<str>) -> anyhow::Result<()> {
        validate_destination_str_impl(self, destination_url.as_ref())
    }
}

fn validate_destination_str_impl(rule: &FilteringRule, destination_url: &str) -> anyhow::Result<()> {
    let (scheme, target) = destination_url
        .split_once("://")
        .context("invalid destination URL format")?;
    let (host, port) = target.rsplit_once(':').context("invalid target format")?;
    let port = port.parse().context("invalid port value")?;

    if is_valid(rule, scheme, host, port) {
        Ok(())
    } else {
        anyhow::bail!("target doesn't obey the filtering rule");
    }
}

fn is_valid(rule: &FilteringRule, target_scheme: &str, target_host: &str, target_port: u16) -> bool {
    match rule {
        FilteringRule::Deny => false,
        FilteringRule::Allow => true,
        FilteringRule::Not(rule) => !is_valid(rule, target_scheme, target_host, target_port),
        FilteringRule::All(rules) => rules
            .iter()
            .all(|r| is_valid(r, target_scheme, target_host, target_port)),
        FilteringRule::Any(rules) => rules
            .iter()
            .any(|r| is_valid(r, target_scheme, target_host, target_port)),
        FilteringRule::Host(host) => target_host == host,
        FilteringRule::Port(port) => target_port == *port,
        FilteringRule::Scheme(scheme) => target_scheme == scheme,
        FilteringRule::HostAndPort { host, port } => target_host == host && target_port == *port,
        FilteringRule::WildcardHost(host) => {
            let mut expected_it = host.rsplit('.');
            let mut actual_it = target_host.rsplit('.');
            loop {
                match (expected_it.next(), actual_it.next()) {
                    (Some(expected), Some(actual)) if expected == actual => {}
                    (Some("*"), Some(_)) => {}
                    (None, None) => return true,
                    _ => return false,
                }
            }
        }
    }
}
