use anyhow::Context;

/// JMUX proxy configuration struct.
///
/// All paramaters are designed to be opt-in rather than opt-out: default values are conservatives
/// and always safe (whitelist approach).
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
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
            ..Self::default()
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
/// always_allow.validate_target("devolutions.net:80")?;
/// always_allow.validate_target("127.0.0.1:8080")?;
///
/// // Let's build this rule:
/// //   (
/// //     port 80
/// //     AND ( host doc.rust-lang.org OR second-level domain segment named "devolutions" )
/// //   )
/// //   OR ( port 22 AND any domain segment named "vps" )
/// //   OR ( NOT { port 1080 } AND host sekai.net )
/// //   OR host:port 127.0.0.1:8080
/// let elaborated_rule = FilteringRule::port(80)
///     .and(
///         FilteringRule::host("doc.rust-lang.org")
///             .or(FilteringRule::specific_domain_segment("devolutions", 2))
///     )
///     .or(FilteringRule::port(22).and(FilteringRule::any_domain_segment("vps")))
///     .or(FilteringRule::port(1080).invert().and(FilteringRule::host("sekai.net")))
///     .or(FilteringRule::host_and_port("127.0.0.1", 8080));
///
/// elaborated_rule.validate_target("doc.rust-lang.org:80")?;
/// elaborated_rule.validate_target("devolutions.net:80")?;
/// elaborated_rule.validate_target("dvls.devolutions.net:80")?;
/// assert!(elaborated_rule.validate_target("devolutions.bad.ninja:80").is_err());
/// assert!(elaborated_rule.validate_target("duckduckgo.com:80").is_err());
///
/// elaborated_rule.validate_target("vps.my-web-site.com:22")?;
/// elaborated_rule.validate_target("vps.rust-lang.org:22")?;
/// elaborated_rule.validate_target("super.vps.ninja:22")?;
/// assert!(elaborated_rule.validate_target("vps.my-web-site.com:2222").is_err());
/// assert!(elaborated_rule.validate_target("myvps.ovh.com:22").is_err());
/// assert!(elaborated_rule.validate_target("doc.rust-lang.org:22").is_err());
/// assert!(elaborated_rule.validate_target("127.0.0.1:22").is_err());
///
/// elaborated_rule.validate_target("sekai.net:80")?;
/// elaborated_rule.validate_target("sekai.net:8080")?;
/// elaborated_rule.validate_target("sekai.net:22")?;
/// assert!(elaborated_rule.validate_target("sekai.net:1080").is_err());
///
/// elaborated_rule.validate_target("127.0.0.1:8080")?;
/// assert!(elaborated_rule.validate_target("doc.rust-lang.org:8080").is_err());
/// assert!(elaborated_rule.validate_target("127.0.0.1:80").is_err());
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
    /// Must fullfill every rule.
    All(Vec<FilteringRule>),
    /// Must fullfill at least one rule.
    Any(Vec<FilteringRule>),
    /// Host must match exactly.
    Host(String),
    /// Port must match exactly.
    Port(u16),
    /// Host and port must match exactly.
    HostAndPort { host: String, port: u16 },
    /// Name must match exactly
    SpecificDomainSegment { name: String, level: usize },
    /// Name must match exactly.
    AnyDomainSegment { name: String },
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

    pub fn host_and_port(host: impl Into<String>, port: u16) -> Self {
        Self::HostAndPort {
            host: host.into(),
            port,
        }
    }

    pub fn specific_domain_segment(name: impl Into<String>, level: usize) -> Self {
        Self::SpecificDomainSegment {
            name: name.into(),
            level,
        }
    }

    pub fn any_domain_segment(name: impl Into<String>) -> Self {
        Self::AnyDomainSegment { name: name.into() }
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

    pub fn validate_target(&self, target: impl AsRef<str>) -> anyhow::Result<()> {
        validate_target_impl(self, target.as_ref())
    }
}

fn validate_target_impl(rule: &FilteringRule, target: &str) -> anyhow::Result<()> {
    let (host, port) = target.rsplit_once(':').context("invalid target format")?;
    let port = port.parse().context("invalid port value")?;

    if is_valid(rule, host, port) {
        Ok(())
    } else {
        anyhow::bail!("target doesn't obey the filtering rule");
    }
}

fn is_valid(rule: &FilteringRule, target_host: &str, target_port: u16) -> bool {
    match rule {
        FilteringRule::Deny => false,
        FilteringRule::Allow => true,
        FilteringRule::Not(rule) => !is_valid(rule, target_host, target_port),
        FilteringRule::All(rules) => rules.iter().all(|r| is_valid(r, target_host, target_port)),
        FilteringRule::Any(rules) => rules.iter().any(|r| is_valid(r, target_host, target_port)),
        FilteringRule::Host(host) => target_host == host,
        FilteringRule::Port(port) => target_port == *port,
        FilteringRule::HostAndPort { host, port } => target_host == host && target_port == *port,
        FilteringRule::SpecificDomainSegment { name, level } => {
            if *level == 0 {
                false
            } else {
                target_host
                    .rsplit('.')
                    .nth(level - 1)
                    .into_iter()
                    .all(|segment| segment == name)
            }
        }
        FilteringRule::AnyDomainSegment { name } => target_host.rsplit('.').any(|segment| segment == name),
    }
}
