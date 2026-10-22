use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::Context as _;
use ipnet::IpNet;
use parking_lot::RwLock;
use tracing::warn;
use url::Url;

/// Manual proxy configuration with protocol-specific URLs and exclude list.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct ManualProxyConfig {
    /// HTTP proxy URL (e.g., `http://proxy.corp:8080`).
    pub http: Option<Url>,
    /// HTTPS proxy URL (e.g., `http://proxy.corp:8080`).
    pub https: Option<Url>,
    /// Fallback proxy URL for all protocols (e.g., `socks5://proxy.corp:1080`).
    pub all: Option<Url>,
    /// Bypass list (same semantics as NO_PROXY).
    ///
    /// Supports hostnames, domain suffixes (.corp.local), IPs, CIDR ranges, and "*" for all.
    pub exclude: Vec<String>,
}

impl ManualProxyConfig {
    /// Check if a target URL should bypass the proxy based on the exclude list.
    ///
    /// This function implements NO_PROXY semantics:
    /// - "*" matches everything (bypass proxy for all targets)
    /// - Exact hostname match: "localhost", "example.com"
    /// - Domain suffix match: ".corp.local" matches "foo.corp.local"
    /// - IP address match: "127.0.0.1"
    /// - CIDR range match: "10.0.0.0/8", "192.168.0.0/16"
    pub fn should_bypass(&self, target: &Url) -> bool {
        let host = match target.host_str() {
            Some(h) => h,
            None => return false,
        };

        for pattern in &self.exclude {
            // Wildcard matches everything.
            if pattern == "*" {
                return true;
            }

            // Domain suffix match (starts with dot).
            if let Some(suffix) = pattern.strip_prefix('.') {
                if host == suffix || host.ends_with(pattern) {
                    return true;
                }
                continue;
            }

            // Exact hostname match.
            if host == pattern {
                return true;
            }

            // Try IP address or CIDR range matching.
            if let Some(target_ip) = target.host().and_then(|h| match h {
                url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
                url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
                url::Host::Domain(_) => None,
            }) {
                // Check if pattern is an IP address.
                if let Ok(pattern_ip) = IpAddr::from_str(pattern) {
                    if target_ip == pattern_ip {
                        return true;
                    }
                    continue;
                }

                // Check if pattern is a CIDR range.
                if let Ok(cidr) = IpNet::from_str(pattern)
                    && cidr.contains(&target_ip)
                {
                    return true;
                }
            }
        }

        false
    }

    /// Select the appropriate proxy URL for a target URL.
    ///
    /// Selection order:
    /// - For http:// -> use http proxy, fallback to all
    /// - For https:// -> use https proxy, fallback to all
    /// - For other schemes -> use all
    pub fn select_proxy(&self, target: &Url) -> Option<&Url> {
        match target.scheme() {
            "http" => self.http.as_ref().or(self.all.as_ref()),
            "https" => self.https.as_ref().or(self.all.as_ref()),
            _ => self.all.as_ref(),
        }
    }
}

/// Proxy configuration that can be specified in configuration files.
///
/// This enum determines how HTTP client proxy settings are resolved:
/// - `Off`: Never use a proxy, ignore environment variables
/// - `System`: Use environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) or WinHTTP
/// - `Manual`: Use explicitly configured proxy URLs with optional exclude list
#[expect(
    clippy::large_enum_variant,
    reason = "Manual is the most common variant in practice, boxing would add unnecessary indirection"
)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyConfig {
    /// Never use a proxy, ignore environment variables.
    Off,
    /// Use environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) or WinHTTP configuration.
    System,
    /// Use manually configured proxy URLs from the configuration file.
    Manual(ManualProxyConfig),
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self::System
    }
}

/// Windows automatic proxy configuration, which System mode doesn't evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AutomaticConfiguration {
    /// "Automatically detect settings", which discovers a configuration script through WPAD.
    pub automatic_detection: bool,
    /// "Use automatic configuration script", which names a PAC script.
    pub configuration_script: bool,
}

impl AutomaticConfiguration {
    /// Reads the WinINet `DefaultConnectionSettings` value, whose ninth byte holds the low byte of its
    /// `INTERNET_PER_CONN_FLAGS`.
    #[cfg(any(windows, test))]
    fn from_default_connection_settings(settings: &[u8]) -> Self {
        // `PROXY_TYPE_AUTO_PROXY_URL` and `PROXY_TYPE_AUTO_DETECT` of `wininet.h`.
        const AUTO_PROXY_URL: u8 = 0x04;
        const AUTO_DETECT: u8 = 0x08;

        let flags = settings
            .get(4 /* Version */ + 4 /* Counter */)
            .copied()
            .unwrap_or_default();
        Self {
            automatic_detection: flags & AUTO_DETECT != 0,
            configuration_script: flags & AUTO_PROXY_URL != 0,
        }
    }
}

/// Reads whether the WinINet settings that System mode reads enable automatic proxy configuration.
///
/// System mode reads the settings of the current user and of the machine, and takes no proxy from settings that enable
/// automatic configuration.
/// Settings that were never saved enable none, as do platforms other than Windows.
pub fn system_automatic_configuration() -> std::io::Result<AutomaticConfiguration> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

        const CONNECTIONS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

        // UNTESTED: the registry is machine state a unit test can't set without changing the machine.
        // When changing this, check a PAC script and automatic detection, each set for the service account and for the
        // machine, and a hive without the `Connections` key.
        let mut configuration = AutomaticConfiguration::default();
        for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
            let settings = match RegKey::predef(hive)
                .open_subkey(CONNECTIONS)
                .and_then(|connections| connections.get_raw_value("DefaultConnectionSettings"))
            {
                Ok(settings) => settings,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let enabled = AutomaticConfiguration::from_default_connection_settings(&settings.bytes);
            configuration.automatic_detection |= enabled.automatic_detection;
            configuration.configuration_script |= enabled.configuration_script;
        }
        Ok(configuration)
    }
    #[cfg(not(windows))]
    {
        Ok(AutomaticConfiguration::default())
    }
}

/// Generates a cache key for HTTP clients based on URL and proxy configuration.
///
/// Keys are based on scheme, host, port, and proxy configuration.
/// Path, query, and fragment are intentionally ignored as they don't affect
/// proxy selection or client configuration.
fn make_cache_key(url: &Url, config: &ProxyConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    url.scheme().hash(&mut hasher);
    url.host_str().unwrap_or("").hash(&mut hasher);
    url.port().hash(&mut hasher);
    config.hash(&mut hasher);
    hasher.finish()
}

/// FIFO cache for HTTP clients with a maximum capacity of 50 entries.
///
/// This cache stores reqwest::Client instances to avoid repeated client creation
/// for the same (scheme, host, port, proxy_config) combinations.
///
/// When the cache reaches capacity, the oldest entry is evicted (FIFO).
///
/// Note: reqwest::Client already uses Arc internally, so we don't need to wrap it.
struct ClientCache {
    /// Map from cache key to client
    map: HashMap<u64, reqwest::Client>,
    /// Queue tracking insertion order for FIFO eviction
    queue: VecDeque<u64>,
    /// Maximum number of clients to cache
    capacity: usize,
}

impl ClientCache {
    const DEFAULT_CAPACITY: usize = 50;

    fn new() -> Self {
        Self {
            map: HashMap::new(),
            queue: VecDeque::new(),
            capacity: Self::DEFAULT_CAPACITY,
        }
    }

    /// Get a client from the cache, or None if not present.
    fn get(&self, key: u64) -> Option<reqwest::Client> {
        self.map.get(&key).cloned()
    }

    /// Insert a client into the cache, evicting the oldest entry if at capacity.
    fn insert(&mut self, key: u64, client: reqwest::Client) {
        // If already in cache, update it without adding duplicate to queue.
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.map.entry(key) {
            e.insert(client);
            return;
        }

        // If at capacity, evict oldest entry.
        if self.map.len() >= self.capacity
            && let Some(oldest_key) = self.queue.pop_front()
        {
            self.map.remove(&oldest_key);
        }

        // Insert new entry.
        self.map.insert(key, client);
        self.queue.push_back(key);
    }
}

/// Detects proxy configuration for a specific target URL using system settings.
///
/// This function uses `proxy_cfg::get_proxy_config()` and then calls
/// `get_proxy_for_url()` method to detect proxy configuration from system
/// settings (WinHTTP on Windows, environment variables on Unix).
///
/// Returns `Ok(None)` if no proxy is configured or if proxy detection fails.
fn detect_system_proxy_for_url(url: &Url) -> anyhow::Result<Option<Url>> {
    // Try to detect proxy using system configuration.
    let proxy_config = match proxy_cfg::get_proxy_config()
        .map_err(|e| anyhow::anyhow!("failed to detect proxy configuration: {e}"))?
    {
        Some(cfg) => cfg,
        None => return Ok(None),
    };

    // Get the proxy URL for the specific target URL.
    // This handles NO_PROXY exclusions automatically.
    let proxy_url = match proxy_config.get_proxy_for_url(url) {
        Some(url) => url,
        None => return Ok(None),
    };

    let proxy_url = Url::parse(&proxy_url).context("invalid proxy URL from system settings")?;

    Ok(Some(proxy_url))
}

/// Returns the proxy that `config` selects for `url`, or `None` to connect directly.
///
/// Every client applies this one rule, so that the same target goes through the same proxy whichever client
/// connects to it.
pub fn proxy_for_url(url: &Url, config: &ProxyConfig) -> Option<Url> {
    match config {
        ProxyConfig::Off => None,
        // UNTESTED: System mode uses the machine's proxy settings (environment variables or WinHTTP).
        // A unit test can't set them without changing the machine or racing other tests over the environment.
        // When changing this arm, check a target behind a system proxy and one in its bypass list.
        ProxyConfig::System => detect_system_proxy_for_url(url).ok().flatten(),
        ProxyConfig::Manual(manual) => {
            if manual.should_bypass(url) {
                None
            } else {
                manual.select_proxy(url).cloned()
            }
        }
    }
}

/// Builds a reqwest client with proxy configuration for a specific target URL.
///
/// This function uses the provided configuration to determine the appropriate
/// proxy for the target URL based on the configured mode.
///
/// # Arguments
///
/// * `builder` - A reqwest::ClientBuilder to start with (may have timeout, TLS config, etc.)
/// * `url` - The URL that the client will connect to (used for proxy selection)
/// * `config` - Proxy configuration (mode, manual URLs, exclude list)
///
/// # Returns
///
/// A configured reqwest::Client ready to use, or an error if client creation fails.
pub fn build_client_with_proxy(
    mut builder: reqwest::ClientBuilder,
    url: &Url,
    config: &ProxyConfig,
) -> reqwest::Result<reqwest::Client> {
    if let Some(proxy_url) = proxy_for_url(url, config) {
        // Create reqwest::Proxy from the proxy URL.
        let proxy = reqwest::Proxy::all(proxy_url.clone()).inspect_err(|error| {
            warn!(%proxy_url, %error, "Failed to configure proxy");
        })?;

        builder = builder.proxy(proxy);
    }

    builder.build()
}

/// Gets or creates a cached HTTP client with proxy configuration.
///
/// This function maintains a global cache of up to 50 HTTP clients to avoid
/// repeated client creation overhead. Clients are cached based on the target
/// URL's scheme, host, port, and proxy configuration.
///
/// The cache uses FIFO eviction: when the cache reaches 50 entries, the oldest
/// entry is removed to make room for new ones.
///
/// # Arguments
///
/// * `builder` - A reqwest::ClientBuilder with additional configuration (timeout, TLS, etc.)
/// * `url` - The target URL (only scheme, host, and port are used for caching)
/// * `config` - Proxy configuration
///
/// # Returns
///
/// A reqwest::Client that can be safely shared and cloned (uses Arc internally).
pub fn get_or_create_cached_client(
    builder: reqwest::ClientBuilder,
    url: &Url,
    config: &ProxyConfig,
) -> reqwest::Result<reqwest::Client> {
    /// Global cache for HTTP clients.
    static CLIENT_CACHE: std::sync::LazyLock<RwLock<ClientCache>> =
        std::sync::LazyLock::new(|| RwLock::new(ClientCache::new()));

    let cache_key = make_cache_key(url, config);

    // Fast path: check if client is already cached (read lock).
    {
        let cache = CLIENT_CACHE.read();
        if let Some(client) = cache.get(cache_key) {
            return Ok(client);
        }
    }

    // Slow path: create new client and cache it (write lock).
    let mut cache = CLIENT_CACHE.write();

    // Check again in case another thread created the client while we were waiting.
    if let Some(client) = cache.get(cache_key) {
        return Ok(client);
    }

    // Build new client with proxy configuration.
    let client = build_client_with_proxy(builder, url, config)?;

    // Insert into cache.
    cache.insert(cache_key, client.clone());

    Ok(client)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn manual(exclude: &[&str]) -> ProxyConfig {
        let url = |url| Url::parse(url).expect("valid proxy URL");
        ProxyConfig::Manual(ManualProxyConfig {
            http: Some(url("http://http-proxy.test:3128")),
            https: Some(url("http://https-proxy.test:3128")),
            all: Some(url("http://all-proxy.test:3128")),
            exclude: exclude.iter().map(|pattern| (*pattern).to_owned()).collect(),
        })
    }

    #[rstest]
    #[case::off(ProxyConfig::Off, "https://authority.test/dvls", None)]
    #[case::manual_https(manual(&[]), "https://authority.test/dvls", Some("http://https-proxy.test:3128/"))]
    #[case::manual_http(manual(&[]), "http://authority.test/dvls", Some("http://http-proxy.test:3128/"))]
    #[case::manual_bypassed(manual(&[".test"]), "https://authority.test/dvls", None)]
    fn selects_the_proxy_the_mode_and_exclude_list_name(
        #[case] config: ProxyConfig,
        #[case] target: &str,
        #[case] expected: Option<&str>,
    ) -> anyhow::Result<()> {
        // oracle: mutant `proxy_for_url` selects no proxy, or ignores the exclude list
        let selected = proxy_for_url(&Url::parse(target)?, &config);
        assert_eq!(selected.as_ref().map(Url::as_str), expected);
        Ok(())
    }

    #[test]
    fn domain_exclusion_respects_label_boundaries() -> anyhow::Result<()> {
        // oracle: mutant an exclude entry `.corp.local` matches any host ending in `corp.local`, such as `evilcorp.local`
        let config = ManualProxyConfig {
            exclude: vec![".corp.local".to_owned()],
            ..Default::default()
        };
        for (target, bypass) in [
            ("https://corp.local", true),
            ("https://a.corp.local", true),
            ("https://evilcorp.local", false),
        ] {
            assert_eq!(config.should_bypass(&Url::parse(target)?), bypass, "{target}");
        }
        Ok(())
    }

    // oracle: spec Windows SDK wininet.h §INTERNET_PER_CONN_FLAGS
    // oracle: reference proxy_cfg 0.4.2 `win_inet_get_autoconfig_type`, which reads these flags from the ninth byte
    #[rstest]
    #[case::direct(0x01, false, false)]
    #[case::named_proxy(0x03, false, false)]
    #[case::configuration_script(0x05, false, true)]
    #[case::automatic_detection(0x09, true, false)]
    fn reads_the_automatic_configuration_flags_of_the_connection_settings(
        #[case] flags: u8,
        #[case] automatic_detection: bool,
        #[case] configuration_script: bool,
    ) {
        // Version, counter, then the `PROXY_TYPE_*` flags, each a little-endian 32-bit value.
        let settings = [0x46, 0, 0, 0, 0x02, 0, 0, 0, flags, 0, 0, 0];
        let expected = AutomaticConfiguration {
            automatic_detection,
            configuration_script,
        };
        assert_eq!(
            AutomaticConfiguration::from_default_connection_settings(&settings),
            expected
        );
    }
}
