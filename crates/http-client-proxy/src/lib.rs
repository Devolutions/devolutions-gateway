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
                if host.ends_with(suffix) || host == suffix {
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
    let proxy_url = match config {
        ProxyConfig::Off => {
            // No proxy mode - never use a proxy.
            None
        }
        ProxyConfig::System => {
            // System mode - use environment variables or WinHTTP.
            detect_system_proxy_for_url(url).ok().flatten()
        }
        ProxyConfig::Manual(manual) => {
            // Manual mode - check exclude list, then use configured URLs.
            if manual.should_bypass(url) {
                None
            } else {
                manual.select_proxy(url).cloned()
            }
        }
    };

    if let Some(proxy_url) = proxy_url {
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
