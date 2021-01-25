#[derive(Clone, Copy, Debug)]
pub enum ProxyType {
    Socks4,
    Socks5,
    Socks, // unknown SOCKS version
    Https,
    Http,
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub ty: ProxyType,
    pub addr: String,
}

#[cfg(feature = "detect-proxy")]
pub fn detect_proxy() -> Option<ProxyConfig> {
    let mut cfg = proxy_cfg::get_proxy_config().ok()??;

    if let Some(addr) = cfg.proxies.remove("socks5").or_else(|| cfg.proxies.remove("socks5h")) {
        return Some(ProxyConfig {
            ty: ProxyType::Socks5,
            addr,
        });
    }

    if let Some(addr) = cfg.proxies.remove("socks4").or_else(|| cfg.proxies.remove("socks4a")) {
        return Some(ProxyConfig {
            ty: ProxyType::Socks4,
            addr,
        });
    }

    if let Some(addr) = cfg.proxies.remove("socks") {
        return Some(ProxyConfig {
            ty: ProxyType::Socks,
            addr,
        });
    }

    if let Some(addr) = cfg.proxies.remove("https") {
        return Some(ProxyConfig {
            ty: ProxyType::Https,
            addr,
        });
    }

    if let Some(addr) = cfg.proxies.remove("http") {
        return Some(ProxyConfig {
            ty: ProxyType::Http,
            addr,
        });
    }

    None
}

#[cfg(not(feature = "detect-proxy"))]
pub fn detect_proxy() -> Option<ProxyConfig> {
    None
}
