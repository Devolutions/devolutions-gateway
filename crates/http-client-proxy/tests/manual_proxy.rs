#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

use http_client_proxy::ManualProxyConfig;
use url::Url;

#[test]
fn test_should_bypass_wildcard() {
    let config = ManualProxyConfig {
        exclude: vec!["*".to_owned()],
        ..Default::default()
    };

    let url = Url::parse("http://example.com").unwrap();
    assert!(config.should_bypass(&url));
}

#[test]
fn test_should_bypass_exact_hostname() {
    let config = ManualProxyConfig {
        exclude: vec!["localhost".to_owned(), "example.com".to_owned()],
        ..Default::default()
    };

    assert!(config.should_bypass(&Url::parse("http://localhost").unwrap()));
    assert!(config.should_bypass(&Url::parse("https://example.com").unwrap()));
    assert!(!config.should_bypass(&Url::parse("http://other.com").unwrap()));
}

#[test]
fn test_should_bypass_domain_suffix() {
    let config = ManualProxyConfig {
        exclude: vec![".corp.local".to_owned()],
        ..Default::default()
    };

    assert!(config.should_bypass(&Url::parse("http://foo.corp.local").unwrap()));
    assert!(config.should_bypass(&Url::parse("https://bar.corp.local").unwrap()));
    assert!(config.should_bypass(&Url::parse("http://corp.local").unwrap()));
    assert!(!config.should_bypass(&Url::parse("http://example.com").unwrap()));
}

#[test]
fn test_should_bypass_ip_address() {
    let config = ManualProxyConfig {
        exclude: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
        ..Default::default()
    };

    assert!(config.should_bypass(&Url::parse("http://127.0.0.1").unwrap()));
    assert!(config.should_bypass(&Url::parse("http://[::1]").unwrap()));
    assert!(!config.should_bypass(&Url::parse("http://192.168.1.1").unwrap()));
}

#[test]
fn test_should_bypass_cidr() {
    let config = ManualProxyConfig {
        exclude: vec!["10.0.0.0/8".to_owned(), "192.168.0.0/16".to_owned()],
        ..Default::default()
    };

    assert!(config.should_bypass(&Url::parse("http://10.0.0.1").unwrap()));
    assert!(config.should_bypass(&Url::parse("http://10.255.255.255").unwrap()));
    assert!(config.should_bypass(&Url::parse("http://192.168.1.100").unwrap()));
    assert!(!config.should_bypass(&Url::parse("http://172.16.0.1").unwrap()));
}

#[test]
#[expect(
    clippy::similar_names,
    reason = "test semantically requires http and https proxy URLs"
)]
fn test_select_proxy_http() {
    let http_proxy_url = Url::parse("http://http-proxy:8080").unwrap();
    let https_proxy_url = Url::parse("http://https-proxy:8443").unwrap();

    let config = ManualProxyConfig {
        http: Some(http_proxy_url.clone()),
        https: Some(https_proxy_url),
        ..Default::default()
    };

    let target = Url::parse("http://example.com").unwrap();
    assert_eq!(config.select_proxy(&target), Some(&http_proxy_url));
}

#[test]
#[expect(
    clippy::similar_names,
    reason = "test semantically requires http and https proxy URLs"
)]
fn test_select_proxy_https() {
    let http_proxy_url = Url::parse("http://http-proxy:8080").unwrap();
    let https_proxy_url = Url::parse("http://https-proxy:8443").unwrap();

    let config = ManualProxyConfig {
        http: Some(http_proxy_url),
        https: Some(https_proxy_url.clone()),
        ..Default::default()
    };

    let target = Url::parse("https://example.com").unwrap();
    assert_eq!(config.select_proxy(&target), Some(&https_proxy_url));
}

#[test]
fn test_select_proxy_fallback_to_all() {
    let all_proxy = Url::parse("socks5://socks-proxy:1080").unwrap();

    let config = ManualProxyConfig {
        all: Some(all_proxy.clone()),
        ..Default::default()
    };

    // HTTP falls back to all when http is not configured.
    assert_eq!(
        config.select_proxy(&Url::parse("http://example.com").unwrap()),
        Some(&all_proxy)
    );

    // HTTPS falls back to all when https is not configured.
    assert_eq!(
        config.select_proxy(&Url::parse("https://example.com").unwrap()),
        Some(&all_proxy)
    );

    // Other schemes use all.
    assert_eq!(
        config.select_proxy(&Url::parse("ftp://example.com").unwrap()),
        Some(&all_proxy)
    );
}

#[test]
fn test_select_proxy_none() {
    let config = ManualProxyConfig::default();

    assert_eq!(config.select_proxy(&Url::parse("http://example.com").unwrap()), None);
}
