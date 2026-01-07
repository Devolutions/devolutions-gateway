#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

use http_client_proxy::{ManualProxyConfig, ProxyConfig, build_client_with_proxy};
use rstest::rstest;
use url::Url;

#[rstest]
#[case("http://example.com", true)]
#[case("https://example.com", true)]
#[case("ftp://example.com", true)]
fn test_build_client_with_manual_http_proxy(#[case] target_url_str: &str, #[case] should_succeed: bool) {
    let builder = reqwest::Client::builder();
    let target_url = Url::parse(target_url_str).unwrap();
    let config = ProxyConfig::Manual(ManualProxyConfig {
        http: Some(Url::parse("http://manual-proxy:8080").unwrap()),
        ..Default::default()
    });

    let result = build_client_with_proxy(builder, &target_url, &config);
    assert_eq!(result.is_ok(), should_succeed);
}

#[rstest]
#[case("http://example.com", true)]
#[case("https://example.com", true)]
fn test_build_client_with_manual_socks5_proxy(#[case] target_url_str: &str, #[case] should_succeed: bool) {
    let builder = reqwest::Client::builder();
    let target_url = Url::parse(target_url_str).unwrap();
    let config = ProxyConfig::Manual(ManualProxyConfig {
        all: Some(Url::parse("socks5://socks-proxy:1080").unwrap()),
        ..Default::default()
    });

    let result = build_client_with_proxy(builder, &target_url, &config);
    assert_eq!(result.is_ok(), should_succeed);
}

#[test]
fn test_build_client_with_system_mode() {
    let builder = reqwest::Client::builder();
    let target_url = Url::parse("http://example.com").unwrap();
    let config = ProxyConfig::System;

    // System mode should succeed (may or may not use a proxy depending on environment).
    let result = build_client_with_proxy(builder, &target_url, &config);
    assert!(result.is_ok());
}

#[test]
fn test_build_client_with_off_mode() {
    let builder = reqwest::Client::builder();
    let target_url = Url::parse("http://example.com").unwrap();
    let config = ProxyConfig::Off;

    let result = build_client_with_proxy(builder, &target_url, &config);
    assert!(result.is_ok());
}

#[test]
fn test_build_client_with_exclude_list() {
    let builder = reqwest::Client::builder();
    let target_url = Url::parse("http://localhost").unwrap();
    let config = ProxyConfig::Manual(ManualProxyConfig {
        http: Some(Url::parse("http://proxy:8080").unwrap()),
        exclude: vec!["localhost".to_owned()],
        ..Default::default()
    });

    // Should succeed without using proxy (localhost is in exclude list).
    let result = build_client_with_proxy(builder, &target_url, &config);
    assert!(result.is_ok());
}

#[test]
#[expect(clippy::similar_names, reason = "test semantically requires http and https targets")]
fn test_build_client_with_protocol_specific_proxies() {
    let http_target = Url::parse("http://example.com").unwrap();
    let https_target = Url::parse("https://example.com").unwrap();

    let config = ProxyConfig::Manual(ManualProxyConfig {
        http: Some(Url::parse("http://http-proxy:8080").unwrap()),
        https: Some(Url::parse("http://https-proxy:8443").unwrap()),
        ..Default::default()
    });

    // Both should succeed with their respective proxies.
    let http_result = build_client_with_proxy(reqwest::Client::builder(), &http_target, &config);
    assert!(http_result.is_ok());

    let https_result = build_client_with_proxy(reqwest::Client::builder(), &https_target, &config);
    assert!(https_result.is_ok());
}
