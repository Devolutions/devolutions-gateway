//! Tests for listeners whose internal URL uses the `*` host.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context as _;
use rstest::rstest;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::DgwConfig;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The README states that `*` in an internal URL creates a listener on `0.0.0.0` for any IPv4 address
/// and one on `[::]` for any IPv6 address.
///
/// Both listeners share a port, which Linux rejects unless the IPv6 listener is IPv6-only.
#[rstest]
#[case::ipv4(IpAddr::V4(Ipv4Addr::LOCALHOST))]
#[case::ipv6(IpAddr::V6(Ipv6Addr::LOCALHOST))]
#[cfg_attr(
    windows,
    ignore = "a wildcard listener makes Windows Firewall ask for elevation once per executable path"
)]
#[tokio::test]
async fn wildcard_host_listens_on_ipv4_and_ipv6(#[case] loopback: IpAddr) -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .listener_host("*")
        .build()
        .init()
        .context("init config")?;

    let mut process = start_dgw(&config_handle).await?;

    let result = async {
        tokio::net::TcpStream::connect((loopback, config_handle.tcp_port()))
            .await
            .context("connect to the TCP listener")?;

        let mut stream = tokio::net::TcpStream::connect((loopback, config_handle.http_port()))
            .await
            .context("connect to the HTTP listener")?;
        stream
            .write_all(b"GET /jet/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .context("send request")?;

        let mut response = String::new();
        stream.read_to_string(&mut response).await.context("read response")?;

        anyhow::Ok(response)
    }
    .await;

    let _ = process.start_kill();
    let _ = process.wait().await;

    let response = result?;
    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );

    Ok(())
}
