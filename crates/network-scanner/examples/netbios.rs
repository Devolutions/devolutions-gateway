use std::{net::Ipv4Addr, time::Duration};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_thread_names(true)
        .init();

    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

    let lower: Ipv4Addr = "10.10.0.0".parse()?;
    let upper: Ipv4Addr = "10.10.0.125".parse()?;
    let ip_range =
        network_scanner::ip_utils::IpAddrRange::new(std::net::IpAddr::V4(lower), std::net::IpAddr::V4(upper))?;
    let single_query_duration = Duration::from_secs(1);
    let interval = Duration::from_millis(20);
    let mut receiver =
        network_scanner::netbios::netbios_query_scan(runtime, ip_range, single_query_duration, interval)?;

    while let Some((ip, name)) = receiver.recv().await {
        println!("{}: {}", ip, name);
    }

    Ok(())
}
