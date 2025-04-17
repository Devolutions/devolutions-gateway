#![allow(unused_crate_dependencies)]

use std::net::Ipv4Addr;
use std::time::Duration;

use network_scanner::task_utils::TaskManager;
use tracing::info;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_thread_names(true)
        .init();

    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

    let lower: Ipv4Addr = "10.10.0.0".parse()?;
    let upper: Ipv4Addr = "10.10.0.125".parse()?;

    let ip_range = network_scanner::ip_utils::IpV4AddrRange::new(lower, upper);

    let single_query_duration = Duration::from_secs(1);
    let interval = Duration::from_millis(20);
    let mut receiver = network_scanner::netbios::netbios_query_scan(
        runtime,
        ip_range,
        single_query_duration,
        interval,
        TaskManager::new(),
    )?;

    while let Some(event) = receiver.recv().await {
        info!(?event)
    }

    Ok(())
}
