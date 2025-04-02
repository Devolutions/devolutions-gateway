#![allow(unused_crate_dependencies)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::Ok;
use network_scanner::ping::ping_range;
use network_scanner::task_utils::TaskManager;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .init();

    let lower = IpAddr::V4(Ipv4Addr::new(10, 10, 0, 0));
    let upper = IpAddr::V4(Ipv4Addr::new(10, 10, 0, 125));

    let range = network_scanner::ip_utils::IpAddrRange::new(lower, upper)?;

    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

    let ping_interval = Duration::from_millis(20);

    let ping_wait_time = Duration::from_secs(1);

    let should_ping = |ip: IpAddr| {
        // if ip is even, ping it
        ip.is_ipv4() && {
            if let IpAddr::V4(v4) = ip {
                v4.octets()[3] % 2 == 0
            } else {
                false
            }
        }
    };
    let now = std::time::Instant::now();
    let mut receiver = ping_range(
        runtime,
        range,
        ping_interval,
        ping_wait_time,
        should_ping,
        TaskManager::new(),
    )?;

    while let Some(ping_event) = receiver.recv().await {
        tracing::info!(?ping_event);
    }

    tracing::info!("Elapsed time: {:?}", now.elapsed());

    Ok(())
}
