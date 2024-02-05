use std::time::Duration;

use anyhow::Context;
use network_scanner::ping::ping;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let ip = std::net::Ipv4Addr::new(8, 8, 8, 82); //famous google dns
    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    ping(runtime, ip, Duration::from_secs(1)).await.context("ping failed")?; // this will fail
    Ok(())
}
