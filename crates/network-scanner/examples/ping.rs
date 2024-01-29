use network_scanner::ping::ping;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let ip = std::net::Ipv4Addr::new(8, 8, 8, 8); //famous google dns
    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    ping(runtime, ip).await.expect("Failed to ping");
    Ok(())
}
